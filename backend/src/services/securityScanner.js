/**
 * Security Scanner Service
 * Scans Move code for common security vulnerabilities and risks
 */

class SecurityScanner {
  constructor() {
    this.rules = [
      {
        id: 'unrestricted-public-entry',
        name: 'Unrestricted Public Entry Function',
        severity: 'high',
        description: 'Public entry functions without capability or authority checks',
        check: this.checkUnrestrictedPublicEntry.bind(this)
      },
      {
        id: 'unchecked-transfer',
        name: 'Unchecked Transfer Operation',
        severity: 'high', 
        description: 'Transfer operations without proper validation or access control',
        check: this.checkUncheckedTransfer.bind(this)
      },
      {
        id: 'capability-without-verification',
        name: 'Capability Usage Without Verification',
        severity: 'high',
        description: 'Administrative capabilities used without proper ownership verification',
        check: this.checkCapabilityVerification.bind(this)
      },
      {
        id: 'shared-object-mutation',
        name: 'Unsafe Shared Object Mutation',
        severity: 'medium',
        description: 'Mutable access to shared objects without proper synchronization',
        check: this.checkSharedObjectMutation.bind(this)
      },
      {
        id: 'missing-input-validation',
        name: 'Missing Input Validation',
        severity: 'medium',
        description: 'Function parameters not validated before use',
        check: this.checkInputValidation.bind(this)
      },
      {
        id: 'unsafe-arithmetic',
        name: 'Unsafe Arithmetic Operations',
        severity: 'medium',
        description: 'Arithmetic operations that could overflow or underflow',
        check: this.checkUnsafeArithmetic.bind(this)
      },
      {
        id: 'resource-leak',
        name: 'Potential Resource Leak',
        severity: 'low',
        description: 'Resources created but not properly managed',
        check: this.checkResourceLeak.bind(this)
      },
      {
        id: 'defi-exploit-patterns',
        name: 'DeFi Exploit Patterns',
        severity: 'critical',
        description: 'Detects patterns similar to known DeFi exploits like Cetus',
        check: this.checkDeFiExploitPatterns.bind(this)
      }
    ];
  }

  scanForVulnerabilities(parsedFiles) {
    const vulnerabilities = [];
    
    for (const file of parsedFiles) {
      if (!file.content || file.parseError) continue;
      
      const fileVulns = this.scanFile(file);
      vulnerabilities.push(...fileVulns);
    }
    
    return vulnerabilities;
  }
  
  scanFile(file) {
    const vulnerabilities = [];
    const functions = this.extractFunctionBlocks(file.content);
    
    for (const rule of this.rules) {
      const ruleVulns = rule.check(file, functions);
      vulnerabilities.push(...ruleVulns);
    }
    
    return vulnerabilities;
  }
  
  // 1. Check for unrestricted public entry functions
  checkUnrestrictedPublicEntry(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      if (func.signature.includes('public') && func.signature.includes('entry')) {
        // Check if function has capability checks
        const hasCapCheck = this.hasCapabilityCheck(func.content);
        const hasAccessControl = this.hasAccessControl(func.content);
        
        if (!hasCapCheck && !hasAccessControl) {
          vulnerabilities.push({
            id: 'unrestricted-public-entry',
            name: 'Unrestricted Public Entry Function',
            severity: 'high',
            description: 'Public entry function lacks proper access controls or capability verification',
            file: file.name,
            line: func.startLine,
            code: func.signature,
            match: func.name,
            recommendation: 'Add capability parameter and verify ownership using assert!(capability_owner == tx_sender)',
            confidence: 'high'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 2. Check for unchecked transfer operations
  checkUncheckedTransfer(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const transferMatches = func.content.match(/transfer::(public_)?transfer|coin::transfer|transfer_to_sender/g);
      if (transferMatches) {
        // Check if there's proper validation before transfer
        const hasValidation = this.hasTransferValidation(func.content);
        const hasCapabilityCheck = this.hasCapabilityCheck(func.content);
        
        if (!hasValidation && !hasCapabilityCheck) {
          const lineNumber = this.getLineOfMatch(func.content, transferMatches[0]) + func.startLine;
          vulnerabilities.push({
            id: 'unchecked-transfer',
            name: 'Unchecked Transfer Operation',
            severity: 'high',
            description: 'Transfer operation without proper sender verification or access control',
            file: file.name,
            line: lineNumber,
            code: this.getLineContent(file.content, lineNumber),
            match: transferMatches[0],
            recommendation: 'Add sender verification or capability checks before performing transfers',
            confidence: 'high'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 3. Check capability verification
  checkCapabilityVerification(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const capMatches = func.content.match(/(AdminCap|OwnerCap|MintCap|Authority|Cap)\s*[,)]/g);
      if (capMatches) {
        // Check if capability ownership is verified
        const hasOwnershipCheck = func.content.includes('assert!') && 
          (func.content.includes('owner') || func.content.includes('sender'));
        
        if (!hasOwnershipCheck) {
          const lineNumber = func.startLine;
          vulnerabilities.push({
            id: 'capability-without-verification',
            name: 'Capability Usage Without Verification',
            severity: 'high',
            description: 'Function uses capability parameter without verifying ownership',
            file: file.name,
            line: lineNumber,
            code: func.signature,
            match: capMatches[0],
            recommendation: 'Verify capability ownership with assert!(capability.owner == tx_context::sender(ctx))',
            confidence: 'high'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 4. Check shared object mutation
  checkSharedObjectMutation(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const sharedMutMatches = func.content.match(/&mut\s+[^,\s]*\s*:\s*&mut/g);
      if (sharedMutMatches && func.signature.includes('public')) {
        const lineNumber = this.getLineOfMatch(func.content, sharedMutMatches[0]) + func.startLine;
        vulnerabilities.push({
          id: 'shared-object-mutation',
          name: 'Unsafe Shared Object Mutation',
          severity: 'medium',
          description: 'Public function with mutable access to shared objects',
          file: file.name,
          line: lineNumber,
          code: this.getLineContent(file.content, lineNumber),
          match: sharedMutMatches[0],
          recommendation: 'Consider using immutable references or add proper access controls',
          confidence: 'medium'
        });
      }
    }
    
    return vulnerabilities;
  }

  // 5. Check input validation
  checkInputValidation(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      if (func.signature.includes('public') && func.parameters.length > 0) {
        const hasValidation = func.content.includes('assert!') || 
          func.content.includes('require') ||
          func.content.includes('abort');
        
        if (!hasValidation) {
          vulnerabilities.push({
            id: 'missing-input-validation',
            name: 'Missing Input Validation',
            severity: 'medium',
            description: 'Public function does not validate input parameters',
            file: file.name,
            line: func.startLine,
            code: func.signature,
            match: func.name,
            recommendation: 'Add input validation using assert! or appropriate checks',
            confidence: 'medium'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 6. Check arithmetic operations
  checkUnsafeArithmetic(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const arithmeticMatches = func.content.match(/[+\-*/]\s*=|=\s*[^=]*[+\-*/]/g);
      if (arithmeticMatches) {
        const hasOverflowCheck = func.content.includes('checked_') || 
          func.content.includes('safe_') ||
          func.content.includes('assert!');
        
        if (!hasOverflowCheck) {
          const lineNumber = this.getLineOfMatch(func.content, arithmeticMatches[0]) + func.startLine;
          vulnerabilities.push({
            id: 'unsafe-arithmetic',
            name: 'Unsafe Arithmetic Operations',
            severity: 'medium',
            description: 'Arithmetic operations without overflow/underflow protection',
            file: file.name,
            line: lineNumber,
            code: this.getLineContent(file.content, lineNumber),
            match: arithmeticMatches[0],
            recommendation: 'Use checked arithmetic operations or add overflow checks',
            confidence: 'medium'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 7. Check resource management
  checkResourceLeak(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const createMatches = func.content.match(/object::new|new_uid|create/g);
      const deleteMatches = func.content.match(/object::delete|delete_uid|destroy/g);
      
      if (createMatches && !deleteMatches && !func.content.includes('transfer')) {
        const lineNumber = this.getLineOfMatch(func.content, createMatches[0]) + func.startLine;
        vulnerabilities.push({
          id: 'resource-leak',
          name: 'Potential Resource Leak',
          severity: 'low',
          description: 'Resources created but not properly transferred or deleted',
          file: file.name,
          line: lineNumber,
          code: this.getLineContent(file.content, lineNumber),
          match: createMatches[0],
          recommendation: 'Ensure created resources are properly transferred or destroyed',
          confidence: 'medium'
        });
      }
    }
    
    return vulnerabilities;
  }

  // 8. DeFi Exploit Pattern Detection (Cetus-style)
  checkDeFiExploitPatterns(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const funcContent = func.content;
      
      // Check for swap functions without slippage protection (Cetus-style vulnerability)
      if (func.name.includes('swap') && func.signature.includes('public')) {
        const hasSlippageProtection = funcContent.includes('min_amount') || 
                                    funcContent.includes('slippage') ||
                                    funcContent.includes('minimum_out') ||
                                    funcContent.includes('deadline');
        
        if (!hasSlippageProtection) {
          vulnerabilities.push({
            id: 'swap-slippage-vulnerability',
            name: 'Swap Slippage Vulnerability',
            severity: 'critical',
            description: 'Swap function lacks slippage protection, vulnerable to sandwich attacks',
            file: file.name,
            line: func.startLine,
            code: func.signature,
            match: func.name,
            recommendation: 'Add slippage protection with min_amount_out and deadline parameters',
            confidence: 'high'
          });
        }
      }
      
      // Check for pool functions without reserve validation
      if ((func.name.includes('pool') || func.name.includes('liquidity')) && 
          func.signature.includes('public')) {
        const hasReserveCheck = funcContent.includes('reserve') || 
                              funcContent.includes('balance_check') ||
                              funcContent.includes('invariant');
        
        if (!hasReserveCheck) {
          vulnerabilities.push({
            id: 'pool-reserve-vulnerability',
            name: 'Pool Reserve Manipulation Risk',
            severity: 'high',
            description: 'Pool function lacks reserve consistency validation',
            file: file.name,
            line: func.startLine,
            code: func.signature,
            match: func.name,
            recommendation: 'Add reserve balance validation and invariant checks',
            confidence: 'medium'
          });
        }
      }
      
      // Check for price functions susceptible to manipulation
      if (func.name.includes('price') && func.signature.includes('public')) {
        const hasOracleProtection = funcContent.includes('twap') || 
                                  funcContent.includes('time_weighted') ||
                                  funcContent.includes('oracle') ||
                                  funcContent.includes('median');
        
        if (!hasOracleProtection) {
          vulnerabilities.push({
            id: 'price-manipulation-risk',
            name: 'Price Oracle Manipulation Risk',
            severity: 'high',
            description: 'Price function vulnerable to market manipulation attacks',
            file: file.name,
            line: func.startLine,
            code: func.signature,
            match: func.name,
            recommendation: 'Use time-weighted average prices (TWAP) or multiple oracle sources',
            confidence: 'medium'
          });
        }
      }
    }
    
    return vulnerabilities;
  }
  
  // Helper methods for vulnerability detection
  hasCapabilityCheck(functionContent) {
    return functionContent.includes('Cap') && 
           (functionContent.includes('assert!') || functionContent.includes('abort'));
  }

  hasAccessControl(functionContent) {
    return functionContent.includes('assert!') && 
           (functionContent.includes('sender') || functionContent.includes('owner'));
  }

  hasTransferValidation(functionContent) {
    return functionContent.includes('assert!') || 
           functionContent.includes('require') ||
           (functionContent.includes('if') && functionContent.includes('abort'));
  }

  getLineOfMatch(content, pattern) {
    const index = content.indexOf(pattern);
    if (index === -1) return 0;
    return content.substring(0, index).split('\n').length - 1;
  }

  getLineContent(fileContent, lineNumber) {
    const lines = fileContent.split('\n');
    return lines[lineNumber - 1]?.trim() || '';
  }
  
  extractFunctionBlocks(content) {
    const functions = [];
    const functionRegex = /(?:public\s+)?(?:entry\s+)?fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)[^{]*\{/g;
    let match;
    
    while ((match = functionRegex.exec(content)) !== null) {
      const startIndex = match.index;
      const startLine = this.getLineNumber(content, startIndex);
      const endIndex = this.findMatchingBrace(content, match.index + match[0].length - 1);
      const parametersText = match[2].trim();
      
      // Parse parameters
      const parameters = parametersText ? 
        parametersText.split(',').map(p => p.trim()).filter(p => p.length > 0) : [];
      
      if (endIndex !== -1) {
        functions.push({
          name: match[1],
          signature: match[0].slice(0, -1), // Remove the opening brace
          content: content.substring(match.index, endIndex + 1),
          parameters: parameters,
          startLine: startLine,
          startIndex: startIndex,
          endIndex: endIndex
        });
      }
    }
    
    return functions;
  }
  
  findMatchingBrace(content, startIndex) {
    let depth = 1;
    for (let i = startIndex + 1; i < content.length; i++) {
      if (content[i] === '{') depth++;
      else if (content[i] === '}') depth--;
      
      if (depth === 0) return i;
    }
    return -1;
  }
  
  getLineNumber(content, index) {
    return content.substring(0, index).split('\n').length;
  }
}

module.exports = new SecurityScanner();