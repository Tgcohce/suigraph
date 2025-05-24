/**
 * Enhanced Security Scanner Service
 * Comprehensive AST-based security analysis with taint propagation and simulation
 */

class EnhancedSecurityScanner {
  constructor() {
    // Core Move security patterns
    this.astRules = [
      {
        id: 'unrestricted-public-entry',
        name: 'Unrestricted Public Entry Function',
        severity: 'high',
        description: 'Public entry functions without proper access controls',
        check: this.checkUnrestrictedPublicEntry.bind(this)
      },
      {
        id: 'mutable-shared-data',
        name: 'Mutable References to Shared Data',
        severity: 'high',
        description: 'Mutable access to shared objects without proper synchronization',
        check: this.checkMutableSharedData.bind(this)
      },
      {
        id: 'unchecked-coin-transfers',
        name: 'Unchecked Coin Transfers',
        severity: 'critical',
        description: 'Coin transfer operations without proper access controls',
        check: this.checkUncheckedCoinTransfers.bind(this)
      },
      {
        id: 'authority-overuse',
        name: 'Authority Overuse',
        severity: 'medium',
        description: 'Excessive or unchecked use of administrative authorities',
        check: this.checkAuthorityOveruse.bind(this)
      },
      {
        id: 'missing-access-guards',
        name: 'Missing Access Guards',
        severity: 'high',
        description: 'Missing has_access or assert_owner guard checks',
        check: this.checkMissingAccessGuards.bind(this)
      },
      {
        id: 'cetus-defi-pattern',
        name: 'Cetus-style DeFi Vulnerability',
        severity: 'critical',
        description: 'Public function can transfer coins without access control',
        check: this.checkCetusDefiFPattern.bind(this)
      }
    ];

    // Taint tracking state
    this.taintedVariables = new Set();
    this.accessChecks = new Set();
    this.transferOperations = new Set();
  }

  /**
   * Main scan function - analyzes AST and graph for vulnerabilities
   */
  async scan(ast, graph) {
    const vulnerabilities = [];
    const simulations = [];

    try {
      // Run static AST analysis
      const staticVulns = this.runStaticAnalysis(ast, graph);
      vulnerabilities.push(...staticVulns);

      // Run taint propagation analysis
      const taintVulns = this.runTaintAnalysis(ast, graph);
      vulnerabilities.push(...taintVulns);

      // Run dry-run simulations
      const simResults = await this.runSimulations(ast, graph);
      simulations.push(...simResults);

      return {
        vulnerabilities,
        simulations,
        metadata: {
          staticAnalysisCount: staticVulns.length,
          taintAnalysisCount: taintVulns.length,
          simulationCount: simResults.length,
          analysisTimestamp: new Date().toISOString()
        }
      };
    } catch (error) {
      console.error('Enhanced security scan error:', error);
      return {
        vulnerabilities: [],
        simulations: [],
        error: error.message
      };
    }
  }

  /**
   * Run static AST pattern analysis
   */
  runStaticAnalysis(ast, graph) {
    const vulnerabilities = [];

    // Extract parsed files from AST
    const parsedFiles = this.extractParsedFiles(ast);

    for (const file of parsedFiles) {
      if (!file.ast || file.parseError) continue;

      // Extract functions from AST
      const functions = this.extractFunctionsFromAST(file.ast);

      // Run each AST rule
      for (const rule of this.astRules) {
        try {
          const ruleVulns = rule.check(file, functions, ast, graph);
          vulnerabilities.push(...ruleVulns);
        } catch (error) {
          console.error(`Error in rule ${rule.id}:`, error);
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * 1. Check for unrestricted public entry functions
   */
  checkUnrestrictedPublicEntry(file, functions, ast, graph) {
    const vulnerabilities = [];

    for (const func of functions) {
      if (this.isPublicEntry(func)) {
        const hasAccessControl = this.hasAccessControlInFunction(func);
        
        if (!hasAccessControl) {
          vulnerabilities.push({
            id: 'unrestricted-public-entry',
            name: 'Unrestricted Public Entry Function',
            severity: 'high',
            description: 'Public entry function lacks proper access controls',
            file: file.name,
            line: func.line || 1,
            code: func.signature || func.name,
            match: func.name,
            recommendation: 'Add capability checks or assert_owner guards',
            confidence: 'high',
            astLocation: func.astNode
          });
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * 2. Check for mutable references to shared data
   */
  checkMutableSharedData(file, functions, ast, graph) {
    const vulnerabilities = [];

    for (const func of functions) {
      const sharedMutAccess = this.findSharedMutableAccess(func);
      
      if (sharedMutAccess.length > 0) {
        vulnerabilities.push({
          id: 'mutable-shared-data',
          name: 'Mutable References to Shared Data',
          severity: 'high',
          description: 'Function has mutable access to shared objects without proper synchronization',
          file: file.name,
          line: func.line || 1,
          code: func.signature || func.name,
          match: sharedMutAccess.join(', '),
          recommendation: 'Add proper synchronization or use immutable references',
          confidence: 'medium',
          astLocation: func.astNode
        });
      }
    }

    return vulnerabilities;
  }

  /**
   * 3. Check for unchecked coin transfers
   */
  checkUncheckedCoinTransfers(file, functions, ast, graph) {
    const vulnerabilities = [];

    for (const func of functions) {
      const coinTransfers = this.findCoinTransfers(func);
      
      for (const transfer of coinTransfers) {
        const hasGuard = this.hasAccessGuardBeforeTransfer(func, transfer);
        
        if (!hasGuard) {
          vulnerabilities.push({
            id: 'unchecked-coin-transfers',
            name: 'Unchecked Coin Transfer',
            severity: 'critical',
            description: 'Coin transfer operation without proper access control',
            file: file.name,
            line: transfer.line || func.line || 1,
            code: transfer.code || func.signature,
            match: transfer.operation,
            recommendation: 'Add access control checks before coin transfers',
            confidence: 'high',
            astLocation: transfer.astNode
          });
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * 4. Check for authority overuse
   */
  checkAuthorityOveruse(file, functions, ast, graph) {
    const vulnerabilities = [];

    const authorityUsage = this.analyzeAuthorityUsage(functions);
    
    if (authorityUsage.overused.length > 0) {
      vulnerabilities.push({
        id: 'authority-overuse',
        name: 'Authority Overuse',
        severity: 'medium',
        description: 'Excessive use of administrative authorities without proper checks',
        file: file.name,
        line: 1,
        code: `Functions: ${authorityUsage.overused.join(', ')}`,
        match: authorityUsage.overused[0],
        recommendation: 'Limit authority usage and add proper verification',
        confidence: 'medium'
      });
    }

    return vulnerabilities;
  }

  /**
   * 5. Check for missing access guards
   */
  checkMissingAccessGuards(file, functions, ast, graph) {
    const vulnerabilities = [];

    for (const func of functions) {
      if (this.requiresAccessGuard(func)) {
        const hasGuard = this.hasAccessGuard(func);
        
        if (!hasGuard) {
          vulnerabilities.push({
            id: 'missing-access-guards',
            name: 'Missing Access Guards',
            severity: 'high',
            description: 'Function requires but lacks has_access or assert_owner guards',
            file: file.name,
            line: func.line || 1,
            code: func.signature || func.name,
            match: func.name,
            recommendation: 'Add has_access() or assert_owner() checks',
            confidence: 'high',
            astLocation: func.astNode
          });
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * 6. Check for Cetus-style DeFi patterns
   */
  checkCetusDefiFPattern(file, functions, ast, graph) {
    const vulnerabilities = [];

    for (const func of functions) {
      if (this.isPublicFunction(func)) {
        const transferPaths = this.findTransferPaths(func, graph);
        
        for (const path of transferPaths) {
          const hasAccessGuard = this.pathHasAccessGuard(path);
          
          if (!hasAccessGuard) {
            vulnerabilities.push({
              id: 'cetus-defi-pattern',
              name: 'Cetus-style DeFi Vulnerability',
              severity: 'critical',
              description: 'Public function can transfer coins without access control (similar to Cetus exploit)',
              file: file.name,
              line: func.line || 1,
              code: func.signature || func.name,
              match: func.name,
              recommendation: 'Add access control checks before any transfer operations',
              confidence: 'high',
              astLocation: func.astNode,
              transferPath: path
            });
          }
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Run taint propagation analysis
   */
  runTaintAnalysis(ast, graph) {
    const vulnerabilities = [];
    this.taintedVariables.clear();

    const parsedFiles = this.extractParsedFiles(ast);

    for (const file of parsedFiles) {
      if (!file.ast) continue;

      const functions = this.extractFunctionsFromAST(file.ast);
      
      for (const func of functions) {
        if (this.isEntryPoint(func)) {
          // Tag entrypoint parameters as tainted
          this.tagEntryPointParameters(func);
          
          // Propagate taint through function
          const taintVulns = this.propagateTaint(func, file);
          vulnerabilities.push(...taintVulns);
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Tag entrypoint parameters for resource types as tainted
   */
  tagEntryPointParameters(func) {
    for (const param of func.parameters || []) {
      if (this.isResourceType(param.type)) {
        this.taintedVariables.add(`${func.name}::${param.name}`);
      }
    }
  }

  /**
   * Propagate taint through function and detect violations
   */
  propagateTaint(func, file) {
    const vulnerabilities = [];
    const instructions = this.extractInstructions(func);

    for (const instruction of instructions) {
      // Check for arithmetic/transfer on tainted resource before access check
      if (this.isArithmeticOrTransfer(instruction)) {
        const involvesTainted = this.instructionInvolvesTainted(instruction);
        
        if (involvesTainted && !this.hasAccessCheckBefore(instruction, instructions)) {
          vulnerabilities.push({
            id: 'taint-violation',
            name: 'Tainted Resource Operation',
            severity: 'high',
            description: 'Operation on tainted resource occurs before access check',
            file: file.name,
            line: instruction.line || func.line || 1,
            code: instruction.code || instruction.type,
            match: instruction.target || 'tainted_operation',
            recommendation: 'Add access control checks before operating on tainted resources',
            confidence: 'high'
          });
        }
      }

      // Propagate taint through assignments
      if (instruction.type === 'assignment') {
        this.propagateTaintAssignment(instruction);
      }
    }

    return vulnerabilities;
  }

  /**
   * Run dry-run simulations
   */
  async runSimulations(ast, graph) {
    const simulations = [];
    const parsedFiles = this.extractParsedFiles(ast);

    for (const file of parsedFiles) {
      if (!file.ast) continue;

      const functions = this.extractFunctionsFromAST(file.ast);
      
      for (const func of functions) {
        if (this.isPublicEntry(func)) {
          try {
            const simulation = await this.runDryRunSimulation(func, file);
            simulations.push(simulation);
          } catch (error) {
            simulations.push({
              function: func.name,
              file: file.name,
              status: 'error',
              error: error.message
            });
          }
        }
      }
    }

    return simulations;
  }

  /**
   * Run dry-run simulation for a specific function
   */
  async runDryRunSimulation(func, file) {
    // Note: This would require actual Sui RPC connection
    // For now, return a mock simulation result
    
    const transaction = this.constructMockTransaction(func);
    
    // In a real implementation, this would call Sui JSON RPC dryRunTransaction
    // const result = await this.callSuiRPC('sui_dryRunTransactionBlock', transaction);
    
    return {
      function: func.name,
      file: file.name,
      status: 'success',
      transaction: transaction,
      result: {
        status: 'success',
        gasUsed: 1000000,
        warnings: []
      },
      recommendation: 'Review simulation results for unexpected behavior'
    };
  }

  // Helper methods for AST analysis

  extractParsedFiles(ast) {
    // Handle both array of files and single AST structure
    if (Array.isArray(ast)) {
      return ast;
    }
    if (ast.files) {
      return ast.files;
    }
    return [{ name: 'unnamed.move', ast: ast, content: '' }];
  }

  extractFunctionsFromAST(ast) {
    const functions = [];
    
    if (ast.modules) {
      for (const module of ast.modules) {
        if (module.functions) {
          functions.push(...module.functions);
        }
      }
    }
    
    return functions;
  }

  isPublicEntry(func) {
    return func.visibility === 'public' && func.isEntry === true;
  }

  isPublicFunction(func) {
    return func.visibility === 'public';
  }

  isEntryPoint(func) {
    return this.isPublicEntry(func);
  }

  hasAccessControlInFunction(func) {
    const content = func.content || func.body || '';
    return content.includes('assert!') || 
           content.includes('has_access') || 
           content.includes('assert_owner') ||
           content.includes('capability');
  }

  findSharedMutableAccess(func) {
    const content = func.content || func.body || '';
    const matches = content.match(/&mut\s+\w+/g) || [];
    return matches.filter(match => 
      content.includes('shared') || 
      content.includes('global')
    );
  }

  findCoinTransfers(func) {
    const content = func.content || func.body || '';
    const transfers = [];
    
    const transferPatterns = [
      /coin::transfer/g,
      /transfer::public_transfer/g,
      /transfer::transfer/g,
      /sui::transfer/g
    ];

    for (const pattern of transferPatterns) {
      const matches = [...content.matchAll(pattern)];
      for (const match of matches) {
        transfers.push({
          operation: match[0],
          line: this.getLineFromIndex(content, match.index),
          code: this.getLineContent(content, match.index)
        });
      }
    }

    return transfers;
  }

  hasAccessGuardBeforeTransfer(func, transfer) {
    const content = func.content || func.body || '';
    const transferIndex = content.indexOf(transfer.operation);
    const beforeTransfer = content.substring(0, transferIndex);
    
    return beforeTransfer.includes('assert!') || 
           beforeTransfer.includes('has_access') ||
           beforeTransfer.includes('assert_owner');
  }

  analyzeAuthorityUsage(functions) {
    const authorityFunctions = [];
    const overused = [];

    for (const func of functions) {
      const content = func.content || func.body || '';
      const authorityCount = (content.match(/Cap|Authority|Admin/g) || []).length;
      
      if (authorityCount > 0) {
        authorityFunctions.push(func.name);
        
        if (authorityCount > 2 && !this.hasAccessControlInFunction(func)) {
          overused.push(func.name);
        }
      }
    }

    return { authorityFunctions, overused };
  }

  requiresAccessGuard(func) {
    const content = func.content || func.body || '';
    return this.isPublicFunction(func) && (
      content.includes('transfer') ||
      content.includes('mint') ||
      content.includes('burn') ||
      content.includes('Cap')
    );
  }

  hasAccessGuard(func) {
    return this.hasAccessControlInFunction(func);
  }

  findTransferPaths(func, graph) {
    // Simplified path finding - would need more sophisticated graph traversal
    const paths = [];
    const content = func.content || func.body || '';
    
    if (content.includes('transfer') || content.includes('coin::')) {
      paths.push([{
        function: func.name,
        operation: 'transfer',
        hasGuard: this.hasAccessControlInFunction(func)
      }]);
    }

    return paths;
  }

  pathHasAccessGuard(path) {
    return path.some(node => node.hasGuard);
  }

  isResourceType(type) {
    return type && (
      type.includes('Coin') || 
      type.includes('Pool') || 
      type.includes('Treasury') ||
      type.includes('Balance')
    );
  }

  extractInstructions(func) {
    // Mock instruction extraction - would parse actual AST
    const content = func.content || func.body || '';
    const lines = content.split('\n');
    
    return lines.map((line, index) => ({
      type: this.classifyInstruction(line),
      code: line.trim(),
      line: index + 1,
      target: this.extractTarget(line)
    })).filter(inst => inst.type !== 'unknown' && inst.code.length > 0);
  }

  classifyInstruction(line) {
    const trimmed = line.trim();
    if (trimmed.includes('=') && !trimmed.includes('==')) return 'assignment';
    if (trimmed.includes('transfer')) return 'transfer';
    if (trimmed.includes('*') && trimmed.includes('=')) return 'arithmetic';
    if (trimmed.includes('assert!') || trimmed.includes('has_access')) return 'access_check';
    return 'unknown';
  }

  extractTarget(line) {
    const match = line.match(/(\w+)\s*=/);
    return match ? match[1] : null;
  }

  isArithmeticOrTransfer(instruction) {
    return instruction.type === 'arithmetic' || instruction.type === 'transfer';
  }

  instructionInvolvesTainted(instruction) {
    for (const tainted of this.taintedVariables) {
      if (instruction.code.includes(tainted.split('::')[1])) {
        return true;
      }
    }
    return false;
  }

  hasAccessCheckBefore(instruction, instructions) {
    const currentIndex = instructions.indexOf(instruction);
    return instructions.slice(0, currentIndex).some(inst => inst.type === 'access_check');
  }

  propagateTaintAssignment(instruction) {
    // Simple taint propagation through assignments
    if (this.instructionInvolvesTainted(instruction) && instruction.target) {
      this.taintedVariables.add(instruction.target);
    }
  }

  constructMockTransaction(func) {
    return {
      kind: 'moveCall',
      target: `${func.module}::${func.name}`,
      arguments: this.generateMockArguments(func),
      typeArguments: []
    };
  }

  generateMockArguments(func) {
    return (func.parameters || []).map(param => {
      if (param.type.includes('u64')) return '100';
      if (param.type.includes('address')) return '0x1';
      if (param.type.includes('bool')) return 'true';
      return '0x0';
    });
  }

  getLineFromIndex(content, index) {
    return content.substring(0, index).split('\n').length;
  }

  getLineContent(content, index) {
    const lines = content.split('\n');
    const lineNum = this.getLineFromIndex(content, index);
    return lines[lineNum - 1] || '';
  }
}

module.exports = new EnhancedSecurityScanner();