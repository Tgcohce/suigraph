/**
 * MoveBit-Enhanced Security Scanner
 * Implements comprehensive vulnerability detection based on MoveBit audit methodology
 * Combines static AST analysis with LLM-powered contextual analysis
 */

const OpenAI = require('openai');

class MoveBitEnhancedScanner {
  constructor() {
    // Initialize OpenAI client for LLM analysis
    this.openai = null;
    this.llmAvailable = false;
    
    if (process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'your_openai_api_key_here') {
      try {
        this.openai = new OpenAI({
          apiKey: process.env.OPENAI_API_KEY
        });
        this.llmAvailable = true;
        console.log('✅ MoveBit scanner: OpenAI client initialized');
      } catch (error) {
        console.warn('⚠️ MoveBit scanner: Failed to initialize OpenAI client:', error.message);
        this.llmAvailable = false;
      }
    } else {
      console.log('⚠️ MoveBit scanner: OpenAI API key not configured');
    }

    // MoveBit vulnerability categories with static detection rules
    this.vulnerabilityCategories = [
      {
        id: 'transaction-ordering-dependence',
        name: 'Transaction-Ordering Dependence',
        category: 'Race Conditions',
        severity: 'major',
        staticCheck: this.checkTransactionOrdering.bind(this),
        llmCheck: true
      },
      {
        id: 'timestamp-dependence',
        name: 'Timestamp Dependence',
        category: 'Temporal Logic',
        severity: 'medium',
        staticCheck: this.checkTimestampDependence.bind(this),
        llmCheck: true
      },
      {
        id: 'integer-overflow-underflow',
        name: 'Integer Overflow/Underflow',
        category: 'Arithmetic Safety',
        severity: 'major',
        staticCheck: this.checkIntegerOverflow.bind(this),
        llmCheck: true
      },
      {
        id: 'rounding-errors',
        name: 'Rounding Errors',
        category: 'Precision Loss',
        severity: 'medium',
        staticCheck: this.checkRoundingErrors.bind(this),
        llmCheck: true
      },
      {
        id: 'unchecked-external-calls',
        name: 'Unchecked External Calls',
        category: 'Call Safety',
        severity: 'major',
        staticCheck: this.checkUncheckedExternalCalls.bind(this),
        llmCheck: true
      },
      {
        id: 'denial-of-service',
        name: 'Denial-of-Service',
        category: 'Availability',
        severity: 'major',
        staticCheck: this.checkDenialOfService.bind(this),
        llmCheck: true
      },
      {
        id: 'access-control',
        name: 'Access Control',
        category: 'Authorization',
        severity: 'critical',
        staticCheck: this.checkAccessControl.bind(this),
        llmCheck: true
      },
      {
        id: 'centralization-of-power',
        name: 'Centralization of Power',
        category: 'Governance',
        severity: 'medium',
        staticCheck: this.checkCentralizationOfPower.bind(this),
        llmCheck: true
      },
      {
        id: 'business-logic-issues',
        name: 'Business Logic Issues',
        category: 'Logic Flaws',
        severity: 'major',
        staticCheck: this.checkBusinessLogic.bind(this),
        llmCheck: true
      },
      {
        id: 'gas-usage-inefficiencies',
        name: 'Gas Usage Inefficiencies',
        category: 'Performance',
        severity: 'minor',
        staticCheck: this.checkGasInefficiencies.bind(this),
        llmCheck: true
      },
      {
        id: 'arbitrary-token-minting',
        name: 'Arbitrary Token Minting',
        category: 'Token Security',
        severity: 'critical',
        staticCheck: this.checkArbitraryMinting.bind(this),
        llmCheck: true
      },
      {
        id: 'reentrancy-attacks',
        name: 'Reentrancy Attacks',
        category: 'Control Flow',
        severity: 'critical',
        staticCheck: this.checkReentrancy.bind(this),
        llmCheck: true
      },
      {
        id: 'oracle-manipulation',
        name: 'Oracle Manipulation',
        category: 'External Dependencies',
        severity: 'major',
        staticCheck: this.checkOracleManipulation.bind(this),
        llmCheck: true
      },
      {
        id: 'mutable-reference-leaks',
        name: 'Mutable Reference Leaks',
        category: 'Memory Safety',
        severity: 'major',
        staticCheck: this.checkMutableReferenceLeaks.bind(this),
        llmCheck: true
      },
      {
        id: 'insufficient-authorization',
        name: 'Insufficient Authorization',
        category: 'Permission Checks',
        severity: 'critical',
        staticCheck: this.checkInsufficientAuthorization.bind(this),
        llmCheck: true
      }
    ];

    // Token limits for LLM chunking
    this.maxTokensPerChunk = 1500;
    this.estimatedTokensPerChar = 0.25;
  }

  /**
   * Main scanning function implementing MoveBit methodology
   */
  async scanForVulnerabilities(parsedFiles) {
    console.log('🔍 Starting MoveBit-enhanced vulnerability scan...');
    
    try {
      const allVulnerabilities = [];
      
      for (const file of parsedFiles) {
        if (!file.content || file.parseError) continue;
        
        console.log(`📄 Analyzing ${file.name}...`);
        
        // Extract functions for analysis
        const functions = this.extractFunctionBlocks(file.content);
        
        // Run static analysis for each category
        for (const category of this.vulnerabilityCategories) {
          const staticVulns = await category.staticCheck(file, functions);
          allVulnerabilities.push(...staticVulns);
        }
        
        // Run LLM analysis if available
        if (this.llmAvailable) {
          const llmVulns = await this.runLLMAnalysis(file);
          allVulnerabilities.push(...llmVulns);
        }
      }
      
      // Deduplicate results
      const deduplicatedVulns = this.deduplicateVulnerabilities(allVulnerabilities);
      
      console.log(`✅ MoveBit scan complete: ${deduplicatedVulns.length} vulnerabilities found`);
      
      return this.formatResults(deduplicatedVulns);
      
    } catch (error) {
      console.error('❌ MoveBit scan failed:', error);
      return [];
    }
  }

  // 1. Transaction-Ordering Dependence
  async checkTransactionOrdering(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for race condition patterns
      const hasStateRead = content.includes('balance::value') || content.includes('get_') || content.includes('read');
      const hasStateWrite = content.includes('balance::split') || content.includes('set_') || content.includes('update');
      const hasNoLocking = !content.includes('lock') && !content.includes('mutex') && !content.includes('atomic');
      
      if (hasStateRead && hasStateWrite && hasNoLocking && func.signature.includes('public')) {
        vulnerabilities.push({
          file: file.name,
          line: func.startLine,
          category: 'Transaction-Ordering Dependence',
          description: 'Function performs read-then-write operations without proper synchronization, vulnerable to race conditions',
          severity: 'major',
          source: 'static-movebit'
        });
      }
      
      // Check for timestamp-dependent logic
      if (content.includes('timestamp') || content.includes('epoch') || content.includes('time')) {
        const hasTimeBasedLogic = content.includes('if') && (content.includes('timestamp') || content.includes('time'));
        if (hasTimeBasedLogic) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Transaction-Ordering Dependence',
            description: 'Logic depends on block timestamp which can be manipulated by validators',
            severity: 'major',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 2. Timestamp Dependence
  async checkTimestampDependence(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Look for timestamp usage in critical logic
      const timestampPatterns = [
        /timestamp\s*[<>=]/g,
        /epoch\s*[<>=]/g,
        /time\s*[<>=]/g,
        /tx_context::epoch/g
      ];
      
      for (const pattern of timestampPatterns) {
        if (pattern.test(content)) {
          vulnerabilities.push({
            file: file.name,
            line: this.getLineOfMatch(content, pattern.source) + func.startLine,
            category: 'Timestamp Dependence',
            description: 'Critical logic depends on block timestamp which can be influenced by validators',
            severity: 'medium',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 3. Integer Overflow/Underflow
  async checkIntegerOverflow(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for arithmetic operations without safe checks
      const arithmeticOps = ['+', '-', '*', '/', '%'];
      
      for (const op of arithmeticOps) {
        const regex = new RegExp(`\\w+\\s*\\${op}\\s*\\w+`, 'g');
        const matches = content.match(regex);
        
        if (matches && !content.includes('checked_') && !content.includes('safe_')) {
          // Check if it's in a financial context
          const isFinancial = content.includes('amount') || content.includes('balance') || 
                            content.includes('value') || content.includes('price');
          
          if (isFinancial) {
            vulnerabilities.push({
              file: file.name,
              line: this.getLineOfMatch(content, matches[0]) + func.startLine,
              category: 'Integer Overflow/Underflow',
              description: `Arithmetic operation '${matches[0]}' without overflow protection in financial context`,
              severity: 'major',
              source: 'static-movebit'
            });
          }
        }
      }
    }
    
    return vulnerabilities;
  }

  // 4. Rounding Errors
  async checkRoundingErrors(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for division operations that may cause rounding issues
      const divisionMatches = content.match(/\/\s*\w+/g);
      if (divisionMatches) {
        const hasFinancialContext = content.includes('price') || content.includes('rate') || 
                                  content.includes('fee') || content.includes('reward');
        
        if (hasFinancialContext && !content.includes('precision') && !content.includes('scale')) {
          vulnerabilities.push({
            file: file.name,
            line: this.getLineOfMatch(content, divisionMatches[0]) + func.startLine,
            category: 'Rounding Errors',
            description: 'Division operation in financial calculation may cause precision loss',
            severity: 'medium',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 5. Unchecked External Calls
  async checkUncheckedExternalCalls(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Look for external calls without return value checks
      const externalCallPatterns = [
        /\w+::\w+\(/g,  // Module calls
        /transfer::/g,
        /coin::/g,
        /balance::/g
      ];
      
      for (const pattern of externalCallPatterns) {
        const matches = content.match(pattern);
        if (matches) {
          // Check if return value is used
          const lineContent = this.getLineContent(content, matches[0]);
          const hasReturnCheck = lineContent.includes('=') || lineContent.includes('assert!') || 
                               lineContent.includes('let ') || lineContent.includes('if');
          
          if (!hasReturnCheck && !lineContent.includes('transfer::')) {
            vulnerabilities.push({
              file: file.name,
              line: this.getLineOfMatch(content, matches[0]) + func.startLine,
              category: 'Unchecked External Calls',
              description: 'External call result not checked, may fail silently',
              severity: 'major',
              source: 'static-movebit'
            });
          }
        }
      }
    }
    
    return vulnerabilities;
  }

  // 6. Denial-of-Service
  async checkDenialOfService(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for unbounded loops
      if (content.includes('while') || content.includes('loop')) {
        const hasBreakCondition = content.includes('break') || content.includes('return');
        if (!hasBreakCondition) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Denial-of-Service',
            description: 'Unbounded loop may cause gas exhaustion or infinite execution',
            severity: 'major',
            source: 'static-movebit'
          });
        }
      }
      
      // Check for operations that may consume excessive gas
      const heavyOps = ['vector::for_each', 'vector::map', 'hash::sha3', 'crypto::'];
      for (const op of heavyOps) {
        if (content.includes(op)) {
          vulnerabilities.push({
            file: file.name,
            line: this.getLineOfMatch(content, op) + func.startLine,
            category: 'Denial-of-Service',
            description: `Heavy operation '${op}' may cause gas exhaustion in large datasets`,
            severity: 'medium',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 7. Access Control
  async checkAccessControl(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      if (func.signature.includes('public') && func.signature.includes('entry')) {
        const content = func.content;
        
        // Check for missing access controls
        const hasAccessControl = content.includes('assert!') || content.includes('has_access') ||
                               content.includes('capability') || content.includes('authority');
        
        const isPrivilegedOperation = content.includes('transfer') || content.includes('mint') ||
                                    content.includes('burn') || content.includes('admin') ||
                                    content.includes('owner');
        
        if (isPrivilegedOperation && !hasAccessControl) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Access Control',
            description: 'Privileged operation lacks proper access control checks',
            severity: 'critical',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 8. Centralization of Power
  async checkCentralizationOfPower(file, functions) {
    const vulnerabilities = [];
    let adminFunctionCount = 0;
    
    for (const func of functions) {
      const content = func.content;
      
      // Count admin functions
      if (content.includes('admin') || content.includes('owner') || content.includes('authority')) {
        adminFunctionCount++;
      }
      
      // Check for single-key control
      if (content.includes('AdminCap') && !content.includes('multisig') && !content.includes('consensus')) {
        vulnerabilities.push({
          file: file.name,
          line: func.startLine,
          category: 'Centralization of Power',
          description: 'Administrative function relies on single key without multisig protection',
          severity: 'medium',
          source: 'static-movebit'
        });
      }
    }
    
    // Flag if too many admin functions
    if (adminFunctionCount > 5) {
      vulnerabilities.push({
        file: file.name,
        line: 1,
        category: 'Centralization of Power',
        description: `High concentration of administrative functions (${adminFunctionCount}) may indicate centralization risk`,
        severity: 'medium',
        source: 'static-movebit'
      });
    }
    
    return vulnerabilities;
  }

  // 9. Business Logic Issues
  async checkBusinessLogic(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for missing boundary checks
      if (content.includes('amount') || content.includes('value')) {
        const hasBoundaryCheck = content.includes('assert!(') && 
                               (content.includes('> 0') || content.includes('!= 0') || content.includes('<='));
        
        if (!hasBoundaryCheck && func.signature.includes('public')) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Business Logic Issues',
            description: 'Function handles amounts/values without proper boundary validation',
            severity: 'major',
            source: 'static-movebit'
          });
        }
      }
      
      // Check for inconsistent state updates
      if (content.includes('balance') && content.includes('update')) {
        const updates = content.match(/\w+\s*=\s*/g);
        if (updates && updates.length > 1 && !content.includes('atomic') && !content.includes('transaction')) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Business Logic Issues',
            description: 'Multiple state updates without atomic transaction protection',
            severity: 'major',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 10. Gas Usage Inefficiencies
  async checkGasInefficiencies(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for inefficient patterns
      const inefficiencies = [
        { pattern: 'vector::length', message: 'Consider caching vector length in loops' },
        { pattern: 'string::utf8', message: 'String operations can be gas-intensive' },
        { pattern: 'table::borrow', message: 'Frequent table access may be inefficient' },
        { pattern: 'event::emit', message: 'Excessive event emission increases gas cost' }
      ];
      
      for (const inefficiency of inefficiencies) {
        const matches = (content.match(new RegExp(inefficiency.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g')) || []).length;
        if (matches > 3) { // Flag if used more than 3 times
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Gas Usage Inefficiencies',
            description: `${inefficiency.message} (${matches} occurrences)`,
            severity: 'minor',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 11. Arbitrary Token Minting
  async checkArbitraryMinting(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for minting functions
      if (content.includes('mint') || content.includes('coin::from_balance')) {
        const hasSupplyCheck = content.includes('supply') || content.includes('cap') || content.includes('limit');
        const hasAccessControl = content.includes('assert!') || content.includes('capability');
        
        if (!hasSupplyCheck && func.signature.includes('public')) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Arbitrary Token Minting',
            description: 'Token minting function lacks supply cap validation',
            severity: 'critical',
            source: 'static-movebit'
          });
        }
        
        if (!hasAccessControl && func.signature.includes('public')) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Arbitrary Token Minting',
            description: 'Token minting function lacks proper access control',
            severity: 'critical',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 12. Reentrancy Attacks
  async checkReentrancy(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for reentrancy patterns
      if (content.includes('transfer') && content.includes('call')) {
        const hasReentrancyGuard = content.includes('reentrancy_guard') || content.includes('nonReentrant') ||
                                 content.includes('lock') || content.includes('mutex');
        
        if (!hasReentrancyGuard) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Reentrancy Attacks',
            description: 'Function performs external calls and transfers without reentrancy protection',
            severity: 'critical',
            source: 'static-movebit'
          });
        }
      }
      
      // Check for checks-effects-interactions pattern violation
      const hasTransfer = content.includes('transfer');
      const hasStateUpdate = content.includes('=') && (content.includes('balance') || content.includes('amount'));
      
      if (hasTransfer && hasStateUpdate) {
        // Simple heuristic: if transfer comes before state update
        const transferIndex = content.indexOf('transfer');
        const stateUpdateIndex = content.lastIndexOf('=');
        
        if (transferIndex < stateUpdateIndex && transferIndex !== -1) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Reentrancy Attacks',
            description: 'Transfer occurs before state update, violating checks-effects-interactions pattern',
            severity: 'major',
            source: 'static-movebit'
          });
        }
      }
    }
    
    return vulnerabilities;
  }

  // 13. Oracle Manipulation
  async checkOracleManipulation(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for price oracle usage
      if (content.includes('price') || content.includes('oracle') || content.includes('feed')) {
        const hasTimeWeighting = content.includes('twap') || content.includes('time_weighted') ||
                                content.includes('average') || content.includes('median');
        
        const hasValidation = content.includes('assert!') || content.includes('validate') ||
                            content.includes('bounds') || content.includes('sanity');
        
        if (!hasTimeWeighting && !hasValidation) {
          vulnerabilities.push({
            file: file.name,
            line: func.startLine,
            category: 'Oracle Manipulation',
            description: 'Price oracle usage without time weighting or validation checks',
            severity: 'major',
            source: 'static-movebit'
          });
        }
      }
      
      // Check for single oracle dependency
      if (content.includes('get_price') && !content.includes('multiple') && !content.includes('fallback')) {
        vulnerabilities.push({
          file: file.name,
          line: func.startLine,
          category: 'Oracle Manipulation',
          description: 'Single oracle dependency without fallback mechanism',
          severity: 'medium',
          source: 'static-movebit'
        });
      }
    }
    
    return vulnerabilities;
  }

  // 14. Mutable Reference Leaks
  async checkMutableReferenceLeaks(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      const content = func.content;
      
      // Check for mutable references passed to external modules
      const mutRefMatches = content.match(/&mut\s+\w+/g);
      if (mutRefMatches && func.signature.includes('public')) {
        for (const mutRef of mutRefMatches) {
          // Check if it's passed to external calls
          const externalCallNearby = content.includes('::') && 
                                   content.indexOf('::') > content.indexOf(mutRef) - 50 &&
                                   content.indexOf('::') < content.indexOf(mutRef) + 50;
          
          if (externalCallNearby) {
            vulnerabilities.push({
              file: file.name,
              line: this.getLineOfMatch(content, mutRef) + func.startLine,
              category: 'Mutable Reference Leaks',
              description: `Mutable reference ${mutRef} may be passed to untrusted external module`,
              severity: 'major',
              source: 'static-movebit'
            });
          }
        }
      }
    }
    
    return vulnerabilities;
  }

  // 15. Insufficient Authorization
  async checkInsufficientAuthorization(file, functions) {
    const vulnerabilities = [];
    
    for (const func of functions) {
      if (func.signature.includes('public')) {
        const content = func.content;
        
        // Check for privileged operations
        const privilegedOps = ['admin', 'owner', 'mint', 'burn', 'transfer', 'withdraw', 'emergency'];
        const hasPrivilegedOp = privilegedOps.some(op => func.name.includes(op) || content.includes(op));
        
        if (hasPrivilegedOp) {
          const hasAuthorization = content.includes('assert!') || content.includes('require') ||
                                 content.includes('capability') || content.includes('permission');
          
          if (!hasAuthorization) {
            vulnerabilities.push({
              file: file.name,
              line: func.startLine,
              category: 'Insufficient Authorization',
              description: 'Privileged operation lacks sufficient authorization checks',
              severity: 'critical',
              source: 'static-movebit'
            });
          }
        }
        
        // Check for role-based access patterns
        if (content.includes('role') || content.includes('permission')) {
          const hasRoleValidation = content.includes('has_role') || content.includes('check_permission');
          
          if (!hasRoleValidation) {
            vulnerabilities.push({
              file: file.name,
              line: func.startLine,
              category: 'Insufficient Authorization',
              description: 'Role-based function lacks proper role validation',
              severity: 'major',
              source: 'static-movebit'
            });
          }
        }
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Run LLM analysis for complex business logic detection
   */
  async runLLMAnalysis(file) {
    if (!this.llmAvailable) return [];
    
    try {
      const chunks = this.splitIntoChunks(file.content, file.name);
      const allLLMVulns = [];
      
      for (const chunk of chunks) {
        const llmVulns = await this.analyzeLLMChunk(chunk);
        allLLMVulns.push(...llmVulns);
      }
      
      return allLLMVulns;
    } catch (error) {
      console.error(`❌ LLM analysis failed for ${file.name}:`, error.message);
      return [];
    }
  }

  /**
   * Analyze a code chunk with LLM for MoveBit categories
   */
  async analyzeLLMChunk(chunk) {
    const systemPrompt = `You are an expert Move smart contract auditor specializing in MoveBit audit methodology. Analyze the provided code chunk for the following vulnerability categories:

1. Transaction-Ordering Dependence (race conditions)
2. Timestamp Dependence (block.timestamp misuse)
3. Integer Overflow/Underflow (unsafe arithmetic)
4. Rounding Errors (precision loss in calculations)
5. Unchecked External Calls (missing return checks)
6. Denial-of-Service (gas exhaustion, infinite loops)
7. Access Control (missing permission checks)
8. Centralization of Power (single-key control)
9. Business Logic Issues (flawed reward/permission logic)
10. Gas Usage Inefficiencies (expensive operations)
11. Arbitrary Token Minting (unchecked mint functions)
12. Reentrancy Attacks (external calls before state updates)
13. Oracle Manipulation (unvalidated price feeds)
14. Mutable Reference Leaks (unsafe &mut sharing)
15. Insufficient Authorization (missing capability checks)

Focus on business logic flaws, complex interaction patterns, and subtle vulnerabilities that static analysis might miss.`;

    const userPrompt = `Analyze this Move code chunk for MoveBit vulnerability categories:

File: ${chunk.fileName}
Lines: ${chunk.startLine}-${chunk.endLine}

\`\`\`move
${chunk.content}
\`\`\`

Return findings in this JSON format:
[
  {
    "file": "${chunk.fileName}",
    "line": <line_number>,
    "category": "<category_name>",
    "description": "<detailed_description>",
    "severity": "critical|major|medium|minor"
  }
]

Only return actual vulnerabilities. If no vulnerabilities found, return empty array: []`;

    try {
      const response = await this.openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt }
        ],
        temperature: 0.1,
        max_tokens: 1000,
        response_format: { type: "json_object" }
      });

      const content = response.choices[0].message.content;
      let vulnerabilities = [];

      try {
        const parsed = JSON.parse(content);
        if (Array.isArray(parsed)) {
          vulnerabilities = parsed;
        } else if (parsed.vulnerabilities && Array.isArray(parsed.vulnerabilities)) {
          vulnerabilities = parsed.vulnerabilities;
        }
      } catch (parseError) {
        console.warn(`⚠️ Failed to parse LLM response:`, content.substring(0, 200));
        return [];
      }

      // Validate and format results
      return vulnerabilities.map(vuln => ({
        file: vuln.file || chunk.fileName,
        line: this.adjustLineNumber(vuln.line, chunk.startLine, chunk.endLine),
        category: vuln.category || 'Business Logic Issues',
        description: vuln.description || 'LLM-detected vulnerability',
        severity: this.normalizeSeverity(vuln.severity),
        source: 'llm-movebit'
      }));

    } catch (error) {
      console.error('❌ OpenAI API error:', error.message);
      return [];
    }
  }

  /**
   * Format final results in MoveBit format
   */
  formatResults(vulnerabilities) {
    return vulnerabilities.map(vuln => ({
      file: vuln.file,
      line: vuln.line,
      category: vuln.category,
      description: vuln.description,
      severity: vuln.severity
    }));
  }

  // Helper methods
  splitIntoChunks(content, fileName) {
    const lines = content.split('\n');
    const chunks = [];
    let currentChunk = '';
    let currentStartLine = 1;
    let currentLine = 1;
    let estimatedTokens = 0;

    for (const line of lines) {
      const lineTokens = line.length * this.estimatedTokensPerChar;
      
      if (estimatedTokens + lineTokens > this.maxTokensPerChunk && currentChunk.length > 0) {
        chunks.push({
          content: currentChunk,
          fileName: fileName,
          startLine: currentStartLine,
          endLine: currentLine - 1
        });
        
        currentChunk = line + '\n';
        currentStartLine = currentLine;
        estimatedTokens = lineTokens;
      } else {
        currentChunk += line + '\n';
        estimatedTokens += lineTokens;
      }
      
      currentLine++;
    }
    
    if (currentChunk.trim().length > 0) {
      chunks.push({
        content: currentChunk,
        fileName: fileName,
        startLine: currentStartLine,
        endLine: currentLine - 1
      });
    }
    
    return chunks;
  }

  adjustLineNumber(reportedLine, chunkStartLine, chunkEndLine) {
    if (typeof reportedLine !== 'number') return chunkStartLine;
    
    if (reportedLine <= (chunkEndLine - chunkStartLine + 1)) {
      return chunkStartLine + reportedLine - 1;
    }
    
    if (reportedLine >= chunkStartLine && reportedLine <= chunkEndLine) {
      return reportedLine;
    }
    
    return chunkStartLine;
  }

  normalizeSeverity(severity) {
    if (!severity) return 'medium';
    
    const normalized = severity.toLowerCase();
    if (['critical'].includes(normalized)) return 'critical';
    if (['major', 'high'].includes(normalized)) return 'major';
    if (['medium', 'moderate'].includes(normalized)) return 'medium';
    if (['minor', 'low', 'info'].includes(normalized)) return 'minor';
    
    return 'medium';
  }

  deduplicateVulnerabilities(vulnerabilities) {
    const seen = new Set();
    const deduplicated = [];
    
    for (const vuln of vulnerabilities) {
      const key = `${vuln.file}:${Math.floor(vuln.line / 3)}:${vuln.category}`;
      
      if (!seen.has(key)) {
        seen.add(key);
        deduplicated.push(vuln);
      }
    }
    
    return deduplicated;
  }

  extractFunctionBlocks(content) {
    const functions = [];
    const functionRegex = /(?:public\s+)?(?:entry\s+)?fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)[^{]*\{/g;
    let match;
    
    while ((match = functionRegex.exec(content)) !== null) {
      const startIndex = match.index;
      const startLine = this.getLineNumber(content, startIndex);
      const endIndex = this.findMatchingBrace(content, match.index + match[0].length - 1);
      
      if (endIndex !== -1) {
        functions.push({
          name: match[1],
          signature: match[0].slice(0, -1),
          content: content.substring(match.index, endIndex + 1),
          startLine: startLine,
          startIndex: startIndex,
          endIndex: endIndex
        });
      }
    }
    
    return functions;
  }

  getLineOfMatch(content, pattern) {
    const index = content.indexOf(pattern);
    if (index === -1) return 0;
    return content.substring(0, index).split('\n').length - 1;
  }

  getLineContent(content, pattern) {
    const index = content.indexOf(pattern);
    if (index === -1) return '';
    
    const lines = content.split('\n');
    const lineNum = content.substring(0, index).split('\n').length - 1;
    return lines[lineNum] || '';
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

module.exports = new MoveBitEnhancedScanner();