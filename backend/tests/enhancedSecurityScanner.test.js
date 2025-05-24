const enhancedSecurityScanner = require('../src/services/enhancedSecurityScanner');

describe('Enhanced Security Scanner', () => {
  
  describe('Unchecked Transfer Detection', () => {
    test('should detect public function that transfers SUI without guard', async () => {
      const ast = [{
        name: 'vulnerable.move',
        content: `
          module vulnerable::transfer {
            use sui::coin::{Self, Coin};
            use sui::sui::SUI;
            use sui::transfer;
            
            public entry fun withdraw_without_check(treasury: &mut Treasury, amount: u64, ctx: &mut TxContext) {
              let coin = coin::take(&mut treasury.balance, amount, ctx);
              transfer::public_transfer(coin, tx_context::sender(ctx));
            }
          }
        `,
        ast: {
          modules: [{
            name: 'transfer',
            functions: [{
              name: 'withdraw_without_check',
              visibility: 'public',
              isEntry: true,
              line: 6,
              signature: 'public entry fun withdraw_without_check(treasury: &mut Treasury, amount: u64, ctx: &mut TxContext)',
              content: `
                let coin = coin::take(&mut treasury.balance, amount, ctx);
                transfer::public_transfer(coin, tx_context::sender(ctx));
              `,
              parameters: [
                { name: 'treasury', type: '&mut Treasury' },
                { name: 'amount', type: 'u64' },
                { name: 'ctx', type: '&mut TxContext' }
              ]
            }]
          }]
        }
      }];

      const graph = { nodes: [], links: [] };
      const result = await enhancedSecurityScanner.scan(ast, graph);

      expect(result.vulnerabilities.length).toBeGreaterThanOrEqual(3); // unrestricted-public-entry, unchecked-coin-transfers, cetus-defi-pattern
      
      const cetusVuln = result.vulnerabilities.find(v => v.id === 'cetus-defi-pattern');
      expect(cetusVuln).toBeDefined();
      expect(cetusVuln.severity).toBe('critical');
      expect(cetusVuln.name).toBe('Cetus-style DeFi Vulnerability');
    });

    test('should not flag functions with proper access controls', async () => {
      const ast = [{
        name: 'secure.move',
        content: `
          module secure::transfer {
            use sui::coin::{Self, Coin};
            use sui::sui::SUI;
            use sui::transfer;
            
            public entry fun withdraw_with_check(cap: &AdminCap, treasury: &mut Treasury, amount: u64, ctx: &mut TxContext) {
              assert!(cap.owner == tx_context::sender(ctx), 0);
              let coin = coin::take(&mut treasury.balance, amount, ctx);
              transfer::public_transfer(coin, tx_context::sender(ctx));
            }
          }
        `,
        ast: {
          modules: [{
            name: 'transfer',
            functions: [{
              name: 'withdraw_with_check',
              visibility: 'public',
              isEntry: true,
              line: 6,
              signature: 'public entry fun withdraw_with_check(cap: &AdminCap, treasury: &mut Treasury, amount: u64, ctx: &mut TxContext)',
              content: `
                assert!(cap.owner == tx_context::sender(ctx), 0);
                let coin = coin::take(&mut treasury.balance, amount, ctx);
                transfer::public_transfer(coin, tx_context::sender(ctx));
              `,
              parameters: [
                { name: 'cap', type: '&AdminCap' },
                { name: 'treasury', type: '&mut Treasury' },
                { name: 'amount', type: 'u64' },
                { name: 'ctx', type: '&mut TxContext' }
              ]
            }]
          }]
        }
      }];

      const graph = { nodes: [], links: [] };
      const result = await enhancedSecurityScanner.scan(ast, graph);

      const cetusVuln = result.vulnerabilities.find(v => v.id === 'cetus-defi-pattern');
      expect(cetusVuln).toBeUndefined();
    });
  });

  describe('Taint Propagation', () => {
    test('should detect tainted resource operations', async () => {
      const ast = [{
        name: 'tainted.move',
        content: `
          module tainted::operations {
            public entry fun process_coin(coin: Coin<SUI>, ctx: &mut TxContext) {
              let amount = coin::value(&coin);
              let doubled = amount * 2;
              assert!(doubled > 0, 1);
            }
          }
        `,
        ast: {
          modules: [{
            name: 'operations',
            functions: [{
              name: 'process_coin',
              visibility: 'public',
              isEntry: true,
              line: 2,
              signature: 'public entry fun process_coin(coin: Coin<SUI>, ctx: &mut TxContext)',
              content: `
                let amount = coin::value(&coin);
                let doubled = amount * 2;
                assert!(doubled > 0, 1);
              `,
              parameters: [
                { name: 'coin', type: 'Coin<SUI>' },
                { name: 'ctx', type: '&mut TxContext' }
              ]
            }]
          }]
        }
      }];

      const graph = { nodes: [], links: [] };
      const result = await enhancedSecurityScanner.scan(ast, graph);

      const taintVuln = result.vulnerabilities.find(v => v.id === 'taint-violation');
      expect(taintVuln).toBeDefined();
      expect(taintVuln.severity).toBe('high');
    });
  });

  describe('Mock Dry-run Simulation', () => {
    test('should generate simulation results for public entry functions', async () => {
      const ast = [{
        name: 'simulate.move',
        content: '',
        ast: {
          modules: [{
            name: 'simulate',
            functions: [{
              name: 'test_function',
              visibility: 'public',
              isEntry: true,
              module: 'simulate',
              parameters: [
                { name: 'amount', type: 'u64' },
                { name: 'recipient', type: 'address' }
              ]
            }]
          }]
        }
      }];

      const graph = { nodes: [], links: [] };
      const result = await enhancedSecurityScanner.scan(ast, graph);

      expect(result.simulations).toHaveLength(1);
      expect(result.simulations[0].function).toBe('test_function');
      expect(result.simulations[0].status).toBe('success');
      expect(result.simulations[0].transaction).toBeDefined();
    });
  });

  describe('AST Pattern Rules', () => {
    test('should detect unrestricted public entry functions', async () => {
      const ast = [{
        name: 'unrestricted.move',
        content: '',
        ast: {
          modules: [{
            name: 'unrestricted',
            functions: [{
              name: 'dangerous_function',
              visibility: 'public',
              isEntry: true,
              line: 1,
              signature: 'public entry fun dangerous_function()',
              content: 'let x = 5;'
            }]
          }]
        }
      }];

      const graph = { nodes: [], links: [] };
      const result = await enhancedSecurityScanner.scan(ast, graph);

      const unrestrictedVuln = result.vulnerabilities.find(v => v.id === 'unrestricted-public-entry');
      expect(unrestrictedVuln).toBeDefined();
      expect(unrestrictedVuln.severity).toBe('high');
    });

    test('should detect mutable shared data access', async () => {
      const ast = [{
        name: 'shared.move',
        content: '',
        ast: {
          modules: [{
            name: 'shared',
            functions: [{
              name: 'mutate_shared',
              visibility: 'public',
              line: 1,
              signature: 'public fun mutate_shared()',
              content: 'let shared_ref = &mut global_state;'
            }]
          }]
        }
      }];

      const graph = { nodes: [], links: [] };
      const result = await enhancedSecurityScanner.scan(ast, graph);

      const sharedVuln = result.vulnerabilities.find(v => v.id === 'mutable-shared-data');
      expect(sharedVuln).toBeDefined();
      expect(sharedVuln.severity).toBe('high');
    });

    test('should detect authority overuse', async () => {
      const ast = [{
        name: 'authority.move',
        content: '',
        ast: {
          modules: [{
            name: 'authority',
            functions: [
              {
                name: 'overuse_authority',
                visibility: 'public',
                line: 1,
                signature: 'public fun overuse_authority()',
                content: 'AdminCap Cap Authority Cap'
              },
              {
                name: 'normal_function',
                visibility: 'public',
                line: 2,
                signature: 'public fun normal_function()',
                content: 'let x = 5;'
              }
            ]
          }]
        }
      }];

      const graph = { nodes: [], links: [] };
      const result = await enhancedSecurityScanner.scan(ast, graph);

      const authorityVuln = result.vulnerabilities.find(v => v.id === 'authority-overuse');
      expect(authorityVuln).toBeDefined();
      expect(authorityVuln.severity).toBe('medium');
    });
  });

  describe('Helper Methods', () => {
    test('should identify resource types correctly', () => {
      expect(enhancedSecurityScanner.isResourceType('Coin<SUI>')).toBe(true);
      expect(enhancedSecurityScanner.isResourceType('Pool<X, Y>')).toBe(true);
      expect(enhancedSecurityScanner.isResourceType('Treasury')).toBe(true);
      expect(enhancedSecurityScanner.isResourceType('Balance<T>')).toBe(true);
      expect(enhancedSecurityScanner.isResourceType('u64')).toBe(false);
      expect(enhancedSecurityScanner.isResourceType('address')).toBe(false);
    });

    test('should detect public entry functions correctly', () => {
      const publicEntry = { visibility: 'public', isEntry: true };
      const publicNotEntry = { visibility: 'public', isEntry: false };
      const privateEntry = { visibility: 'private', isEntry: true };

      expect(enhancedSecurityScanner.isPublicEntry(publicEntry)).toBe(true);
      expect(enhancedSecurityScanner.isPublicEntry(publicNotEntry)).toBe(false);
      expect(enhancedSecurityScanner.isPublicEntry(privateEntry)).toBe(false);
    });

    test('should detect access control in functions', () => {
      const withAssert = { content: 'assert!(owner == sender, 0);' };
      const withHasAccess = { content: 'has_access(cap);' };
      const withCapability = { content: 'capability.verify();' };
      const withoutControl = { content: 'let x = 5;' };

      expect(enhancedSecurityScanner.hasAccessControlInFunction(withAssert)).toBe(true);
      expect(enhancedSecurityScanner.hasAccessControlInFunction(withHasAccess)).toBe(true);
      expect(enhancedSecurityScanner.hasAccessControlInFunction(withCapability)).toBe(true);
      expect(enhancedSecurityScanner.hasAccessControlInFunction(withoutControl)).toBe(false);
    });
  });

  describe('Integration', () => {
    test('should return comprehensive analysis results', async () => {
      const ast = [{
        name: 'comprehensive.move',
        content: '',
        ast: {
          modules: [{
            name: 'comprehensive',
            functions: [{
              name: 'vulnerable_function',
              visibility: 'public',
              isEntry: true,
              line: 1,
              signature: 'public entry fun vulnerable_function()',
              content: 'transfer::public_transfer(coin, recipient);'
            }]
          }]
        }
      }];

      const graph = { 
        nodes: [
          { id: 'func_1', name: 'vulnerable_function', type: 'function' }
        ], 
        links: [] 
      };
      
      const result = await enhancedSecurityScanner.scan(ast, graph);

      expect(result).toHaveProperty('vulnerabilities');
      expect(result).toHaveProperty('simulations');
      expect(result).toHaveProperty('metadata');
      
      expect(Array.isArray(result.vulnerabilities)).toBe(true);
      expect(Array.isArray(result.simulations)).toBe(true);
      expect(typeof result.metadata).toBe('object');
      
      expect(result.metadata).toHaveProperty('staticAnalysisCount');
      expect(result.metadata).toHaveProperty('taintAnalysisCount');
      expect(result.metadata).toHaveProperty('simulationCount');
      expect(result.metadata).toHaveProperty('analysisTimestamp');
    });
  });
});

// Test data helpers
const createTestAST = (moduleName, functions) => [{
  name: `${moduleName}.move`,
  content: '',
  ast: {
    modules: [{
      name: moduleName,
      functions: functions
    }]
  }
}];

const createTestFunction = (name, overrides = {}) => ({
  name,
  visibility: 'public',
  isEntry: false,
  line: 1,
  signature: `public fun ${name}()`,
  content: '',
  parameters: [],
  ...overrides
});

module.exports = {
  createTestAST,
  createTestFunction
};