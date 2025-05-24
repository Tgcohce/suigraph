#!/usr/bin/env node

/**
 * Test script for LLM-Enhanced Security Scanner
 * Demonstrates the combined static + LLM vulnerability detection
 */

const llmEnhancedSecurityScanner = require('./src/services/llmEnhancedSecurityScanner');

async function testLLMScanner() {
  console.log('🧪 Testing LLM-Enhanced Security Scanner\n');

  // Test vulnerable Move contract
  const testFiles = [{
    name: 'vulnerable_defi.move',
    content: `
module vulnerable_defi::pool {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::balance::{Self, Balance};

    struct Pool<phantom X, phantom Y> has key {
        id: UID,
        reserve_x: Balance<X>,
        reserve_y: Balance<Y>,
        fee_rate: u64
    }

    struct AdminCap has key {
        id: UID
    }

    // VULNERABLE: No access control on withdraw function
    public entry fun emergency_withdraw(
        pool: &mut Pool<SUI, SUI>, 
        amount: u64, 
        ctx: &mut TxContext
    ) {
        let withdrawn = balance::split(&mut pool.reserve_x, amount);
        let coin = coin::from_balance(withdrawn, ctx);
        transfer::public_transfer(coin, tx_context::sender(ctx));
    }

    // VULNERABLE: Swap without slippage protection
    public fun swap<X, Y>(
        pool: &mut Pool<X, Y>,
        coin_in: Coin<X>,
        ctx: &mut TxContext
    ): Coin<Y> {
        let amount_in = coin::value(&coin_in);
        // Simple AMM formula without slippage checks
        let reserve_x = balance::value(&pool.reserve_x);
        let reserve_y = balance::value(&pool.reserve_y);
        
        // VULNERABLE: No overflow protection
        let amount_out = (amount_in * reserve_y) / (reserve_x + amount_in);
        
        balance::join(&mut pool.reserve_x, coin::into_balance(coin_in));
        let out_balance = balance::split(&mut pool.reserve_y, amount_out);
        coin::from_balance(out_balance, ctx)
    }

    // VULNERABLE: Price oracle without TWAP
    public fun get_current_price<X, Y>(pool: &Pool<X, Y>): u64 {
        let reserve_x = balance::value(&pool.reserve_x);
        let reserve_y = balance::value(&pool.reserve_y);
        reserve_y / reserve_x  // Direct spot price
    }

    // VULNERABLE: Admin function without capability check
    public entry fun set_fee_rate(
        pool: &mut Pool<SUI, SUI>,
        new_fee_rate: u64,
        _ctx: &mut TxContext
    ) {
        pool.fee_rate = new_fee_rate;
    }

    // VULNERABLE: Mint function with potential overflow
    public fun mint_lp_tokens(
        amount_x: u64,
        amount_y: u64
    ): u64 {
        amount_x * amount_y  // No overflow check
    }
}
    `,
    parseError: null
  }];

  try {
    console.log('🔍 Running LLM-Enhanced Security Analysis...\n');
    
    const vulnerabilities = await llmEnhancedSecurityScanner.scanForVulnerabilities(testFiles);
    
    console.log(`\n📊 Analysis Results:`);
    console.log(`Total Vulnerabilities Found: ${vulnerabilities.length}\n`);
    
    // Group by source
    const bySource = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.source || 'unknown'] = (acc[vuln.source || 'unknown'] || 0) + 1;
      return acc;
    }, {});
    
    console.log('📈 Breakdown by Source:');
    Object.entries(bySource).forEach(([source, count]) => {
      const icon = source === 'llm' ? '🤖' : source === 'static' ? '📊' : '🔍';
      console.log(`   ${icon} ${source.toUpperCase()}: ${count} vulnerabilities`);
    });
    
    // Group by severity
    const bySeverity = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {});
    
    console.log('\n⚠️ Breakdown by Severity:');
    Object.entries(bySeverity).forEach(([severity, count]) => {
      const icon = severity === 'critical' ? '🚨' : severity === 'high' ? '❗' : severity === 'medium' ? '⚠️' : '💡';
      console.log(`   ${icon} ${severity.toUpperCase()}: ${count} vulnerabilities`);
    });
    
    console.log('\n🔍 Detailed Vulnerability Report:');
    console.log('=' .repeat(80));
    
    vulnerabilities.forEach((vuln, index) => {
      const sourceIcon = vuln.source === 'llm' ? '🤖' : vuln.source === 'static' ? '📊' : '🔍';
      const severityIcon = vuln.severity === 'critical' ? '🚨' : vuln.severity === 'high' ? '❗' : vuln.severity === 'medium' ? '⚠️' : '💡';
      
      console.log(`\n${index + 1}. ${sourceIcon} ${vuln.name}`);
      console.log(`   ${severityIcon} Severity: ${vuln.severity.toUpperCase()}`);
      console.log(`   📁 File: ${vuln.file}:${vuln.line}`);
      console.log(`   📝 Description: ${vuln.description}`);
      console.log(`   💡 Recommendation: ${vuln.recommendation}`);
      console.log(`   🎯 Confidence: ${vuln.confidence}`);
    });
    
    console.log('\n' + '=' .repeat(80));
    console.log('✅ LLM-Enhanced Security Scanner Test Complete!');
    console.log(`\n📋 Summary:`);
    console.log(`   • Static Analysis: Detected ${bySource.static || 0} pattern-based vulnerabilities`);
    console.log(`   • LLM Analysis: Detected ${bySource.llm || 0} context-aware vulnerabilities`);
    console.log(`   • Total Coverage: ${vulnerabilities.length} security issues identified`);
    console.log(`   • Most Critical: ${bySeverity.critical || 0} critical, ${bySeverity.high || 0} high severity`);
    
  } catch (error) {
    console.error('❌ Test failed:', error);
    
    if (error.message.includes('OpenAI')) {
      console.log('\n💡 Note: To enable LLM analysis, set OPENAI_API_KEY in your .env file');
      console.log('The scanner will fallback to static analysis only without API key.');
    }
  }
}

// Check if OpenAI API key is available
function checkApiKey() {
  if (!process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY === 'your_openai_api_key_here') {
    console.log('⚠️ Warning: OPENAI_API_KEY not configured');
    console.log('Set your OpenAI API key in the .env file to enable LLM analysis');
    console.log('The test will run with static analysis only.\n');
    return false;
  }
  console.log('✅ OpenAI API key configured\n');
  return true;
}

// Run test if called directly
if (require.main === module) {
  checkApiKey();
  testLLMScanner()
    .then(() => process.exit(0))
    .catch(error => {
      console.error('💥 Test execution failed:', error);
      process.exit(1);
    });
}

module.exports = { testLLMScanner };