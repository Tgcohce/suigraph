/// Deliberately Vulnerable DeFi Contract for Security Testing
/// WARNING: This contract contains known vulnerabilities - DO NOT use in production
/// Designed for testing SuiGraph's MoveBit-enhanced security scanner

module vulnerable_defi::pool {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::balance::{Self, Balance};
    use sui::clock::{Self, Clock};
    use sui::event;
    use std::vector;

    /// Pool object containing funds and configuration
    struct Pool has key, store {
        id: UID,
        sui_balance: Balance<SUI>,
        total_shares: u64,
        last_update: u64,
        reward_rate: u64,
        admin: address,
        emergency_pause: bool,
        oracle_price: u64,
    }

    /// User stake tracking
    struct UserStake has key, store {
        id: UID,
        pool_id: address,
        shares: u64,
        reward_debt: u64,
        lock_until: u64,
    }

    /// Admin capability
    struct AdminCap has key, store {
        id: UID,
        pool_id: address,
    }

    /// Events
    struct DepositEvent has copy, drop {
        user: address,
        amount: u64,
        shares: u64,
    }

    struct WithdrawEvent has copy, drop {
        user: address,
        amount: u64,
        shares: u64,
    }

    struct RewardClaimEvent has copy, drop {
        user: address,
        reward: u64,
    }

    // ========== VULNERABILITY 1: Transaction-ordering dependence ==========
    /// Swap function vulnerable to MEV and sandwich attacks
    public fun swap_tokens(
        pool: &mut Pool,
        payment: Coin<SUI>,
        clock: &Clock,
        ctx: &mut TxContext
    ): Coin<SUI> {
        let amount_in = coin::value(&payment);
        let current_price = pool.oracle_price; // Price can be manipulated
        
        // VULNERABLE: No slippage protection, susceptible to front-running
        let amount_out = (amount_in * current_price) / 1_000_000;
        
        // Update pool balance (order matters for price calculation)
        coin::put(&mut pool.sui_balance, payment);
        
        // VULNERABLE: Price affected by transaction order
        pool.oracle_price = calculate_new_price(pool, amount_in);
        
        coin::take(&mut pool.sui_balance, amount_out, ctx)
    }

    // ========== VULNERABILITY 2: Timestamp dependence ==========
    /// Claim rewards based on time elapsed - vulnerable to timestamp manipulation
    public fun claim_rewards(
        pool: &mut Pool,
        stake: &mut UserStake,
        clock: &Clock,
        ctx: &mut TxContext
    ): Coin<SUI> {
        let current_time = clock::timestamp_ms(clock);
        
        // VULNERABLE: Critical logic depends on block timestamp
        let time_diff = current_time - pool.last_update;
        let rewards = (stake.shares * pool.reward_rate * time_diff) / 1_000_000;
        
        // VULNERABLE: Miners can manipulate timestamp within bounds
        pool.last_update = current_time;
        
        coin::take(&mut pool.sui_balance, rewards, ctx)
    }

    // ========== VULNERABILITY 3: Integer overflow/underflow ==========
    /// Deposit function with potential overflow
    public fun deposit(
        pool: &mut Pool,
        payment: Coin<SUI>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let amount = coin::value(&payment);
        let user = tx_context::sender(ctx);
        
        // VULNERABLE: No overflow checks on arithmetic operations
        let new_shares = amount * 1_000_000; // Could overflow
        pool.total_shares = pool.total_shares + new_shares; // Could overflow
        
        coin::put(&mut pool.sui_balance, payment);
        
        // Create or update user stake
        let stake = UserStake {
            id: object::new(ctx),
            pool_id: object::uid_to_address(&pool.id),
            shares: new_shares,
            reward_debt: 0,
            lock_until: clock::timestamp_ms(clock) + 86_400_000, // 24 hours
        };
        
        transfer::transfer(stake, user);
        
        event::emit(DepositEvent {
            user,
            amount,
            shares: new_shares,
        });
    }

    // ========== VULNERABILITY 4: Rounding errors ==========
    /// Fee calculation with precision loss
    public fun calculate_fee(amount: u64): u64 {
        let fee_rate = 25; // 0.25%
        // VULNERABLE: Division rounds down, can be exploited with small amounts
        (amount * fee_rate) / 10_000
    }

    // ========== VULNERABILITY 5: Unchecked external calls ==========
    /// Transfer without proper validation
    public fun external_transfer(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        // VULNERABLE: No validation of recipient or amount bounds
        let payment = coin::take(&mut pool.sui_balance, amount, ctx);
        transfer::public_transfer(payment, recipient);
    }

    // ========== VULNERABILITY 6: Denial-of-Service ==========
    /// Batch processing without gas limits
    public fun batch_reward_update(
        pool: &mut Pool,
        user_addresses: vector<address>,
        _ctx: &mut TxContext
    ) {
        let i = 0;
        let len = vector::length(&user_addresses);
        
        // VULNERABLE: Unbounded loop can cause gas exhaustion
        while (i < len) {
            let _addr = *vector::borrow(&user_addresses, i);
            // Simulate expensive computation per user
            let _computation = i * i * i * 1000 + 9999;
            i = i + 1;
        };
        
        pool.reward_rate = pool.reward_rate + 1;
    }

    // ========== VULNERABILITY 7: Access control issues ==========
    /// Weak admin check
    public fun emergency_withdraw(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        // VULNERABLE: Only checks pause state, not proper admin authorization
        assert!(pool.emergency_pause, 1);
        
        coin::take(&mut pool.sui_balance, amount, ctx)
    }

    // ========== VULNERABILITY 8: Centralization of power ==========
    /// Admin can drain all funds
    public fun admin_emergency_drain(
        pool: &mut Pool,
        _admin_cap: &AdminCap,
        ctx: &mut TxContext
    ): Coin<SUI> {
        // VULNERABLE: Admin has unlimited power to drain funds
        let total_balance = balance::value(&pool.sui_balance);
        coin::take(&mut pool.sui_balance, total_balance, ctx)
    }

    // ========== VULNERABILITY 9: Business logic flaw ==========
    /// Withdrawal without proper balance check
    public fun withdraw(
        pool: &mut Pool,
        stake: &mut UserStake,
        amount: u64,
        ctx: &mut TxContext
    ): Coin<SUI> {
        // VULNERABLE: Logic flaw - checks shares but withdraws different amount
        assert!(stake.shares >= amount, 2);
        
        // Flaw: reduces shares by amount but could withdraw more sui
        stake.shares = stake.shares - amount;
        
        // VULNERABLE: Could withdraw more than proportional share
        let withdrawal_amount = amount * 2; // Logic error
        
        coin::take(&mut pool.sui_balance, withdrawal_amount, ctx)
    }

    // ========== VULNERABILITY 10: Gas inefficiency ==========
    /// Inefficient computation
    public fun inefficient_calculation(): u64 {
        let result = 0;
        let i = 0;
        
        // VULNERABLE: Unnecessary computation waste
        while (i < 1000) {
            result = result + i * i * i + i * i + i + 1;
            i = i + 1;
        };
        
        result
    }

    // ========== VULNERABILITY 11: Arbitrary token minting equivalent ==========
    /// Admin can arbitrarily increase pool balance
    public fun mint_pool_balance(
        pool: &mut Pool,
        amount: u64,
        payment: Coin<SUI>
    ) {
        // VULNERABLE: No supply cap or proper authorization
        coin::put(&mut pool.sui_balance, payment);
        pool.total_shares = pool.total_shares + amount * 1_000_000;
    }

    // ========== VULNERABILITY 12: Oracle manipulation ==========
    /// Price update without validation
    public fun update_oracle_price(
        pool: &mut Pool,
        new_price: u64,
        _ctx: &mut TxContext
    ) {
        // VULNERABLE: No bounds checking or price source validation
        pool.oracle_price = new_price;
    }

    // ========== VULNERABILITY 13: Insufficient authorization ==========
    /// Critical operation without proper checks
    public fun toggle_emergency_pause(
        pool: &mut Pool,
        _ctx: &mut TxContext
    ) {
        // VULNERABLE: Missing authorization - anyone can pause
        pool.emergency_pause = !pool.emergency_pause;
    }

    // ========== UTILITY FUNCTIONS ==========
    
    /// Initialize pool (admin function)
    public fun create_pool(ctx: &mut TxContext): (Pool, AdminCap) {
        let pool_uid = object::new(ctx);
        let pool_id = object::uid_to_address(&pool_uid);
        
        let pool = Pool {
            id: pool_uid,
            sui_balance: balance::zero(),
            total_shares: 0,
            last_update: 0,
            reward_rate: 100, // 0.01%
            admin: tx_context::sender(ctx),
            emergency_pause: false,
            oracle_price: 1_000_000, // 1:1 initial price
        };
        
        let admin_cap = AdminCap {
            id: object::new(ctx),
            pool_id,
        };
        
        (pool, admin_cap)
    }

    /// Calculate new price based on trade (simplified AMM)
    fun calculate_new_price(pool: &Pool, trade_amount: u64): u64 {
        let current_balance = balance::value(&pool.sui_balance);
        // Simplified price impact calculation
        let impact = (trade_amount * 1000) / (current_balance + 1);
        pool.oracle_price + impact
    }

    /// Get pool info
    public fun get_pool_info(pool: &Pool): (u64, u64, u64, bool) {
        (
            balance::value(&pool.sui_balance),
            pool.total_shares,
            pool.oracle_price,
            pool.emergency_pause
        )
    }

    /// Get stake info
    public fun get_stake_info(stake: &UserStake): (u64, u64, u64) {
        (stake.shares, stake.reward_debt, stake.lock_until)
    }
}