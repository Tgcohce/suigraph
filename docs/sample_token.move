module sample_token::token {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use std::option;

    /// Error codes
    const EInsufficientBalance: u64 = 0;
    const ENotOwner: u64 = 1;
    const EInvalidAmount: u64 = 2;

    /// The main token struct
    struct Token has key, store {
        id: UID,
        value: u64,
        metadata: TokenMetadata,
    }

    /// Token metadata
    struct TokenMetadata has store {
        name: vector<u8>,
        symbol: vector<u8>,
        decimals: u8,
    }

    /// Capability for minting tokens
    struct MintCap has key {
        id: UID,
        max_supply: u64,
        current_supply: u64,
    }

    /// Treasury for holding tokens
    struct Treasury has key {
        id: UID,
        balance: Balance<Token>,
    }

    /// Initialize the token module
    fun init(ctx: &mut TxContext) {
        let mint_cap = MintCap {
            id: object::new(ctx),
            max_supply: 1000000000, // 1 billion tokens
            current_supply: 0,
        };
        
        let treasury = Treasury {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        
        transfer::transfer(mint_cap, tx_context::sender(ctx));
        transfer::share_object(treasury);
    }

    /// Public entry function to mint tokens (potential vulnerability)
    public entry fun mint(
        cap: &mut MintCap,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        assert!(amount > 0, EInvalidAmount);
        assert!(cap.current_supply + amount <= cap.max_supply, EInsufficientBalance);
        
        let token = Token {
            id: object::new(ctx),
            value: amount,
            metadata: TokenMetadata {
                name: b"Sample Token",
                symbol: b"SAMPLE",
                decimals: 9,
            },
        };
        
        cap.current_supply = cap.current_supply + amount;
        transfer::transfer(token, recipient);
    }

    /// Transfer tokens without proper validation (vulnerability)
    public entry fun transfer_token(
        token: Token,
        recipient: address,
    ) {
        transfer::transfer(token, recipient);
    }

    /// Burn tokens and return value
    public fun burn(token: Token): u64 {
        let Token { id, value, metadata: _ } = token;
        object::delete(id);
        value
    }

    /// Get token value (public accessor)
    public fun value(token: &Token): u64 {
        token.value
    }

    /// Split token into two tokens
    public fun split(token: &mut Token, amount: u64, ctx: &mut TxContext): Token {
        assert!(token.value >= amount, EInsufficientBalance);
        token.value = token.value - amount;
        
        Token {
            id: object::new(ctx),
            value: amount,
            metadata: token.metadata,
        }
    }

    /// Join two tokens
    public fun join(token1: &mut Token, token2: Token) {
        let Token { id, value, metadata: _ } = token2;
        object::delete(id);
        token1.value = token1.value + value;
    }

    /// Admin function without proper capability check (vulnerability)
    public entry fun admin_mint(
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let token = Token {
            id: object::new(ctx),
            value: amount,
            metadata: TokenMetadata {
                name: b"Admin Token",
                symbol: b"ADMIN",
                decimals: 9,
            },
        };
        transfer::transfer(token, recipient);
    }

    /// Function with mutable shared object access
    public entry fun deposit_to_treasury(
        treasury: &mut Treasury,
        token: Token,
    ) {
        let value = burn(token);
        balance::join(&mut treasury.balance, balance::create_for_testing(value));
    }

    /// Withdraw from treasury without proper checks (vulnerability)
    public entry fun withdraw_from_treasury(
        treasury: &mut Treasury,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let withdrawn = balance::split(&mut treasury.balance, amount);
        let token = Token {
            id: object::new(ctx),
            value: balance::value(&withdrawn),
            metadata: TokenMetadata {
                name: b"Treasury Token",
                symbol: b"TREAS",
                decimals: 9,
            },
        };
        balance::destroy_for_testing(withdrawn);
        transfer::transfer(token, recipient);
    }
}