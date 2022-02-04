use std::borrow::Cow;
use std::convert::TryFrom;

use anoma::ledger::pos::{BondId, Bonds, Unbonds};
use anoma::proto::Tx;
use anoma::types::address::Address;
use anoma::types::key::*;
use anoma::types::transaction::{
    pos, Fee, InitAccount, InitValidator, UpdateVp, WrapperTx,
};
use anoma::types::{address, token};
use anoma::{ledger, vm};
use async_std::io::{self, WriteExt};
use borsh::BorshSerialize;
use itertools::Either::*;
use jsonpath_lib as jsonpath;
use serde::Serialize;
#[cfg(not(feature = "ABCI"))]
use tendermint_config::net::Address as TendermintAddress;
#[cfg(feature = "ABCI")]
use tendermint_config_abci::net::Address as TendermintAddress;
#[cfg(not(feature = "ABCI"))]
use tendermint_rpc::endpoint::broadcast::tx_sync::Response;
#[cfg(not(feature = "ABCI"))]
use tendermint_rpc::query::{EventType, Query};
#[cfg(not(feature = "ABCI"))]
use tendermint_rpc::{Client, HttpClient};
#[cfg(feature = "ABCI")]
use tendermint_rpc_abci::endpoint::broadcast::tx_sync::Response;
#[cfg(feature = "ABCI")]
use tendermint_rpc_abci::query::{EventType, Query};
#[cfg(feature = "ABCI")]
use tendermint_rpc_abci::{Client, HttpClient};

use super::{rpc, signing};
use crate::cli::context::WalletAddress;
use crate::cli::{args, safe_exit, Context};
#[cfg(not(feature = "ABCI"))]
use crate::client::tendermint_websocket_client::hash_tx;
use crate::client::tendermint_websocket_client::{
    Error, TendermintWebsocketClient, WebSocketAddress,
};
#[cfg(not(feature = "ABCI"))]
use crate::node::ledger::events::{Attributes, EventType as TmEventType};
use crate::node::ledger::tendermint_node;

const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
const TX_INIT_VALIDATOR_WASM: &str = "tx_init_validator.wasm";
const TX_UPDATE_VP_WASM: &str = "tx_update_vp.wasm";
const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";
const VP_USER_WASM: &str = "vp_user.wasm";
const TX_BOND_WASM: &str = "tx_bond.wasm";
const TX_UNBOND_WASM: &str = "tx_unbond.wasm";
const TX_WITHDRAW_WASM: &str = "tx_withdraw.wasm";

pub async fn submit_custom(ctx: Context, args: args::TxCustom) {
    let tx_code = ctx.read_wasm(args.code_path);
    let data = args.data_path.map(|data_path| {
        std::fs::read(data_path).expect("Expected a file at given data path")
    });
    let tx = Tx::new(tx_code, data);
    let (ctx, tx, keypair) = sign_tx(ctx, tx, &args.tx, None).await;
    let (ctx, initialized_accounts) =
        process_tx(ctx, &args.tx, tx, &keypair).await;
    save_initialized_accounts(ctx, &args.tx, initialized_accounts).await;
}

pub async fn submit_update_vp(ctx: Context, args: args::TxUpdateVp) {
    let addr = ctx.get(&args.addr);

    // Check that the address is established and exists on chain
    match &addr {
        Address::Established(_) => {
            let exists =
                rpc::known_address(&addr, args.tx.ledger_address.clone()).await;
            if !exists {
                eprintln!("The address {} doesn't exist on chain.", addr);
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        Address::Implicit(_) => {
            eprintln!(
                "A validity predicate of an implicit address cannot be \
                 directly updated. You can use an established address for \
                 this purpose."
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
        Address::Internal(_) => {
            eprintln!(
                "A validity predicate of an internal address cannot be \
                 directly updated."
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }

    let vp_code = ctx.read_wasm(args.vp_code_path);
    // Validate the VP code
    if let Err(err) = vm::validate_untrusted_wasm(&vp_code) {
        eprintln!("Validity predicate code validation failed with {}", err);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let tx_code = ctx.read_wasm(TX_UPDATE_VP_WASM);

    let data = UpdateVp { addr, vp_code };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let (ctx, tx, keypair) = sign_tx(ctx, tx, &args.tx, Some(&args.addr)).await;
    process_tx(ctx, &args.tx, tx, &keypair).await;
}

pub async fn submit_init_account(mut ctx: Context, args: args::TxInitAccount) {
    let public_key = ctx.get_cached(&args.public_key);
    let vp_code = args
        .vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));
    // Validate the VP code
    if let Err(err) = vm::validate_untrusted_wasm(&vp_code) {
        eprintln!("Validity predicate code validation failed with {}", err);
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let tx_code = ctx.read_wasm(TX_INIT_ACCOUNT_WASM);
    let data = InitAccount {
        public_key,
        vp_code,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(&args.source)).await;
    let (ctx, initialized_accounts) =
        process_tx(ctx, &args.tx, tx, &keypair).await;
    save_initialized_accounts(ctx, &args.tx, initialized_accounts).await;
}

pub async fn submit_init_validator(
    mut ctx: Context,
    args::TxInitValidator {
        tx: tx_args,
        source,
        account_key,
        consensus_key,
        rewards_account_key,
        validator_vp_code_path,
        rewards_vp_code_path,
        unsafe_dont_encrypt,
    }: args::TxInitValidator,
) {
    let alias = tx_args
        .initialized_account_alias
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "validator".to_string());

    let validator_key_alias = format!("{}-key", alias);
    let consensus_key_alias = format!("{}-consensus-key", alias);
    let rewards_key_alias = format!("{}-rewards-key", alias);
    let account_key = ctx.get_opt_cached(&account_key).unwrap_or_else(|| {
        println!("Generating validator account key...");
        ctx.wallet
            .gen_key(Some(validator_key_alias.clone()), unsafe_dont_encrypt)
            .1
            .public_part()
            .clone()
    });

    let consensus_key =
        ctx.get_opt_cached(&consensus_key).unwrap_or_else(|| {
            println!("Generating consensus key...");
            ctx.wallet
                .gen_key(Some(consensus_key_alias.clone()), unsafe_dont_encrypt)
                .1
        });

    let rewards_account_key =
        ctx.get_opt_cached(&rewards_account_key).unwrap_or_else(|| {
            println!("Generating staking reward account key...");
            ctx.wallet
                .gen_key(Some(rewards_key_alias.clone()), unsafe_dont_encrypt)
                .1
                .public_part()
                .clone()
        });

    ctx.wallet.save().unwrap_or_else(|err| eprintln!("{}", err));

    let validator_vp_code = validator_vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));
    // Validate the validator VP code
    if let Err(err) = vm::validate_untrusted_wasm(&validator_vp_code) {
        eprintln!(
            "Validator validity predicate code validation failed with {}",
            err
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }
    let rewards_vp_code = rewards_vp_code_path
        .map(|path| ctx.read_wasm(path))
        .unwrap_or_else(|| ctx.read_wasm(VP_USER_WASM));
    // Validate the rewards VP code
    if let Err(err) = vm::validate_untrusted_wasm(&rewards_vp_code) {
        eprintln!(
            "Staking reward account validity predicate code validation failed \
             with {}",
            err
        );
        if !tx_args.force {
            safe_exit(1)
        }
    }
    let tx_code = ctx.read_wasm(TX_INIT_VALIDATOR_WASM);

    let data = InitValidator {
        account_key,
        consensus_key: consensus_key.public_part().clone(),
        rewards_account_key,
        validator_vp_code,
        rewards_vp_code,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");
    let tx = Tx::new(tx_code, Some(data));
    let (ctx, tx, keypair) = sign_tx(ctx, tx, &tx_args, Some(&source)).await;

    let (mut ctx, initialized_accounts) =
        process_tx(ctx, &tx_args, tx, &keypair).await;
    if !tx_args.dry_run {
        let (validator_address_alias, validator_address, rewards_address_alias) =
            match &initialized_accounts[..] {
                // There should be 2 accounts, one for the validator itself, one
                // for its staking reward address.
                [account_1, account_2] => {
                    // We need to find out which address is which
                    let (validator_address, rewards_address) =
                        if rpc::is_validator(account_1, tx_args.ledger_address)
                            .await
                        {
                            (account_1, account_2)
                        } else {
                            (account_2, account_1)
                        };

                    let validator_address_alias = match tx_args
                        .initialized_account_alias
                    {
                        Some(alias) => alias,
                        None => {
                            print!(
                                "Choose an alias for the validator address: "
                            );
                            io::stdout().flush().await.unwrap();
                            let mut alias = String::new();
                            io::stdin().read_line(&mut alias).await.unwrap();
                            alias.trim().to_owned()
                        }
                    };
                    let validator_address_alias =
                        if validator_address_alias.is_empty() {
                            println!(
                                "Empty alias given, using {} as the alias.",
                                validator_address.encode()
                            );
                            validator_address.encode()
                        } else {
                            validator_address_alias
                        };
                    if let Some(new_alias) = ctx.wallet.add_address(
                        validator_address_alias.clone(),
                        validator_address.clone(),
                    ) {
                        println!(
                            "Added alias {} for address {}.",
                            new_alias,
                            validator_address.encode()
                        );
                    }
                    let rewards_address_alias =
                        format!("{}-rewards", validator_address_alias);
                    if let Some(new_alias) = ctx.wallet.add_address(
                        rewards_address_alias.clone(),
                        rewards_address.clone(),
                    ) {
                        println!(
                            "Added alias {} for address {}.",
                            new_alias,
                            rewards_address.encode()
                        );
                    }
                    (
                        validator_address_alias,
                        validator_address.clone(),
                        rewards_address_alias,
                    )
                }
                _ => {
                    eprintln!("Expected two accounts to be created");
                    safe_exit(1)
                }
            };

        ctx.wallet.save().unwrap_or_else(|err| eprintln!("{}", err));

        let tendermint_home = ctx.config.ledger.tendermint_dir();
        tendermint_node::write_validator_key(
            &tendermint_home,
            &validator_address,
            &consensus_key,
        );
        tendermint_node::write_validator_state(tendermint_home);

        println!();
        println!(
            "The validator's addresses and keys were stored in the wallet:"
        );
        println!("  Validator address \"{}\"", validator_address_alias);
        println!("  Staking reward address \"{}\"", rewards_address_alias);
        println!("  Validator account key \"{}\"", validator_key_alias);
        println!("  Consensus key \"{}\"", consensus_key_alias);
        println!("  Staking reward key \"{}\"", rewards_key_alias);
        println!(
            "The ledger node has been setup to use this validator's address \
             and consensus key."
        );
    } else {
        println!("Transaction dry run. No addresses have been saved.")
    }
}

pub async fn submit_transfer(ctx: Context, args: args::TxTransfer) {
    let source = ctx.get(&args.source);
    // Check that the source address exists on chain
    let source_exists =
        rpc::known_address(&source, args.tx.ledger_address.clone()).await;
    if !source_exists {
        eprintln!("The source address {} doesn't exist on chain.", source);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    let target = ctx.get(&args.target);
    // Check that the target address exists on chain
    let target_exists =
        rpc::known_address(&target, args.tx.ledger_address.clone()).await;
    if !target_exists {
        eprintln!("The target address {} doesn't exist on chain.", target);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    let token = ctx.get(&args.token);
    // Check that the token address exists on chain
    let token_exists =
        rpc::known_address(&token, args.tx.ledger_address.clone()).await;
    if !token_exists {
        eprintln!("The token address {} doesn't exist on chain.", token);
        if !args.tx.force {
            safe_exit(1)
        }
    }
    // Check source balance
    let balance_key = token::balance_key(&token, &source);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    match rpc::query_storage_value::<token::Amount>(client, balance_key).await {
        Some(balance) => {
            if balance < args.amount {
                eprintln!(
                    "The balance of the source {} of token {} is lower than \
                     the amount to be transferred. Amount to transfer is {} \
                     and the balance is {}.",
                    source, token, args.amount, balance
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!(
                "No balance found for the source {} of token {}",
                source, token
            );
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }
    let tx_code = ctx.read_wasm(TX_TRANSFER_WASM);
    let transfer = token::Transfer {
        source,
        target,
        token,
        amount: args.amount,
    };
    tracing::debug!("Transfer data {:?}", transfer);
    let data = transfer
        .try_to_vec()
        .expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(&args.source)).await;
    process_tx(ctx, &args.tx, tx, &keypair).await;
}

pub async fn submit_bond(ctx: Context, args: args::Bond) {
    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }
    let source = ctx.get_opt(&args.source);
    // Check that the source address exists on chain
    if let Some(source) = &source {
        let source_exists =
            rpc::known_address(source, args.tx.ledger_address.clone()).await;
        if !source_exists {
            eprintln!("The source address {} doesn't exist on chain.", source);
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }
    // Check bond's source (source for delegation or validator for self-bonds)
    // balance
    let bond_source = source.as_ref().unwrap_or(&validator);
    let balance_key = token::balance_key(&address::xan(), bond_source);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    match rpc::query_storage_value::<token::Amount>(client, balance_key).await {
        Some(balance) => {
            if balance < args.amount {
                eprintln!(
                    "The balance of the source {} is lower than the amount to \
                     be transferred. Amount to transfer is {} and the balance \
                     is {}.",
                    bond_source, args.amount, balance
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!("No balance found for the source {}", bond_source);
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }
    let tx_code = ctx.read_wasm(TX_BOND_WASM);
    let bond = pos::Bond {
        validator,
        amount: args.amount,
        source,
    };
    let data = bond.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.as_ref().unwrap_or(&args.validator);
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(default_signer)).await;
    process_tx(ctx, &args.tx, tx, &keypair).await;
}

pub async fn submit_unbond(ctx: Context, args: args::Unbond) {
    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_UNBOND_WASM);

    // Check the source's current bond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::bond_key(&bond_id);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    let bonds =
        rpc::query_storage_value::<Bonds>(client.clone(), bond_key).await;
    match bonds {
        Some(bonds) => {
            let mut bond_amount: token::Amount = 0.into();
            for bond in bonds.iter() {
                for delta in bond.deltas.values() {
                    bond_amount += *delta;
                }
            }
            if args.amount > bond_amount {
                eprintln!(
                    "The total bonds of the source {} is lower than the \
                     amount to be unbonded. Amount to unbond is {} and the \
                     total bonds is {}.",
                    bond_source, args.amount, bond_amount
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!("No bonds found");
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }

    let data = pos::Unbond {
        validator,
        amount: args.amount,
        source,
    };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.as_ref().unwrap_or(&args.validator);
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(default_signer)).await;
    process_tx(ctx, &args.tx, tx, &keypair).await;
}

pub async fn submit_withdraw(ctx: Context, args: args::Withdraw) {
    let epoch = rpc::query_epoch(args::Query {
        ledger_address: args.tx.ledger_address.clone(),
    })
    .await;

    let validator = ctx.get(&args.validator);
    // Check that the validator address exists on chain
    let is_validator =
        rpc::is_validator(&validator, args.tx.ledger_address.clone()).await;
    if !is_validator {
        eprintln!(
            "The address {} doesn't belong to any known validator account.",
            validator
        );
        if !args.tx.force {
            safe_exit(1)
        }
    }

    let source = ctx.get_opt(&args.source);
    let tx_code = ctx.read_wasm(TX_WITHDRAW_WASM);

    // Check the source's current unbond amount
    let bond_source = source.clone().unwrap_or_else(|| validator.clone());
    let bond_id = BondId {
        source: bond_source.clone(),
        validator: validator.clone(),
    };
    let bond_key = ledger::pos::unbond_key(&bond_id);
    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
    let unbonds =
        rpc::query_storage_value::<Unbonds>(client.clone(), bond_key).await;
    match unbonds {
        Some(unbonds) => {
            let mut unbonded_amount: token::Amount = 0.into();
            if let Some(unbond) = unbonds.get(epoch) {
                for delta in unbond.deltas.values() {
                    unbonded_amount += *delta;
                }
            }
            if unbonded_amount == 0.into() {
                eprintln!(
                    "There are no unbonded bonds ready to withdraw in the \
                     current epoch {}.",
                    epoch
                );
                if !args.tx.force {
                    safe_exit(1)
                }
            }
        }
        None => {
            eprintln!("No unbonded bonds found");
            if !args.tx.force {
                safe_exit(1)
            }
        }
    }

    let data = pos::Withdraw { validator, source };
    let data = data.try_to_vec().expect("Encoding tx data shouldn't fail");

    let tx = Tx::new(tx_code, Some(data));
    let default_signer = args.source.as_ref().unwrap_or(&args.validator);
    let (ctx, tx, keypair) =
        sign_tx(ctx, tx, &args.tx, Some(default_signer)).await;
    process_tx(ctx, &args.tx, tx, &keypair).await;
}

/// Sign a transaction with a given signing key or public key of a given signer.
/// If no explicit signer given, use the `default`. If no `default` is given,
/// returns unsigned transaction.
async fn sign_tx(
    mut ctx: Context,
    tx: Tx,
    args: &args::Tx,
    default: Option<&WalletAddress>,
) -> (Context, Tx, std::rc::Rc<ed25519c::Keypair>) {
    let (tx, keypair) = if let Some(signing_key) = &args.signing_key {
        let signing_key = ctx.get_cached(signing_key);
        (tx.sign::<ed25519c::SigScheme>(&signing_key), signing_key)
    } else if let Some(signer) = args.signer.as_ref().or(default) {
        let signer = ctx.get(signer);
        let signing_key = signing::find_keypair(
            &mut ctx.wallet,
            &signer,
            args.ledger_address.clone(),
        )
        .await;
        (tx.sign::<ed25519c::SigScheme>(&signing_key), signing_key)
    } else {
        panic!(
            "All transactions must be signed; please either specify the key \
             or the address from which to look up the signing key."
        );
    };

    (ctx, tx, keypair)
}

/// Submit transaction and wait for result. Returns a list of addresses
/// initialized in the transaction if any. In dry run, this is always empty.
async fn process_tx(
    ctx: Context,
    args: &args::Tx,
    tx: Tx,
    keypair: &ed25519c::Keypair,
) -> (Context, Vec<Address>) {
    // NOTE: use this to print the request JSON body:

    // let request =
    // tendermint_rpc::endpoint::broadcast::tx_commit::Request::new(
    //     tx_bytes.clone().into(),
    // );
    // use tendermint_rpc::Request;
    // let request_body = request.into_json();
    // println!("HTTP request body: {}", request_body);

    if args.dry_run {
        rpc::dry_run_tx(&args.ledger_address, tx.to_bytes()).await;
        (ctx, vec![])
    } else {
        let epoch = rpc::query_epoch(args::Query {
            ledger_address: args.ledger_address.clone(),
        })
        .await;
        let tx = WrapperTx::new(
            Fee {
                amount: args.fee_amount,
                token: ctx.get(&args.fee_token),
            },
            keypair,
            epoch,
            args.gas_limit.clone(),
            tx,
        );
        // Either broadcast or submit transaction and collect result into
        // sum type
        let result = if args.broadcast_only {
            Left(broadcast_tx(args.ledger_address.clone(), tx, keypair).await)
        } else {
            Right(submit_tx(args.ledger_address.clone(), tx, keypair).await)
        };
        // Return result based on executed operation, otherwise deal with
        // the encountered errors uniformly
        match result {
            Right(Ok(result)) => (ctx, result.initialized_accounts),
            Left(Ok(_)) => (ctx, Vec::default()),
            Right(Err(err)) | Left(Err(err)) => {
                eprintln!(
                    "Encountered error while broadcasting transaction: {}",
                    err
                );
                safe_exit(1)
            }
        }
    }
}

/// Save accounts initialized from a tx into the wallet, if any.
async fn save_initialized_accounts(
    mut ctx: Context,
    args: &args::Tx,
    initialized_accounts: Vec<Address>,
) {
    let len = initialized_accounts.len();
    if len != 0 {
        // Store newly initialized account addresses in the wallet
        println!(
            "The transaction initialized {} new account{}",
            len,
            if len == 1 { "" } else { "s" }
        );
        // Store newly initialized account addresses in the wallet
        let wallet = &mut ctx.wallet;
        for (ix, address) in initialized_accounts.iter().enumerate() {
            let encoded = address.encode();
            let alias: Cow<str> = match &args.initialized_account_alias {
                Some(initialized_account_alias) => {
                    if len == 1 {
                        // If there's only one account, use the
                        // alias as is
                        initialized_account_alias.into()
                    } else {
                        // If there're multiple accounts, use
                        // the alias as prefix, followed by
                        // index number
                        format!("{}{}", initialized_account_alias, ix).into()
                    }
                }
                None => {
                    print!("Choose an alias for {}: ", encoded);
                    io::stdout().flush().await.unwrap();
                    let mut alias = String::new();
                    io::stdin().read_line(&mut alias).await.unwrap();
                    alias.trim().to_owned().into()
                }
            };
            let alias = alias.into_owned();
            let added = wallet.add_address(alias.clone(), address.clone());
            match added {
                Some(new_alias) if new_alias != encoded => {
                    println!(
                        "Added alias {} for address {}.",
                        new_alias, encoded
                    );
                }
                _ => println!("No alias added for address {}.", encoded),
            };
        }
        if !args.dry_run {
            wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
        } else {
            println!("Transaction dry run. No addresses have been saved.")
        }
    }
}

/// Extract the wrapper transaction's hash and, if in ABCI++ mode, the inner
/// transaction's hash. Useful for determining when parts of the given
/// tranasaction make it on-chain.
pub fn tx_hashes(tx: &WrapperTx) -> (String, String) {
    let tx_hash = tx.tx_hash.to_string();
    #[cfg(not(feature = "ABCI"))]
    return (hash_tx(&tx.try_to_vec().unwrap()).to_string(), tx_hash);
    // In the case of ABCI, proceed as if inner and wrapper transaction
    // are synonymous
    #[cfg(feature = "ABCI")]
    return (tx_hash.clone(), tx_hash);
}

/// Broadcast a transaction to be included in the blockchain and checks that
/// the tx has been successfully included into the mempool of a validator
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn broadcast_tx(
    address: TendermintAddress,
    tx: WrapperTx,
    keypair: &ed25519c::Keypair,
) -> Result<Response, Error> {
    // These can later be used to determine when parts of the tx make it
    // on-chain
    let (wrapper_tx_hash, _decrypted_tx_hash) = tx_hashes(&tx);

    let mut wrapper_tx_subscription = TendermintWebsocketClient::open(
        WebSocketAddress::try_from(address.clone())?,
        None,
    )?;

    // we sign all txs
    let tx = tx
        .sign(keypair)
        .expect("Signing of the wrapper transaction should not fail");
    let tx_bytes = tx.to_bytes();

    let response = wrapper_tx_subscription
        .broadcast_tx_sync(tx_bytes.into())
        .await
        .map_err(|err| Error::Response(format!("{:?}", err)))?;

    wrapper_tx_subscription.close();

    if response.code == 0.into() {
        println!("Transaction added to mempool: {:?}", response);
        // Print the transaction identifiers to enable the extraction of
        // acceptance/application results later
        #[cfg(not(feature = "ABCI"))]
        {
            println!("Wrapper transaction hash: {:?}", wrapper_tx_hash);
            println!("Inner transaction hash: {:?}", _decrypted_tx_hash);
        }
        #[cfg(feature = "ABCI")]
        println!("Transaction hash: {:?}", wrapper_tx_hash);
        Ok(response)
    } else {
        Err(Error::Response(response.log.to_string()))
    }
}

/// Submits a transaction to the blockchain.
///
/// Checks that
/// 1. The tx has been successfully included into the mempool of a validator
/// 2. The tx with encrypted payload has been included on the blockchain
/// 3. The decrypted payload of the tx has been included on the blockchain.
///
/// In the case of errors in any of those stages, an error message is returned
pub async fn submit_tx(
    address: TendermintAddress,
    tx: WrapperTx,
    keypair: &ed25519c::Keypair,
) -> Result<TxResponse, Error> {
    let mut wrapper_tx_subscription = TendermintWebsocketClient::open(
        WebSocketAddress::try_from(address.clone())?,
        None,
    )?;

    // We use these to determine when parts of the tx make it on-chain
    let (wrapper_tx_hash, _decrypted_tx_hash) = tx_hashes(&tx);
    // It is better to subscribe to the transaction before it is broadcast
    //
    // Note that the `applied.hash` key comes from a custom event
    // created by the shell
    #[cfg(not(feature = "ABCI"))]
    let query_key = "accepted.hash";
    #[cfg(feature = "ABCI")]
    let query_key = "applied.hash";
    let query = Query::from(EventType::NewBlock)
        .and_eq(query_key, wrapper_tx_hash.as_str());
    wrapper_tx_subscription.subscribe(query)?;

    // If we are using ABCI++, we also subscribe to the event emitted
    // when the encrypted payload makes its way onto the blockchain
    #[cfg(not(feature = "ABCI"))]
    let mut decrypted_tx_subscription = {
        let mut decrypted_tx_subscription = TendermintWebsocketClient::open(
            WebSocketAddress::try_from(address.clone())?,
            None,
        )?;
        let query = Query::from(EventType::NewBlock)
            .and_eq("applied.hash", _decrypted_tx_hash.as_str());
        decrypted_tx_subscription.subscribe(query)?;
        decrypted_tx_subscription
    };
    // Broadcast the supplied transaction
    broadcast_tx(address, tx, keypair).await?;

    #[cfg(feature = "ABCI")]
    let parsed = {
        let parsed = TxResponse::find_tx(
            wrapper_tx_subscription.receive_response()?,
            wrapper_tx_hash,
        );
        println!(
            "Transaction applied with result: {}",
            serde_json::to_string_pretty(&parsed).unwrap()
        );
        Ok(parsed)
    };
    #[cfg(not(feature = "ABCI"))]
    let parsed = {
        let parsed = parse(
            wrapper_tx_subscription.receive_response()?,
            TmEventType::Accepted,
            &wrapper_tx_hash.to_string(),
        );
        println!(
            "Transaction accepted with result: {}",
            serde_json::to_string_pretty(&parsed).unwrap()
        );
        // The transaction is now on chain. We wait for it to be decrypted
        // and applied
        if parsed.code == 0.to_string() {
            let parsed = parse(
                decrypted_tx_subscription.receive_response()?,
                TmEventType::Applied,
                _decrypted_tx_hash.as_str(),
            );
            println!(
                "Transaction applied with result: {}",
                serde_json::to_string_pretty(&parsed).unwrap()
            );
            Ok(parsed)
        } else {
            Ok(parsed)
        }
    };
    wrapper_tx_subscription.unsubscribe()?;
    wrapper_tx_subscription.close();
    #[cfg(not(feature = "ABCI"))]
    {
        decrypted_tx_subscription.unsubscribe()?;
        decrypted_tx_subscription.close();
    }

    parsed
}

#[derive(Debug, Serialize)]
pub struct TxResponse {
    pub info: String,
    pub height: String,
    pub hash: String,
    pub code: String,
    pub gas_used: String,
    pub initialized_accounts: Vec<Address>,
}

/// Parse the JSON payload received from a subscription
///
/// Searches for custom events emitted from the ledger and converts
/// them back to thin wrapper around a hashmap for further parsing.
#[cfg(not(feature = "ABCI"))]
fn parse(
    json: serde_json::Value,
    event_type: TmEventType,
    tx_hash: &str,
) -> TxResponse {
    let mut selector = jsonpath::selector(&json);
    let mut event =
        selector(&format!("$.events.[?(@.type=='{}')]", event_type))
            .unwrap()
            .iter()
            .filter_map(|event| {
                let attrs = Attributes::from(*event);
                match attrs.get("hash") {
                    Some(hash) if hash == tx_hash => Some(attrs),
                    _ => None,
                }
            })
            .collect::<Vec<Attributes>>()
            .remove(0);

    let info = event.take("info").unwrap();
    let height = event.take("height").unwrap();
    let hash = event.take("hash").unwrap();
    let code = event.take("code").unwrap();
    let gas_used = event.take("gas_used").unwrap_or_else(|| String::from("0"));
    let initialized_accounts = event.take("initialized_accounts");
    let initialized_accounts = match initialized_accounts {
        Some(values) => serde_json::from_str(&values).unwrap(),
        _ => vec![],
    };
    TxResponse {
        info,
        height,
        hash,
        code,
        gas_used,
        initialized_accounts,
    }
}

impl TxResponse {
    pub fn find_tx(json: serde_json::Value, tx_hash: String) -> Self {
        let tx_hash_json = serde_json::Value::String(tx_hash.clone());
        let mut selector = jsonpath::selector(&json);
        let mut index = 0;
        #[cfg(feature = "ABCI")]
        let evt_key = "applied";
        #[cfg(not(feature = "ABCI"))]
        let evt_key = "accepted";
        // Find the tx with a matching hash
        let hash = loop {
            if let Ok(hash) =
                selector(&format!("$.events.['{}.hash'][{}]", evt_key, index))
            {
                let hash = hash[0].clone();
                if hash == tx_hash_json {
                    break hash;
                } else {
                    index += 1;
                }
            } else {
                eprintln!(
                    "Couldn't find tx with hash {} in the event string {}",
                    tx_hash, json
                );
                safe_exit(1)
            }
        };
        let info =
            selector(&format!("$.events.['{}.info'][{}]", evt_key, index))
                .unwrap();
        let height =
            selector(&format!("$.events.['{}.height'][{}]", evt_key, index))
                .unwrap();
        let code =
            selector(&format!("$.events.['{}.code'][{}]", evt_key, index))
                .unwrap();
        let gas_used =
            selector(&format!("$.events.['{}.gas_used'][{}]", evt_key, index))
                .unwrap();
        let initialized_accounts = selector(&format!(
            "$.events.['{}.initialized_accounts'][{}]",
            evt_key, index
        ));
        let initialized_accounts = match initialized_accounts {
            Ok(values) if !values.is_empty() => {
                // In a response, the initialized accounts are encoded as e.g.:
                // ```
                // "applied.initialized_accounts": Array([
                //   String(
                //     "[\"atest1...\"]",
                //   ),
                // ]),
                // ...
                // So we need to decode the inner string first ...
                let raw: String =
                    serde_json::from_value(values[0].clone()).unwrap();
                // ... and then decode the vec from the array inside the string
                serde_json::from_str(&raw).unwrap()
            }
            _ => vec![],
        };
        TxResponse {
            info: serde_json::from_value(info[0].clone()).unwrap(),
            height: serde_json::from_value(height[0].clone()).unwrap(),
            hash: serde_json::from_value(hash).unwrap(),
            code: serde_json::from_value(code[0].clone()).unwrap(),
            gas_used: serde_json::from_value(gas_used[0].clone()).unwrap(),
            initialized_accounts,
        }
    }
}
