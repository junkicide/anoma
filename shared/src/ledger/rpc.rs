//! Client RPC queries

// TODO: remove Context and args from functions' parameters
// TODO: Factor out the code's side-effects to allow to query storage data with
// any client that impl tendermint_rpc::client::Client and return the typed
// values (e.g. Result<pos::Bonds, QueryError>      -> Replace all mentions to
// HttpClient with impl tendermint_rpc::client::Client   
// TODO: move error and stdout prints to app folder (where these functions are actually called) 
// TODO: testing?
// TODO: return Results instead of printing
// TODO: fix all TODOs and FIXMEs left around also in other files
// TODO: improve docs
// TODO: move all structs to types dir? Implements some traits on them?
// TODO: check if turbofish operators sill work
// TODO: generic letter for client should be C for all methods in this module
// TODO: what to do with unwraps and expect on abci_query? If you leave them document the panics
// TODO: check what actually needs to be public

use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{self, Write};

use borsh::BorshDeserialize;
use itertools::Itertools;
#[cfg(not(feature = "ABCI"))]
use tendermint::abci::Code;
#[cfg(not(feature = "ABCI"))]
use tendermint_config::net::Address as TendermintAddress;
#[cfg(feature = "ABCI")]
use tendermint_config_abci::net::Address as TendermintAddress;
#[cfg(not(feature = "ABCI"))]
use tendermint_rpc::error::Error as TError;
#[cfg(not(feature = "ABCI"))]
use tendermint_rpc::query::Query;
#[cfg(not(feature = "ABCI"))]
use tendermint_rpc::{Client, HttpClient};
#[cfg(not(feature = "ABCI"))]
use tendermint_rpc::{Order, SubscriptionClient, WebSocketClient};
use tendermint_rpc_abci::endpoint::abci_query::AbciQuery;
#[cfg(feature = "ABCI")]
use tendermint_rpc_abci::error::Error as TError;
#[cfg(feature = "ABCI")]
use tendermint_rpc_abci::query::Query;
#[cfg(feature = "ABCI")]
use tendermint_rpc_abci::{Client, HttpClient};
#[cfg(feature = "ABCI")]
use tendermint_rpc_abci::{Order, SubscriptionClient, WebSocketClient};
#[cfg(feature = "ABCI")]
use tendermint_stable::abci::Code;
use thiserror::Error;

use crate::ledger::pos::types::{
    Epoch as PosEpoch, VotingPower, WeightedValidator,
};
use crate::ledger::pos::{
    self, is_validator_slashes_key, Bonds, Slash, Unbonds,
};
use crate::types::address::Address;
use crate::types::key::ed25519;
use crate::types::rpc::{Path, PrefixValue, TxEventQuery, TxResponse};
use crate::types::token::Amount;
use crate::types::storage::{Epoch, Key};
use crate::types::{address, storage, token};


#[derive(Error)]
pub enum QueryError {
    #[error("Error decoding the value: {0}")]
    Decoding(#[from] TError), //FIXME: TError or Error?
    #[error("Error in the query {0} (error code {1})")]
    Format(String, u32),
    #[error("Unable to find a block applying the given transaction")]
    BlockNotFound,
    #[error("Unable to find the event corresponding to the specified transaction")]
    EventNotFound,
    #[error("Unexpected storage key {0}")]
    NoBondKey(Key)
}

pub enum TxQueryResult {
    Accepted(TxResponse),
    Applied(TxResponse),
}

pub struct BondQueryResult {
    bonds: Amount,
    active: Amount,
    unbonds: Amount,
    withdrawable: Amount
}

/// Represents the result of a balance query. First Address is the Owner one,
/// nested Address is the token one.
pub struct BalanceQueryResult(HashMap<Address, HashMap<Address, Amount>>); //FIXME: Or HashMap<(Adress, Address), Amount> ?

impl BalanceQueryResult {
    fn new() -> Self {
        BalanceQueryResult(HashMap::new())
    }

    /// Update the given keys if exist, otherwise insert them
    fn insert(&mut self, owner: Address, token: Address, balance: Amount) {
        match self.0.get_mut(&owner) { //FIXME: deref?
            // FIXME: improve this block
            Some(token_map) => {
                token_map.insert(token, balance);
            }
            None => {
                let token_map = HashMap::new();
                token_map.insert(token, balance);
                self.insert(owner, token_map);
            }
        }
    }

    pub fn get_balance(
        &self,
        owner: &Address,
        token: &Address,
    ) -> Option<Amount> {
        match self.0.get(owner) { //FIXME: deref?
            Some(token) => Some(self.0.get(token).clone()),
            None => None,
        }
    }
}


/// Query the epoch of the last committed block.
pub async fn query_epoch<T>(client: T) -> Result<Epoch, QueryError>
where T: Client {
    let path = Path::Epoch;
    let data = vec![];
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .unwrap();

    match response.code {
        Code::Ok => Ok(Epoch::try_from_slice(&response.value[..])?),
        Code::Err(err) => Err(QueryError::Format(response.info, err)),
    }
    // match response.code { //FIXME: remove if it works
    //     Code::Ok => match Epoch::try_from_slice(&response.value[..]) {
    //         Ok(epoch) => {
    //             Ok(epoch)
    //         },
    //         Err(err) => {
    //             Err(QueryError::Decoding(err))
    //         }
    //     },
    //     Code::Err(err) => Err(QueryError::Format(response.info, err))
    // }
}

/// Query token balance(s)
///
/// Arguments owner and token are Options, the function will produce a result
/// based on the effective values of these arguments.
///
/// Cases (token, owner):
///     Some, Some: returns the balance of token for owner
///     None, Some: returns the balances of all the tokens owned by owner
///     Some, None: returns the balances of token for all the users owning token
///     None, None: returns the balances of all the tokens for all the users
/// 
/// FIXME: this forces the caller to actually perform two calls: one to this
///     function and one on the struct returned to get the actual Amount
pub async fn query_balance<T>(
    client: T,
    token: Option<&Address>,
    owner: Option<&Address>,
) -> Result<BalanceQueryResult, QueryError>
where T: Client {
    let tokens = address::tokens();
    let result = BalanceQueryResult::new();
    match (token, owner) {
        (Some(token), Some(owner)) => {
            let key = token::balance_key(token, owner);
            let currency_code = tokens
                .get(token)
                .map(|c| Cow::Borrowed(*c))
                .unwrap_or_else(|| Cow::Owned(token.to_string()));

            if let Some(balance) =
                query_storage_value::<Amount>(client, key).await?
            {
                result.insert(owner.to_owned(), token.to_owned(), balance);
            }
        }
        (None, Some(owner)) => {
            for (token, currency_code) in tokens {
                let key = token::balance_key(&token, owner);
                if let Some(balance) =
                    query_storage_value::<Amount>(client.clone(), key)
                        .await?
                {
                    result.insert(owner.to_owned(), token, balance);
                }
            }
        }
        (Some(token), None) => {
            let key = token::balance_prefix(token);
            if let Some(balances) =
                query_storage_prefix::<Amount>(client, key).await?
            {
                let currency_code = tokens
                    .get(token)
                    .map(|c| Cow::Borrowed(*c))
                    .unwrap_or_else(|| Cow::Owned(token.to_string()));
                for (key, balance) in balances {
                    let owner = token::is_any_token_balance_key(&key).unwrap();
                    result.insert(owner.to_owned(), token.to_owned(), balance);
                }
            }
        }
        (None, None) => {
            for (token, currency_code) in tokens {
                let key = token::balance_prefix(&token);
                if let Some(balances) =
                    query_storage_prefix::<Amount>(client.clone(), key)
                        .await?
                {
                    for (key, balance) in balances {
                        let owner =
                            token::is_any_token_balance_key(&key).unwrap();
                        result.insert(owner.to_owned(), token, balance);
                    }
                }
            }
        }
    }
    Ok(result)
}

/// Query PoS bond(s)
pub async fn query_bonds<C>(client: C, owner: Option<&Address>, validator: Option<&Address>) -> Result<BondQueryResult, QueryError>
where C: Client {
    // FIXME: refactor, function too long (export to different supfunctions and/or try to share code between match cases)
    // FIXME: should return Bonds?
    let epoch = query_epoch(client).await?;
    let mut result: BondQueryResult; // TODO: initialize to 0 all fields
    match (owner, validator) {
        (Some(owner), Some(validator)) => {
            // Find owner's delegations to the given validator
            let bond_id = pos::BondId { source: owner, validator };
            let bond_key = pos::bond_key(&bond_id);
            let bonds =
                query_storage_value::<pos::Bonds>(client.clone(), bond_key)
                    .await?;
            // Find owner's unbonded delegations from the given
            // validator
            let unbond_key = pos::unbond_key(&bond_id);
            let unbonds =
                query_storage_value::<pos::Unbonds>(client.clone(), unbond_key)
                    .await?;
            // Find validator's slashes, if any
            let slashes_key = pos::validator_slashes_key(&bond_id.validator);
            let slashes =
                query_storage_value::<pos::Slashes>(client, slashes_key)
                    .await?
                    .unwrap_or_default();

            if let Some(bonds) = &bonds {
                let (t, a) = process_bonds_query(
                    bonds, &slashes, epoch, None, None, None,
                );
                result.bonds = t;
                result.active = a;
            }

            if let Some(unbonds) = &unbonds {
                let (t, w) = process_unbonds_query(
                    unbonds, &slashes, epoch, None, None, None,
                );
                result.unbonds = t;
                result.withdrawable = w;
            }
        }
        (None, Some(validator)) => {
            // Find validator's self-bonds
            let bond_id = pos::BondId {
                source: validator.clone(),
                validator,
            };
            let bond_key = pos::bond_key(&bond_id);
            let bonds =
                query_storage_value::<pos::Bonds>(client.clone(), bond_key)
                    .await?;
            // Find validator's unbonded self-bonds
            let unbond_key = pos::unbond_key(&bond_id);
            let unbonds =
                query_storage_value::<pos::Unbonds>(client.clone(), unbond_key)
                    .await?;
            // Find validator's slashes, if any
            let slashes_key = pos::validator_slashes_key(&bond_id.validator);
            let slashes =
                query_storage_value::<pos::Slashes>(client, slashes_key)
                    .await?
                    .unwrap_or_default();

            if let Some(bonds) = &bonds {
                let (t, a) = process_bonds_query(
                    bonds, &slashes, epoch, None, None, None,
                );
                result.bonds = t;
                result.active = a;
            }

            if let Some(unbonds) = &unbonds {
                let (t, w) = process_unbonds_query(
                    unbonds, &slashes, epoch, None, None, None,
                );
                result.unbonds = t;
                result.withdrawable = w;
            }
        }
        (Some(owner), None) => {
            // Find owner's bonds to any validator
            let bonds_prefix = pos::bonds_for_source_prefix(&owner);
            let bonds = query_storage_prefix::<pos::Bonds>(
                client.clone(),
                bonds_prefix,
            )
            .await?;
            // Find owner's unbonds to any validator
            let unbonds_prefix = pos::unbonds_for_source_prefix(&owner);
            let unbonds = query_storage_prefix::<pos::Unbonds>(
                client.clone(),
                unbonds_prefix,
            )
            .await?;

            if let Some(bonds) = bonds {
                for (key, bonds) in bonds {
                    match pos::is_bond_key(&key) {
                        Some(pos::BondId { source, validator }) => {
                            // Find validator's slashes, if any
                            let slashes_key =
                                pos::validator_slashes_key(&validator);
                            let slashes = query_storage_value::<pos::Slashes>(
                                client.clone(),
                                slashes_key,
                            )
                            .await?
                            .unwrap_or_default();

                            let (tot, tot_active) = process_bonds_query(
                                &bonds,
                                &slashes,
                                epoch,
                                Some(&source),
                                Some(result.bonds),
                                Some(result.active),
                            );
                            result.bonds = tot;
                            result.active = tot_active;
                        }
                        None => {
                            return QueryError::NoBondKey(key);
                        }
                    }
                }
            }

            if let Some(unbonds) = unbonds {
                for (key, unbonds) in unbonds {
                    match pos::is_unbond_key(&key) {
                        Some(pos::BondId { source, validator }) => {
                            // Find validator's slashes, if any
                            let slashes_key =
                                pos::validator_slashes_key(&validator);
                            let slashes = query_storage_value::<pos::Slashes>(
                                client.clone(),
                                slashes_key,
                            )
                            .await?
                            .unwrap_or_default();

                            let (tot, tot_withdrawable) = process_unbonds_query(
                                &unbonds,
                                &slashes,
                                epoch,
                                Some(&source),
                                Some(result.unbonds),
                                Some(result.withdrawable),
                            );
                            result.unbonds = tot;
                            result.withdrawable = tot_withdrawable;
                        }
                        None => {
                            return QueryError::NoBondKey(key);
                        }
                    }
                }
            }
        }
        (None, None) => {
            // Find all the bonds
            let bonds_prefix = pos::bonds_prefix();
            let bonds = query_storage_prefix::<pos::Bonds>(
                client.clone(),
                bonds_prefix,
            )
            .await?;
            // Find all the unbonds
            let unbonds_prefix = pos::unbonds_prefix();
            let unbonds = query_storage_prefix::<pos::Unbonds>(
                client.clone(),
                unbonds_prefix,
            )
            .await?;

            if let Some(bonds) = bonds {
                for (key, bonds) in bonds {
                    match pos::is_bond_key(&key) {
                        Some(pos::BondId { source, validator }) => {
                            // Find validator's slashes, if any
                            let slashes_key =
                                pos::validator_slashes_key(&validator);
                            let slashes = query_storage_value::<pos::Slashes>(
                                client.clone(),
                                slashes_key,
                            )
                            .await?
                            .unwrap_or_default();

                            let (tot, tot_active) = process_bonds_query(
                                &bonds,
                                &slashes,
                                epoch,
                                Some(&source),
                                Some(result.bonds),
                                Some(result.active),
                            );
                            result.bonds = tot;
                            result.active = tot_active;
                        }
                        None => {
                            return QueryError::NoBondKey(key);
                        }
                    }
                }
            }

            if let Some(unbonds) = unbonds {
                for (key, unbonds) in unbonds {
                    match pos::is_unbond_key(&key) {
                        Some(pos::BondId { source, validator }) => {
                            // Find validator's slashes, if any
                            let slashes_key =
                                pos::validator_slashes_key(&validator);
                            let slashes = query_storage_value::<pos::Slashes>(
                                client.clone(),
                                slashes_key,
                            )
                            .await?
                            .unwrap_or_default();

                            let (tot, tot_withdrawable) = process_unbonds_query(
                                &unbonds,
                                &slashes,
                                epoch,
                                Some(&source),
                                Some(result.unbonds),
                                Some(result.withdrawable),
                            );
                            result.unbonds = tot;
                            result.withdrawable = tot_withdrawable;
                        }
                        None => {
                            return QueryError::NoBondKey(key);
                        }
                    }
                }
            }
        }
    }
    Ok(result)
}

/// Query PoS voting power
pub async fn query_voting_power(ctx: Context, args: args::QueryVotingPower) { //TODO: restart from here
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => query_epoch(args.query.clone()).await,
    };
    let client = HttpClient::new(args.query.ledger_address).unwrap();

    // Find the validator set
    let validator_set_key = pos::validator_set_key();
    let validator_sets = query_storage_value::<pos::ValidatorSets>(
        client.clone(),
        validator_set_key,
    )
    .await?
    .expect("Validator set should always be set");
    let validator_set = validator_sets
        .get(epoch)
        .expect("Validator set should be always set in the current epoch");
    match args.validator {
        Some(validator) => {
            let validator = ctx.get(&validator);
            // Find voting power for the given validator
            let voting_power_key = pos::validator_voting_power_key(&validator);
            let voting_powers =
                query_storage_value::<pos::ValidatorVotingPowers>(
                    client.clone(),
                    voting_power_key,
                )
                .await?;
            match voting_powers.and_then(|data| data.get(epoch)) {
                Some(voting_power_delta) => {
                    let voting_power: VotingPower =
                        voting_power_delta.try_into().expect(
                            "The sum voting power deltas shouldn't be negative",
                        );
                    let weighted = WeightedValidator {
                        address: validator.clone(),
                        voting_power,
                    };
                    let is_active = validator_set.active.contains(&weighted);
                    if !is_active {
                        debug_assert!(
                            validator_set.inactive.contains(&weighted)
                        );
                    }
                    println!(
                        "Validator {} is {}, voting power: {}",
                        validator.encode(),
                        if is_active { "active" } else { "inactive" },
                        voting_power
                    )
                }
                None => {
                    println!("No voting power found for {}", validator.encode())
                }
            }
        }
        None => {
            // Iterate all validators
            let stdout = io::stdout();
            let mut w = stdout.lock();

            writeln!(w, "Active validators:").unwrap();
            for active in &validator_set.active {
                writeln!(
                    w,
                    "  {}: {}",
                    active.address.encode(),
                    active.voting_power
                )
                .unwrap();
            }
            if !validator_set.inactive.is_empty() {
                writeln!(w, "Inactive validators:").unwrap();
                for inactive in &validator_set.inactive {
                    writeln!(
                        w,
                        "  {}: {}",
                        inactive.address.encode(),
                        inactive.voting_power
                    )
                    .unwrap();
                }
            }
        }
    }
    let total_voting_power_key = pos::total_voting_power_key();
    let total_voting_powers = query_storage_value::<pos::TotalVotingPowers>(
        client,
        total_voting_power_key,
    )
    .await?
    .expect("Total voting power should always be set");
    let total_voting_power = total_voting_powers
        .get(epoch)
        .expect("Total voting power should be always set in the current epoch");
    println!("Total voting power: {}", total_voting_power);
}

/// Query PoS slashes
pub async fn query_slashes(ctx: Context, args: args::QuerySlashes) { //FIXME: must return result. Caller of this method should print error and safe_exit on Err
    let client = HttpClient::new(args.query.ledger_address).unwrap();
    match args.validator {
        Some(validator) => {
            let validator = ctx.get(&validator);
            // Find slashes for the given validator
            let slashes_key = pos::validator_slashes_key(&validator);
            let slashes = query_storage_value::<pos::Slashes>(
                client.clone(),
                slashes_key,
            )
            .await?;
            match slashes {
                Some(slashes) => {
                    let stdout = io::stdout();
                    let mut w = stdout.lock();
                    for slash in slashes {
                        writeln!(
                            w,
                            "Slash epoch {}, rate {}, type {}",
                            slash.epoch, slash.rate, slash.r#type
                        )
                        .unwrap();
                    }
                }
                None => {
                    println!("No slashes found for {}", validator.encode())
                }
            }
        }
        None => {
            // Iterate slashes for all validators
            let slashes_prefix = pos::slashes_prefix();
            let slashes = query_storage_prefix::<pos::Slashes>(
                client.clone(),
                slashes_prefix,
            )
            .await?;

            match slashes {
                Some(slashes) => {
                    let stdout = io::stdout();
                    let mut w = stdout.lock();
                    for (slashes_key, slashes) in slashes {
                        if let Some(validator) =
                            is_validator_slashes_key(&slashes_key)
                        {
                            for slash in slashes {
                                writeln!(
                                    w,
                                    "Slash epoch {}, block height {}, rate \
                                     {}, type {}, validator {}",
                                    slash.epoch,
                                    slash.block_height,
                                    slash.rate,
                                    slash.r#type,
                                    validator,
                                )
                                .unwrap();
                            }
                        } else {
                            eprintln!("Unexpected slashes key {}", slashes_key);
                        }
                    }
                }
                None => {
                    println!("No slashes found")
                }
            }
        }
    }
}

/// Dry run a transaction
pub async fn dry_run_tx<T>(client: T, tx_bytes: Vec<u8>) -> AbciQuery
where T: Client {
    let path = Path::DryRunTx;
    client
        .abci_query(Some(path.into()), tx_bytes, None, false)
        .await
        .unwrap() //FIXME: unwrap?
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key<T>( //FIXME: fix calls to this method to manage di Error
    client: T,
    address: &Address,
) -> Result<Option<ed25519::PublicKey>, QueryError>
where T: Client {
    let key = ed25519::pk_key(address);
    query_storage_value(client, key).await?
}

/// Check if the given address is a known validator.
pub async fn is_validator<T>( //FIXME: fix calls to this method to manage di Error
    client: T,
    address: &Address,
) -> Result<bool, QueryError>
where T: Client {
    // Check if there's any validator state
    let key = pos::validator_state_key(address);
    // We do not need to decode it
    let state: Option<pos::ValidatorStates> =
        query_storage_value(client, key).await?;
    // If there is, then the address is a validator
    Ok(state.is_some())
}

/// Check if the address exists on chain. Established address exists if it has a
/// stored validity predicate. Implicit and internal addresses always return
/// true.
pub async fn known_address<C>( //FIXME: fix calls to this method to manage di Error
    client: C,
    address: &Address,
) -> Result<bool, QueryError>
where C: Client {
    match address {
        Address::Established(_) => {
            // Established account exists if it has a VP
            let key = Key::validity_predicate(address);
            query_has_storage_key(client, key).await?
        }
        Address::Implicit(_) | Address::Internal(_) => Ok(true),
    }
}

/// Accumulate slashes starting from `epoch_start` until (optionally)
/// `withdraw_epoch` and apply them to the token amount `delta`.
fn apply_slashes(
    slashes: &[Slash],
    mut delta: Amount,
    epoch_start: PosEpoch,
    withdraw_epoch: Option<PosEpoch>,
) -> Amount {
    for slash in slashes {
        if slash.epoch >= epoch_start
            && slash.epoch < withdraw_epoch.unwrap_or_else(|| u64::MAX.into())
        {
            let raw_delta: u64 = delta.into();
            let current_slashed = Amount::from(slash.rate * raw_delta);
            delta -= current_slashed;
        }
    }

    delta
}

/// Process the result of a bonds query to determine total bonds
/// and total active bonds. This includes taking into account
/// an aggregation of slashes since the start of the given epoch.
fn process_bonds_query(
    bonds: &Bonds,
    slashes: &[Slash],
    epoch: Epoch,
    source: Option<&Address>,
    total: Option<Amount>,
    total_active: Option<Amount>,
) -> (Amount, Amount) {
    let mut total_active = total_active.unwrap_or_else(|| 0.into());
    let mut current_total: Amount = 0.into();

    for bond in bonds.iter() {
        for (epoch_start, &(mut delta)) in bond.deltas.iter().sorted() {
            delta = apply_slashes(slashes, delta, *epoch_start, None);
            current_total += delta;

            if epoch >= epoch_start {
                total_active += delta;
            }
        }
    }
    let total = total.unwrap_or_else(|| 0.into()) + current_total;

    (total, total_active)
}

/// Process the result of an unbonds query to determine total bonds
/// and total withdrawable bonds. This includes taking into account
/// an aggregation of slashes since the start of the given epoch up
/// until the withdrawal epoch.
fn process_unbonds_query(
    unbonds: &Unbonds,
    slashes: &[Slash],
    epoch: Epoch,
    source: Option<&Address>,
    total: Option<Amount>,
    total_withdrawable: Option<Amount>,
) -> (Amount, Amount) {
    let mut withdrawable = total_withdrawable.unwrap_or_else(|| 0.into());
    let mut current_total: Amount = 0.into();

    for deltas in unbonds.iter() {
        for ((epoch_start, epoch_end), &(mut delta)) in
            deltas.deltas.iter().sorted()
        {
            let withdraw_epoch = *epoch_end + 1_u64;
            delta = apply_slashes(
                slashes,
                delta,
                *epoch_start,
                Some(withdraw_epoch),
            );
            current_total += delta;
            if epoch > epoch_end {
                withdrawable += delta;
            }
        }
    }
    let total = total.unwrap_or_else(|| 0.into()) + current_total;

    (total, withdrawable)
}

/// Query a storage value and decode it with [`BorshDeserialize`].
pub async fn query_storage_value<C, T>(
    client: C,
    key: Key,
) -> Result<Option<T>, QueryError>
where
    C: Client,
    T: BorshDeserialize, 
{
    let path = Path::Value(key);
    let data = vec![];
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .unwrap();
    match response.code {
        Code::Ok => match T::try_from_slice(&response.value[..]) {
            Ok(value) => Ok(Some(value)),
            Err(err) => Err(QueryError::Decoding(err))
        },
        Code::Err(err) if err == 1 => Ok(None),
        Code::Err(err) => Err(QueryError::Format(response.info, err)) 
    }
}

/// Query a range of storage values with a matching prefix and decode them with
/// [`BorshDeserialize`]. Returns an iterator of the storage keys paired with
/// their associated values.
pub async fn query_storage_prefix<C, K, T>(
    client: C,
    key: Key,
) -> Result<Option<K>, QueryError>
where
    C: Client,
    K: Iterator<Item = (Key, T)>,
    T: BorshDeserialize,
{
    let path = Path::Prefix(key);
    let data = vec![];
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .unwrap();
    match response.code {
        Code::Ok => {
            match Vec::<PrefixValue>::try_from_slice(&response.value[..]) {
                Ok(values) => {
                    let decode = |PrefixValue { key, value }: PrefixValue| {
                        match T::try_from_slice(&value[..]) {
                            Err(_) => None,
                            Ok(value) => Some((key, value)),
                        }
                    };
                    Some(values.into_iter().filter_map(decode))
                }
                Err(err) => Err(QueryError::Decoding(err)),
            }
        }
        Code::Err(err) if err == 1 => Ok(None),
        Code::Err(err) =>  Err(QueryError::Format(response.info, err))
    }
}

/// Query to check if the given storage key exists.

pub async fn query_has_storage_key<C>(
    client: C,
    key: Key,
) -> Result<bool, QueryError> 
where C: Client{
    let path = Path::HasKey(key);
    let data = vec![];
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .unwrap();
    match response.code {
        Code::Ok => match bool::try_from_slice(&response.value[..]) {
            Ok(value) => Ok(value),
            Err(err) => Err(QueryError::Decoding(err)),
        },
        Code::Err(err) => Err(QueryError::Format(response.info, err))
    }
}

/// Lookup the full response accompanying the specified transaction event

pub async fn query_tx_respons<C>(
    client: C,
    tx_query: TxEventQuery,
) -> Result<TxResponse, QueryError>
where C: Client {
    // Find all blocks that apply a transaction with the specified hash
    let blocks = client
        .block_search(Query::from(tx_query.clone()), 1, 255, Order::Ascending)
        .await
        .expect("Unable to query for transaction with given hash")
        .blocks;
    // Get the block results corresponding to a block to which
    // the specified transaction belongs
    let block = blocks
        .get(0)
        .ok_or_else(|| {
            QueryError::BlockNotFound
        })?
        .block;
    let response_block_results = client
        .block_results(block.header.height)
        .await
        .expect("Unable to retrieve block containing transaction");
    // Search for the event where the specified transaction is
    // applied to the blockchain
    let query_event_opt =
        response_block_results.end_block_events.and_then(|events| {
            (&events)
                .iter()
                .find(|event| {
                    event.type_str == tx_query.event_type()
                        && (&event.attributes).iter().any(|tag| {
                            tag.key.as_ref() == "hash"
                                && tag.value.as_ref() == tx_query.tx_hash()
                        })
                })
                .cloned()
        });
    let query_event = query_event_opt.ok_or_else(|| {
        QueryError::EventNotFound
    })?;
    // Reformat the event attributes so as to ease value extraction
    let event_map: HashMap<&str, &str> = (&query_event.attributes)
        .iter()
        .map(|tag| (tag.key.as_ref(), tag.value.as_ref()))
        .collect();
    // Summarize the transaction results that we were searching for
    let result = TxResponse {
        info: event_map["info"].to_string(),
        height: event_map["height"].to_string(),
        hash: event_map["hash"].to_string(),
        code: event_map["code"].to_string(),
        gas_used: event_map["gas_used"].to_string(),
        initialized_accounts: serde_json::from_str(
            event_map["initialized_accounts"],
        )
        .unwrap_or_default(),
    };

    Ok(result)
}

/// Lookup the results of applying the specified transaction to the
/// blockchain.

pub async fn query_tx_result<C>(client: C, tx_hash: T) -> Result<TxQueryResult, QueryError>
where C: Client, T: Into<String> {
    // First try looking up application event pertaining to given hash.
    let tx_response = query_tx_response(
        client.clone(),
        TxEventQuery::Applied(tx_hash.into().clone()),
    )
    .await;

    match tx_response {
        Ok(tx_response) => Ok(TxQueryResult::Applied(tx_response)),
        Err(_) => {
            // If this fails then instead look for an acceptance event.
            let tx_response = query_tx_response(
                client,
                TxEventQuery::Accepted(tx_hash.into()),
            )
            .await?;
            Ok(TxQueryResult::Accepted(tx_response))
        }
    }
}
