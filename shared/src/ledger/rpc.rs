//! Client RPC queries
 
// TODO: testing?
// TODO: fix all TODOs and FIXMEs left around also in other files
// TODO: improve docs
// TODO: move public structs to types dir and private ones here. Implements some traits on the public ones?
// TODO: remove unused imports
// TODO: format code

use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryInto;
use std::marker::Sync;
use std::clone::Clone;

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
    self, Bonds, Slash, Unbonds,
};
use crate::types::address::Address;
use crate::types::key::ed25519;
use crate::types::rpc::{Path, PrefixValue, TxResponse};
use crate::types::token::Amount;
use crate::types::storage::{Epoch, Key};
use crate::types::{address, storage, token};


// FIXME: add causing Errors to this ones? Or implement from and remove map_err
#[derive(Debug, Error)]
pub enum QueryError {
    #[error("Abci query failed")]
    ABCIQueryError,
    #[error("Error decoding the value: {0}")]
    Decoding(#[from] std::io::Error),
    #[error("Error in the query {0} (error code {1})")]
    Format(String, u32),
    #[error("Unable to find a block applying the given transaction")]
    BlockNotFound,
    #[error("Unable to find the event corresponding to the specified transaction")]
    EventNotFound,
    #[error("Unexpected storage key {0}")]
    NoBondKey(Key),
    #[error("Validator set should be always set in the current epoch")]
    UnsetValidator, //FIXME: move into a VotingPOwerError?
    #[error("The sum voting power deltas shouldn't be negative")]
    NegativeVotingPowerDeltas, //FIXME: move into a VotingPOwerError?
    #[error("Total voting power should always be set")]
    UnsetVotingPower, //FIXME: move into a VotingPOwerError?
    #[error("Unable to query for transaction with given hash")]
    TransactionNotFound
}

/// Represents a query for an event pertaining to the specified transaction
#[derive(Debug, Clone)]
enum TxEventQuery {
    Accepted(String),
    Applied(String),
}

impl TxEventQuery {
    /// The event type to which this event query pertains
    fn event_type(&self) -> &'static str {
        match self {
            TxEventQuery::Accepted(_tx_hash) => "accepted",
            TxEventQuery::Applied(_tx_hash) => "applied",
        }
    }

    /// The transaction to which this event query pertains
    fn tx_hash(&self) -> &String {
        match self {
            TxEventQuery::Accepted(tx_hash) => tx_hash,
            TxEventQuery::Applied(tx_hash) => tx_hash,
        }
    }
}

/// Transaction event queries are semantically a subset of general queries

impl From<TxEventQuery> for Query {
    fn from(tx_query: TxEventQuery) -> Self {
        match tx_query {
            TxEventQuery::Accepted(tx_hash) => {
                Query::default().and_eq("accepted.hash", tx_hash)
            }
            TxEventQuery::Applied(tx_hash) => {
                Query::default().and_eq("applied.hash", tx_hash)
            }
        }
    }
}

pub enum TxQueryResult {
    Accepted(TxResponse),
    Applied(TxResponse),
}

pub struct BondQueryResult { //FIXME: improve this struct
    bonds: Amount,
    active: Amount,
    unbonds: Amount,
    withdrawable: Amount
}

pub struct SlashQueryResult(HashMap<Address, Vec<Slash>>); // TODO: implement getter for this


/// Represents the result of a balance query. First Address is the Owner one,
/// nested Address is the token one.
#[derive(Default)]
pub struct BalanceQueryResult(HashMap<Address, HashMap<Address, Amount>>);

impl BalanceQueryResult {
    fn insert(&mut self, owner: Address, token: Address, balance: Amount) {
        self.0.insert(owner, token, balance);
    }

    pub fn get_balance(
        &self,
        owner: &Address,
        token: &Address,
    ) -> Option<Amount> {
        match self.0.get(owner) {
            Some(inner) => inner.get(token).unwrap(),
            None => None
        }
    }
}

pub type Result<T> = std::result::Result<T, QueryError>;


/// Query the epoch of the last committed block.
pub async fn query_epoch<C>(client: C) -> Result<Epoch>
where C: Client + Sync {
    let path = Path::Epoch;
    let data = vec![];
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .map_err(|_| QueryError::ABCIQueryError)?;

    match response.code {
        Code::Ok => Ok(Epoch::try_from_slice(&response.value[..])?),
        Code::Err(err) => Err(QueryError::Format(response.info, err)),
    }
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
pub async fn query_balance<C>(
    client: C,
    token: Option<&Address>,
    owner: Option<&Address>,
) -> Result<BalanceQueryResult>
where C: Client + Clone + Sync {
    let tokens = address::tokens();
    let mut result = BalanceQueryResult::new();
    match (token, owner) {
        (Some(token), Some(owner)) => {
            let key = token::balance_key(token, owner);
            let currency_code = tokens
                .get(token)
                .map(|c| Cow::Borrowed(*c))
                .unwrap_or_else(|| Cow::Owned(token.to_string()));

            if let Some(balance) =
                query_storage_value::<C, Amount>(client, key).await?
            {
                result.insert(owner.to_owned(), token.to_owned(), balance);
            }
        }
        (None, Some(owner)) => {
            for (token, currency_code) in tokens {
                let key = token::balance_key(&token, owner);
                if let Some(balance) =
                    query_storage_value::<C, Amount>(client.clone(), key)
                        .await?
                {
                    result.insert(owner.to_owned(), token, balance);
                }
            }
        }
        (Some(token), None) => {
            let key = token::balance_prefix(token);
            if let Some(balances) =
                query_storage_prefix::<C, Amount>(client, key).await?
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
                    query_storage_prefix::<C, Amount>(client.clone(), key)
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
pub async fn query_bonds<C>(client: C, owner: Option<Address>, validator: Option<Address>) -> Result<BondQueryResult> //FIXME: check calls to this function (no more references now)
where C: Client + Clone + Sync  {
    // FIXME: refactor, function too long (export to different supfunctions and/or try to share code between match cases)
    // FIXME: should return Bonds?
    let epoch = query_epoch(client.clone()).await?;
    let mut result: BondQueryResult; // TODO: initialize to 0 all fields
    match (owner, validator) {
        (Some(owner), Some(validator)) => {
            // Find owner's delegations to the given validator
            let bond_id = pos::BondId { source: owner, validator };
            let bond_key = pos::bond_key(&bond_id);
            let bonds =
                query_storage_value::<C, pos::Bonds>(client.clone(), bond_key)
                    .await?;
            // Find owner's unbonded delegations from the given
            // validator
            let unbond_key = pos::unbond_key(&bond_id);
            let unbonds =
                query_storage_value::<C, pos::Unbonds>(client.clone(), unbond_key)
                    .await?;
            // Find validator's slashes, if any
            let slashes_key = pos::validator_slashes_key(&bond_id.validator);
            let slashes =
                query_storage_value::<C, pos::Slashes>(client, slashes_key)
                    .await?
                    .unwrap_or_default();

            if let Some(bonds) = &bonds {
                let (t, a) = process_bonds_query(
                    bonds, &slashes, epoch, None, None,
                );
                result.bonds = t;
                result.active = a;
            }

            if let Some(unbonds) = &unbonds {
                let (t, w) = process_unbonds_query(
                    unbonds, &slashes, epoch, None, None,
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
                query_storage_value::<C, pos::Bonds>(client.clone(), bond_key)
                    .await?;
            // Find validator's unbonded self-bonds
            let unbond_key = pos::unbond_key(&bond_id);
            let unbonds =
                query_storage_value::<C, pos::Unbonds>(client.clone(), unbond_key)
                    .await?;
            // Find validator's slashes, if any
            let slashes_key = pos::validator_slashes_key(&bond_id.validator);
            let slashes =
                query_storage_value::<C, pos::Slashes>(client, slashes_key)
                    .await?
                    .unwrap_or_default();

            if let Some(bonds) = &bonds {
                let (b, a) = process_bonds_query(
                    bonds, &slashes, epoch, None, None,
                );
                result.bonds = b;
                result.active = a;
            }

            if let Some(unbonds) = &unbonds {
                let (u, w) = process_unbonds_query(
                    unbonds, &slashes, epoch, None, None,
                );
                result.unbonds = u;
                result.withdrawable = w;
            }
        }
        (Some(owner), None) => {
            // Find owner's bonds to any validator
            let bonds_prefix = pos::bonds_for_source_prefix(&owner);
            let bonds = query_storage_prefix::<C, pos::Bonds>(
                client.clone(),
                bonds_prefix,
            )
            .await?;
            // Find owner's unbonds to any validator
            let unbonds_prefix = pos::unbonds_for_source_prefix(&owner);
            let unbonds = query_storage_prefix::<C, pos::Unbonds>(
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
                            let slashes = query_storage_value::<C, pos::Slashes>(
                                client.clone(),
                                slashes_key,
                            )
                            .await?
                            .unwrap_or_default();

                            let (tot, tot_active) = process_bonds_query(
                                &bonds,
                                &slashes,
                                epoch,
                                Some(result.bonds),
                                Some(result.active),
                            );
                            result.bonds = tot;
                            result.active = tot_active;
                        }
                        None => {
                            return Err(QueryError::NoBondKey(key));
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
                            let slashes = query_storage_value::<C, pos::Slashes>(
                                client.clone(),
                                slashes_key,
                            )
                            .await?
                            .unwrap_or_default();

                            let (tot, tot_withdrawable) = process_unbonds_query(
                                &unbonds,
                                &slashes,
                                epoch,
                                Some(result.unbonds),
                                Some(result.withdrawable),
                            );
                            result.unbonds = tot;
                            result.withdrawable = tot_withdrawable;
                        }
                        None => {
                            return Err(QueryError::NoBondKey(key));
                        }
                    }
                }
            }
        }
        (None, None) => {
            // Find all the bonds
            let bonds_prefix = pos::bonds_prefix();
            let bonds = query_storage_prefix::<C, pos::Bonds>(
                client.clone(),
                bonds_prefix,
            )
            .await?;
            // Find all the unbonds
            let unbonds_prefix = pos::unbonds_prefix();
            let unbonds = query_storage_prefix::<C, pos::Unbonds>(
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
                            let slashes = query_storage_value::<C, pos::Slashes>(
                                client.clone(),
                                slashes_key,
                            )
                            .await?
                            .unwrap_or_default();

                            let (tot, tot_active) = process_bonds_query(
                                &bonds,
                                &slashes,
                                epoch,
                                Some(result.bonds),
                                Some(result.active),
                            );
                            result.bonds = tot;
                            result.active = tot_active;
                        }
                        None => {
                            return Err(QueryError::NoBondKey(key));
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
                            let slashes = query_storage_value::<C, pos::Slashes>(
                                client.clone(),
                                slashes_key,
                            )
                            .await?
                            .unwrap_or_default();

                            let (tot, tot_withdrawable) = process_unbonds_query(
                                &unbonds,
                                &slashes,
                                epoch,
                                Some(result.unbonds),
                                Some(result.withdrawable),
                            );
                            result.unbonds = tot;
                            result.withdrawable = tot_withdrawable;
                        }
                        None => {
                            return Err(QueryError::NoBondKey(key));
                        }
                    }
                }
            }
        }
    }
    Ok(result)
}

/// Query PoS voting power
/// If validator is Some then returns the voting power of that specific address,
/// otherwise returns the total voting power.
pub async fn query_voting_power<C>(client: C, validator: Option<&Address>, epoch: Option<Epoch>) -> Result<Option<VotingPower>>
where C: Client + Clone + Sync {
    let epoch = match epoch {
        Some(epoch) => epoch,
        None => query_epoch(client.clone()).await?,
    };

    match validator {
        Some(validator) => {
            // Find voting power for the given validator
            let voting_power_key = pos::validator_voting_power_key(validator);
            let voting_powers =
                query_storage_value::<C, pos::ValidatorVotingPowers>(
                    client.clone(),
                    voting_power_key,
                )
                .await?;
            match voting_powers.and_then(|data| data.get(epoch)) {
                Some(voting_power_delta) => {
                    let voting_power: VotingPower =
                        voting_power_delta.try_into().map_err(|_| QueryError::NegativeVotingPowerDeltas)?;
                    Ok(Some(voting_power))
                }
                None => Ok(None)
            }
        }
        None => {
            // Find total voting power
            let total_voting_power_key = pos::total_voting_power_key();
            let total_voting_powers = query_storage_value::<C, pos::TotalVotingPowers>(
                client,
                total_voting_power_key,
            )
            .await?
            .ok_or(QueryError::UnsetVotingPower)?;

            match total_voting_powers.get(epoch) {
                Some(total_voting_power_delta) => {
                    let total_voting_power = total_voting_power_delta.try_into().map_err(|_| QueryError::NegativeVotingPowerDeltas)?;
                    Ok(Some(total_voting_power))
                },
                None => Ok(None)
            }
        }
    }
}

/// Query PoS slashes
/// If validator is Some then returns the slashes for it, otherwise returns
/// the slashes for all the validators.
pub async fn query_slashes<C>(client: C, validator: Option<&Address>) -> Result<Option<SlashQueryResult>>
where C: Client + Clone + Sync {
    let mut result: SlashQueryResult;
    match validator {
        Some(validator) => {
            // Find slashes for the given validator
            let slashes_key = pos::validator_slashes_key(validator);
            let slashes = query_storage_value::<C, pos::Slashes>(
                client.clone(),
                slashes_key,
            )
            .await?;

            match slashes { //FIXME: improve this
                Some(slashes) => {
                    result.insert(validator.to_owned(), slashes); //FIXME: is slashes a Vec<Slash>?
                },
                None => {
                    return Ok(None);
                }
            }
        }
        None => {
            // Iterate slashes for all validators
            let slashes_prefix = pos::slashes_prefix();
            let slashes = query_storage_prefix::<C, pos::Slashes>(
                client.clone(),
                slashes_prefix,
            )
            .await?;

            match slashes {
                Some(slashes) => {
                    for (slashes_key, slashes) in slashes {
                        if let Some(validator) =
                            pos::is_validator_slashes_key(&slashes_key)
                        {
                            result.insert(validator.to_owned(), slashes);  //FIXME: is slashes a Vec<Slash>?
                        }
                    }
                }
                None => {
                    return Ok(None);
                }
            }
        }
    }
    Ok(Some(result))
}

/// Dry run a transaction
pub async fn dry_run_tx<C>(client: C, tx_bytes: Vec<u8>) -> Result<AbciQuery>
where C: Client + Sync {
    let path = Path::DryRunTx;
    client
        .abci_query(Some(path.into()), tx_bytes, None, false)
        .await
        .map_err(|_| QueryError::ABCIQueryError)
}

/// Get account's public key stored in its storage sub-space
pub async fn get_public_key<C>(
    client: C,
    address: &Address,
) -> Result<Option<ed25519::PublicKey>>
where C: Client + Sync {
    let key = ed25519::pk_key(address);
    query_storage_value(client, key).await
}

/// Check if the given address is a known validator.
pub async fn is_validator<C>(
    client: C,
    address: &Address,
) -> Result<bool>
where C: Client + Sync {
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
pub async fn known_address<C>(
    client: C,
    address: &Address,
) -> Result<bool>
where C: Client + Sync {
    match address {
        Address::Established(_) => {
            // Established account exists if it has a VP
            let key = Key::validity_predicate(address);
            query_has_storage_key(client, key).await
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
    total: Option<Amount>,
    total_active: Option<Amount>,
) -> (Amount, Amount) {
    let mut total_active = total_active.unwrap_or_else(|| 0.into());
    let mut current_total: Amount = 0.into();

    for bond in bonds.iter() {
        for (epoch_start, &(mut delta)) in bond.deltas.iter().sorted() {
            delta = apply_slashes(slashes, delta, *epoch_start, None);
            current_total += delta;

            if epoch > (*epoch_start).into() {
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
            if epoch > (*epoch_end).into() {
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
) -> Result<Option<T>>
where
    C: Client + Sync,
    T: BorshDeserialize, 
{
    let path = Path::Value(key);
    let data = vec![];
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .map_err(|_| QueryError::ABCIQueryError)?;

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
async fn query_storage_prefix<C, T>(
    client: C,
    key: Key,
) -> Result<Option<impl Iterator<Item = (Key, T)>>>
where
    C: Client + Sync,
    T: BorshDeserialize,
{
    let path = Path::Prefix(key);
    let data = vec![];
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .map_err(|_| QueryError::ABCIQueryError)?;

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
                    Ok(Some(values.into_iter().filter_map(decode)))
                }
                Err(err) => Err(QueryError::Decoding(err)),
            }
        }
        Code::Err(err) if err == 1 => Ok(None),
        Code::Err(err) =>  Err(QueryError::Format(response.info, err))
    }
}

/// Query to check if the given storage key exists.
async fn query_has_storage_key<C>(
    client: C,
    key: Key,
) -> Result<bool> 
where C: Client + Sync{
    let path = Path::HasKey(key);
    let data = vec![];
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .map_err(|_| QueryError::ABCIQueryError)?;

    match response.code {
        Code::Ok => match bool::try_from_slice(&response.value[..]) {
            Ok(value) => Ok(value),
            Err(err) => Err(QueryError::Decoding(err)),
        },
        Code::Err(err) => Err(QueryError::Format(response.info, err))
    }
}

/// Lookup the full response accompanying the specified transaction event
async fn query_tx_response<C>(
    client: C,
    tx_query: TxEventQuery,
) -> Result<TxResponse>
where C: Client + Sync {
    // Find all blocks that apply a transaction with the specified hash
    let blocks = client
        .block_search(Query::from(tx_query.clone()), 1, 255, Order::Ascending)
        .await
        .map_err(|_| QueryError::TransactionNotFound)?
        .blocks;

    // Get the block results corresponding to a block to which
    // the specified transaction belongs
    let block = &blocks
        .get(0)
        .ok_or_else(|| {
            QueryError::BlockNotFound
        })?
        .block;

    let response_block_results = client
        .block_results(block.header.height)
        .await
        .map_err(|_| QueryError::BlockNotFound)?;

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
pub async fn query_tx_result<C, T>(client: C, tx_hash: T) -> Result<TxQueryResult>
where C: Client + Clone + Sync, T: Into<String> {
    // First try looking up application event pertaining to given hash.
    let tx_hash: String = tx_hash.into();
    let tx_response = query_tx_response(
        client.clone(),
        TxEventQuery::Applied(tx_hash.clone()),
    )
    .await;

    match tx_response {
        Ok(tx_response) => Ok(TxQueryResult::Applied(tx_response)),
        Err(_) => {
            // If this fails then instead look for an acceptance event.
            let tx_response = query_tx_response(
                client,
                TxEventQuery::Accepted(tx_hash),
            )
            .await?;
            Ok(TxQueryResult::Accepted(tx_response))
        }
    }
}
