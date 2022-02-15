//! Types that are used in RPC.

// TODO: fixes imports
// TODO: remove print and move them where the functions are called
// TODO: remove safe exits
// TODO: check which elements should be public

use std::fmt::Display;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(not(feature = "ABCI"))]
use tendermint::abci::Path as AbciPath;
#[cfg(not(feature = "ABCI"))]
use tendermint_rpc::query::Query;
#[cfg(feature = "ABCI")]
use tendermint_rpc_abci::query::Query;
#[cfg(feature = "ABCI")]
use tendermint_stable::abci::Path as AbciPath;
use thiserror::Error;

use crate::types::address::Address;
use crate::types::storage;

/// RPC query path
#[derive(Debug, Clone)]
pub enum Path {
    /// Dry run a transaction
    DryRunTx,
    /// Epoch of the last committed block
    Epoch,
    /// Read a storage value with exact storage key
    Value(storage::Key),
    /// Read a range of storage values with a matching key prefix
    Prefix(storage::Key),
    /// Check if the given storage key exists
    HasKey(storage::Key),
}

/// RPC query path
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct PrefixValue {
    pub key: storage::Key,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BalanceQuery {
    #[allow(dead_code)]
    owner: Option<Address>,
    #[allow(dead_code)]
    token: Option<Address>,
}

const DRY_RUN_TX_PATH: &str = "dry_run_tx";
const EPOCH_PATH: &str = "epoch";
const VALUE_PREFIX: &str = "value";
const PREFIX_PREFIX: &str = "prefix";
const HAS_KEY_PREFIX: &str = "has_key";

impl Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Path::DryRunTx => write!(f, "{}", DRY_RUN_TX_PATH),
            Path::Epoch => write!(f, "{}", EPOCH_PATH),
            Path::Value(storage_key) => {
                write!(f, "{}/{}", VALUE_PREFIX, storage_key)
            }
            Path::Prefix(storage_key) => {
                write!(f, "{}/{}", PREFIX_PREFIX, storage_key)
            }
            Path::HasKey(storage_key) => {
                write!(f, "{}/{}", HAS_KEY_PREFIX, storage_key)
            }
        }
    }
}

impl FromStr for Path {
    type Err = PathParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = s.to_lowercase();
        match path.as_str() {
            DRY_RUN_TX_PATH => Ok(Self::DryRunTx),
            EPOCH_PATH => Ok(Self::Epoch),
            _ => match path.split_once("/") {
                Some((VALUE_PREFIX, storage_key)) => {
                    let key = storage::Key::parse(storage_key)
                        .map_err(PathParseError::InvalidStorageKey)?;
                    Ok(Self::Value(key))
                }
                Some((PREFIX_PREFIX, storage_key)) => {
                    let key = storage::Key::parse(storage_key)
                        .map_err(PathParseError::InvalidStorageKey)?;
                    Ok(Self::Prefix(key))
                }
                Some((HAS_KEY_PREFIX, storage_key)) => {
                    let key = storage::Key::parse(storage_key)
                        .map_err(PathParseError::InvalidStorageKey)?;
                    Ok(Self::HasKey(key))
                }
                _ => Err(PathParseError::InvalidPath(s.to_string())),
            },
        }
    }
}

impl From<Path> for AbciPath {
    fn from(path: Path) -> Self {
        let path = path.to_string();
        // TODO: update in tendermint-rs to allow to construct this from owned
        // string. It's what `from_str` does anyway
        AbciPath::from_str(&path).unwrap()
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum PathParseError {
    #[error("Unrecognized query path: {0}")]
    InvalidPath(String),
    #[error("Invalid storage key: {0}")]
    InvalidStorageKey(storage::Error),
}

/// A data type to represent the response of a tx.
#[derive(Debug, Serialize)]
pub struct TxResponse {
    pub info: String,
    pub height: String,
    pub hash: String,
    pub code: String,
    pub gas_used: String,
    pub initialized_accounts: Vec<Address>,
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

