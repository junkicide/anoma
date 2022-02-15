# RPC

The ledger provides an RPC interface for submitting transactions to the mempool, subscribing to their results and queries about the state of the ledger and its storage.

The RPC interface is provided as [specified](https://github.com/tendermint/spec/tree/4566f1e3028278c5b3eca27b53254a48771b152b/spec/rpc) from Tendermint and most of the requests are routed to the Anoma ledger via ABCI.

## Transactions

A [transaction](../ledger.md#transactions) can be submitted to the [mempool](../ledger.md#mempool) via Tendermint's [`BroadCastTxSync`](https://github.com/tendermint/spec/tree/4566f1e3028278c5b3eca27b53254a48771b152b/spec/rpc#broadcasttxsync) or [`BroadCastTxAsync`](https://github.com/tendermint/spec/tree/4566f1e3028278c5b3eca27b53254a48771b152b/spec/rpc#broadcasttxasync). The `CheckTx` result of these requests is success only if the transaction passes [mempool validation rules](../ledger.md#mempool). In case of `BroadCastTxAsync`, the `DeliverTx` is not indicative of the transaction's result, it's merely a result of the transaction being added to the [transaction queue](../ledger.md#outer-transaction-processing). The actual result of the outer transaction and the inner transaction can be found from via the [ABCI events](https://github.com/tendermint/spec/blob/4566f1e3028278c5b3eca27b53254a48771b152b/spec/abci/abci.md#events).

To find a result of the inner transaction, query for event with `type` equal to `"NewBlock"` and key equal to `"applied.hash"`, where the `value` of the found `Event` will contain the `TxResult` (TODO link to encoding depends on <https://github.com/anoma/anoma/issues/455>).

## Read-only queries

TODO document response types encoding

Read-only queries can be requested via [ABCIQuery](https://github.com/tendermint/spec/tree/4566f1e3028278c5b3eca27b53254a48771b152b/spec/rpc#abciquery). The `path` for the query can be one of the following options:

- `epoch`: get current epoch
- `dry_run_tx`: simulate a transaction being applied in a block
- `value/{dynamic}`: look-up a raw [storage](../ledger.md#storage) value for the given `dynamic` key
- `prefix/{dynamic}`: iterate a [storage](../ledger.md#storage) key prefix for the given `dynamic` key
- `has_key/{dynamic}`: check if the given `dynamic` key is present in the [storage](../ledger.md#storage)

For example, to find if an established address exists on-chain, we can submit a query to find if it has a validity predicate at path `has_key/@{established_address}/?`, which is the only storage value required for established addresses (note that `@` is a special storage key segment prefix for bech32m encoded addresses and `?` character is used as the last segment of a validity predicate storage key).

## PoS

TODO document response types encoding

The Proof-of-Stake queries are built on top of the [read-only queries](#read-only-queries), where all the PoS data are stored under the [internal `PoS` address](../encoding.html#internaladdress), which is governed by its native validity predicate. The bech32m encoded address of the PoS account currently is `"atest1v9hx7w362pex7mmxyphkvgznw3skkefqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqq8ylv7"`, in the storage keys below in place of `PoS`.

- `@{PoS}/bond/@{validator}/@{validator}`: validator self-bonds, where `validator` is its bech32m encoded address
- `@{PoS}/bond/@{owner}/@{validator}`: delegation bonds, where `owner` is the delegation source and `validator` the delegation target
- `@{PoS}/unbond/@{validator}/@{validator}`: unbonded validator self-bonds, where `validator` is its bech32m encoded address
- `@{PoS}/unbond/@{owner}/@{validator}`: unbonded delegation bonds, where `owner` is the delegation source and `validator` the delegation target
- `@{PoS}/validator/@{validator}/voting_power`: `validator`'s voting power
- `@{PoS}/slash/@{validator}`: slashes applied to the `validator`, if any

## Default validity predicate storage queries

The [default validity predicate](default-validity-predicates.md) for the implicit accounts and token accounts enforce a format for the account's storage. This storage can be queried at the following paths:

- public key
- token balance
