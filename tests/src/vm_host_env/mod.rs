//! VM host environment integration tests.
//!
//! You can enable logging with the `RUST_LOG` environment variable, e.g.:
//!
//! `RUST_LOG=debug cargo test`.
//!
//! Because the test runner captures the standard output from the test, this
//! will only print logging from failed tests. To avoid that, use the
//! `--nocapture` argument. Also, because by default the tests run in parallel,
//! it is better to select a single test, e.g.:
//!
//! `RUST_LOG=debug cargo test test_tx_read_write -- --nocapture`
pub mod ibc;
pub mod tx;
pub mod vp;

#[cfg(test)]
mod tests {

    use std::panic;

    #[cfg(not(feature = "ABCI"))]
    use ::ibc::tx_msg::Msg;
    use anoma::ledger::ibc::handler::IbcActions;
    use anoma::ledger::ibc::vp::Error as IbcError;
    use anoma::proto::Tx;
    use anoma::types::key::*;
    use anoma::types::storage::{self, Key, KeySeg};
    use anoma::types::time::DateTimeUtc;
    use anoma::types::token::{self, Amount};
    use anoma::types::{address, key};
    use anoma_vm_env::tx_prelude::{
        BorshDeserialize, BorshSerialize, KeyValIterator,
    };
    use anoma_vm_env::vp_prelude::{PostKeyValIterator, PreKeyValIterator};
    #[cfg(feature = "ABCI")]
    use ibc_abci::tx_msg::Msg;
    use itertools::Itertools;
    use prost::Message;
    #[cfg(not(feature = "ABCI"))]
    use tendermint_proto::Protobuf;
    #[cfg(feature = "ABCI")]
    use tendermint_proto_abci::Protobuf;
    use test_log::test;

    use super::ibc;
    use super::tx::*;
    use super::vp::*;

    // paths to the WASMs used for tests
    const VP_ALWAYS_TRUE_WASM: &str = "../wasm_for_tests/vp_always_true.wasm";
    const VP_ALWAYS_FALSE_WASM: &str = "../wasm_for_tests/vp_always_false.wasm";

    #[test]
    fn test_tx_read_write() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let key = "key";
        let read_value: Option<String> = tx_host_env::read(key);
        assert_eq!(
            None, read_value,
            "Trying to read a key that doesn't exists shouldn't find any value"
        );

        // Write some value
        let value = "test".repeat(4);
        tx_host_env::write(key, value.clone());

        let read_value: Option<String> = tx_host_env::read(key);
        assert_eq!(
            Some(value),
            read_value,
            "After a value has been written, we should get back the same \
             value when we read it"
        );

        let value = vec![1_u8; 1000];
        tx_host_env::write(key, value.clone());
        let read_value: Option<Vec<u8>> = tx_host_env::read(key);
        assert_eq!(
            Some(value),
            read_value,
            "Writing to an existing key should override the previous value"
        );
    }

    #[test]
    fn test_tx_has_key() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let key = "key";
        assert!(
            !tx_host_env::has_key(key),
            "Before a key-value is written, its key shouldn't be found"
        );

        // Write some value
        let value = "test".to_string();
        tx_host_env::write(key, value);

        assert!(
            tx_host_env::has_key(key),
            "After a key-value has been written, its key should be found"
        );
    }

    #[test]
    fn test_tx_delete() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        let test_account = address::testing::established_address_1();
        env.spawn_accounts([&test_account]);
        init_tx_env(&mut env);

        // Trying to delete a key that doesn't exists should be a no-op
        let key = "key";
        tx_host_env::delete(key);

        let value = "test".to_string();
        tx_host_env::write(key, value);
        assert!(
            tx_host_env::has_key(key),
            "After a key-value has been written, its key should be found"
        );

        // Then delete it
        tx_host_env::delete(key);

        assert!(
            !tx_host_env::has_key(key),
            "After a key has been deleted, its key shouldn't be found"
        );

        // Trying to delete a validity predicate should fail
        let key = storage::Key::validity_predicate(&test_account).to_string();
        assert!(
            panic::catch_unwind(|| { tx_host_env::delete(key) })
                .err()
                .map(|a| a.downcast_ref::<String>().cloned().unwrap())
                .unwrap()
                .contains("CannotDeleteVp")
        );
    }

    #[test]
    fn test_tx_iter_prefix() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let iter: KeyValIterator<Vec<u8>> = tx_host_env::iter_prefix("empty");
        assert_eq!(
            iter.count(),
            0,
            "Trying to iter a prefix that doesn't have any matching keys \
             should yield an empty iterator."
        );

        // Write some values directly into the storage first
        let prefix = Key::parse("prefix").unwrap();
        for i in 0..10_i32 {
            let key = prefix.join(&Key::parse(i.to_string()).unwrap());
            let value = i.try_to_vec().unwrap();
            env.storage.write(&key, value).unwrap();
        }
        env.storage.commit().unwrap();

        // Then try to iterate over their prefix
        let iter: KeyValIterator<i32> =
            tx_host_env::iter_prefix(prefix.to_string());
        let expected = (0..10).map(|i| (format!("{}/{}", prefix, i), i));
        itertools::assert_equal(iter.sorted(), expected.sorted());
    }

    #[test]
    fn test_tx_insert_verifier() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        assert!(env.verifiers.is_empty(), "pre-condition");
        let verifier = address::testing::established_address_1();
        tx_host_env::insert_verifier(&verifier);
        assert!(
            env.verifiers.contains(&verifier),
            "The verifier should have been inserted"
        );
        assert_eq!(
            env.verifiers.len(),
            1,
            "There should be only one verifier inserted"
        );
    }

    #[test]
    #[should_panic]
    fn test_tx_init_account_with_invalid_vp() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let code = vec![];
        tx_host_env::init_account(code);
    }

    #[test]
    fn test_tx_init_account_with_valid_vp() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        let code =
            std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");
        tx_host_env::init_account(code);
    }

    #[test]
    fn test_tx_get_metadata() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        assert_eq!(tx_host_env::get_chain_id(), env.storage.get_chain_id().0);
        assert_eq!(
            tx_host_env::get_block_height(),
            env.storage.get_block_height().0
        );
        assert_eq!(
            tx_host_env::get_block_hash(),
            env.storage.get_block_hash().0
        );
        assert_eq!(
            tx_host_env::get_block_epoch(),
            env.storage.get_current_epoch().0
        );
    }

    /// An example how to write a VP host environment integration test
    #[test]
    fn test_vp_host_env() {
        // The environment must be initialized first
        let mut env = TestVpEnv::default();
        init_vp_env(&mut env);

        // We can add some data to the environment
        let key_raw = "key";
        let key = Key::parse(key_raw.to_string()).unwrap();
        let value = "test".to_string();
        let value_raw = value.try_to_vec().unwrap();
        env.write_log.write(&key, value_raw).unwrap();

        let read_pre_value: Option<String> = vp_host_env::read_pre(key_raw);
        assert_eq!(None, read_pre_value);
        let read_post_value: Option<String> = vp_host_env::read_post(key_raw);
        assert_eq!(Some(value), read_post_value);
    }

    #[test]
    fn test_vp_read_and_has_key() {
        let mut tx_env = TestTxEnv::default();

        let addr = address::testing::established_address_1();
        let addr_key = Key::from(addr.to_db_key());

        // Write some value to storage
        let existing_key =
            addr_key.join(&Key::parse("existing_key_raw").unwrap());
        let existing_key_raw = existing_key.to_string();
        let existing_value = vec![2_u8; 1000];
        // Values written to storage have to be encoded with Borsh
        let existing_value_encoded = existing_value.try_to_vec().unwrap();
        tx_env
            .storage
            .write(&existing_key, existing_value_encoded)
            .unwrap();

        // In a transaction, write override the existing key's value and add
        // another key-value
        let override_value = "override".to_string();
        let new_key =
            addr_key.join(&Key::parse("new_key").unwrap()).to_string();
        let new_value = "vp".repeat(4);

        // Initialize the VP environment via a transaction
        // The `_vp_env` MUST NOT be dropped until the end of the test
        let _vp_env = init_vp_env_from_tx(addr, tx_env, |_addr| {
            // Override the existing key
            tx_host_env::write(&existing_key_raw, &override_value);

            // Write the new key-value
            tx_host_env::write(&new_key, new_value.clone());
        });

        assert!(
            vp_host_env::has_key_pre(&existing_key_raw),
            "The existing key before transaction should be found"
        );
        let pre_existing_value: Option<Vec<u8>> =
            vp_host_env::read_pre(&existing_key_raw);
        assert_eq!(
            Some(existing_value),
            pre_existing_value,
            "The existing value read from state before transaction should be \
             unchanged"
        );

        assert!(
            !vp_host_env::has_key_pre(&new_key),
            "The new key before transaction shouldn't be found"
        );
        let pre_new_value: Option<Vec<u8>> = vp_host_env::read_pre(&new_key);
        assert_eq!(
            None, pre_new_value,
            "The new value read from state before transaction shouldn't yet \
             exist"
        );

        assert!(
            vp_host_env::has_key_post(&existing_key_raw),
            "The existing key after transaction should still be found"
        );
        let post_existing_value: Option<String> =
            vp_host_env::read_post(&existing_key_raw);
        assert_eq!(
            Some(override_value),
            post_existing_value,
            "The existing value read from state after transaction should be \
             overridden"
        );

        assert!(
            vp_host_env::has_key_post(&new_key),
            "The new key after transaction should be found"
        );
        let post_new_value: Option<String> = vp_host_env::read_post(&new_key);
        assert_eq!(
            Some(new_value),
            post_new_value,
            "The new value read from state after transaction should have a \
             value equal to the one written in the transaction"
        );
    }

    #[test]
    fn test_vp_iter_prefix() {
        let mut tx_env = TestTxEnv::default();

        let addr = address::testing::established_address_1();
        let addr_key = Key::from(addr.to_db_key());

        // Write some value to storage
        let prefix = addr_key.join(&Key::parse("prefix").unwrap());
        for i in 0..10_i32 {
            let key = prefix.join(&Key::parse(i.to_string()).unwrap());
            let value = i.try_to_vec().unwrap();
            tx_env.storage.write(&key, value).unwrap();
        }
        tx_env.storage.commit().unwrap();

        // In a transaction, write override the existing key's value and add
        // another key-value
        let existing_key = prefix.join(&Key::parse(5.to_string()).unwrap());
        let existing_key_raw = existing_key.to_string();
        let new_key = prefix.join(&Key::parse(11.to_string()).unwrap());
        let new_key_raw = new_key.to_string();

        // Initialize the VP environment via a transaction
        // The `_vp_env` MUST NOT be dropped until the end of the test
        let _vp_env = init_vp_env_from_tx(addr, tx_env, |_addr| {
            // Override one of the existing keys
            tx_host_env::write(&existing_key_raw, 100_i32);

            // Write the new key-value under the same prefix
            tx_host_env::write(&new_key_raw, 11.try_to_vec().unwrap());
        });

        let iter_pre: PreKeyValIterator<i32> =
            vp_host_env::iter_prefix_pre(prefix.to_string());
        let expected_pre = (0..10).map(|i| (format!("{}/{}", prefix, i), i));
        itertools::assert_equal(iter_pre.sorted(), expected_pre.sorted());

        let iter_post: PostKeyValIterator<i32> =
            vp_host_env::iter_prefix_post(prefix.to_string());
        let expected_post = (0..10).map(|i| {
            let val = if i == 5 { 100 } else { i };
            (format!("{}/{}", prefix, i), val)
        });
        itertools::assert_equal(iter_post.sorted(), expected_post.sorted());
    }

    #[test]
    fn test_vp_verify_tx_signature() {
        let mut env = TestVpEnv::default();

        let addr = address::testing::established_address_1();

        // Write the public key to storage
        let pk_key = key::pk_key(&addr);
        let keypair = key::testing::keypair_1();
        let pk = keypair.public_part().clone();
        env.storage
            .write(&pk_key, pk.try_to_vec().unwrap())
            .unwrap();

        // Use some arbitrary bytes for tx code
        let code = vec![4, 3, 2, 1, 0];
        for data in &[
            // Tx with some arbitrary data
            Some(vec![1, 2, 3, 4].repeat(10)),
            // Tx without any data
            None,
        ] {
            env.tx = Tx::new(code.clone(), data.clone()).sign::<ed25519c::SigScheme>(&keypair);
            // Initialize the environment
            init_vp_env(&mut env);

            let tx_data = env.tx.data.expect("data should exist");
            let signed_tx_data =
                match SignedTxData::<ed25519c::SigScheme>::try_from_slice(&tx_data[..]) {
                    Ok(data) => data,
                    _ => panic!("decoding failed"),
                };
            assert_eq!(&signed_tx_data.data, data);
            assert!(vp_host_env::verify_tx_signature(&pk, &signed_tx_data.sig));

            let other_keypair = key::testing::keypair_2();
            assert!(!vp_host_env::verify_tx_signature(
                &other_keypair.public_part(),
                &signed_tx_data.sig
            ));
        }
    }

    #[test]
    fn test_vp_get_metadata() {
        // The environment must be initialized first
        let mut env = TestVpEnv::default();
        init_vp_env(&mut env);

        assert_eq!(vp_host_env::get_chain_id(), env.storage.get_chain_id().0);
        assert_eq!(
            vp_host_env::get_block_height(),
            env.storage.get_block_height().0
        );
        assert_eq!(
            vp_host_env::get_block_hash(),
            env.storage.get_block_hash().0
        );
        assert_eq!(
            vp_host_env::get_block_epoch(),
            env.storage.get_current_epoch().0
        );
    }

    #[test]
    fn test_vp_eval() {
        // The environment must be initialized first
        let mut env = TestVpEnv::default();
        init_vp_env(&mut env);

        // evaluating without any code should fail
        let empty_code = vec![];
        let input_data = vec![];
        let result = vp_host_env::eval(empty_code, input_data);
        assert!(!result);

        // evaluating the VP template which always returns `true` should pass
        let code =
            std::fs::read(VP_ALWAYS_TRUE_WASM).expect("cannot load wasm");
        let input_data = vec![];
        let result = vp_host_env::eval(code, input_data);
        assert!(result);

        // evaluating the VP template which always returns `false` shouldn't
        // pass
        let code =
            std::fs::read(VP_ALWAYS_FALSE_WASM).expect("cannot load wasm");
        let input_data = vec![];
        let result = vp_host_env::eval(code, input_data);
        assert!(!result);
    }

    #[test]
    fn test_ibc_client() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        ibc::init_storage(&mut env.storage);

        // Start an invalid transaction
        let msg = ibc::msg_create_client();
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // get and increment the connection counter
        let counter_key = ibc::client_counter_key();
        let counter = ibc::TestIbcActions
            .get_and_inc_counter(&counter_key)
            .expect("getting the counter failed");
        let client_id = ibc::client_id(msg.client_state.client_type(), counter)
            .expect("invalid client ID");
        // only insert a client type
        let client_type_key = ibc::client_type_key(&client_id).to_string();
        tx_host_env::write(&client_type_key, msg.client_state.client_type());

        // Check should fail due to no client state
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(matches!(
            ibc_vp
                .validate(&tx_data)
                .expect_err("validation succeeded unexpectedly"),
            IbcError::ClientError(_),
        ));
        // drop the transaction
        env.write_log.drop_tx();

        // Start a transaction to create a new client
        let msg = ibc::msg_create_client();
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };

        // create a client with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("creating a client failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();

        // Start an invalid transaction
        let msg = ibc::msg_update_client(client_id);
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // get and update the client without a header
        let client_id = msg.client_id.clone();
        // update the client with the same state
        let old_data = ibc::msg_create_client();
        let same_client_state = old_data.client_state.clone();
        let height = same_client_state.latest_height();
        let same_consensus_state = old_data.consensus_state;
        let client_state_key = ibc::client_state_key(&client_id).to_string();
        tx_host_env::write_bytes(
            &client_state_key,
            same_client_state.encode_vec().unwrap(),
        );
        let consensus_state_key =
            ibc::consensus_state_key(&client_id, height).to_string();
        tx_host_env::write(
            &consensus_state_key,
            same_consensus_state.encode_vec().unwrap(),
        );
        let event = ibc::make_update_client_event(&client_id, &msg);
        tx_host_env::emit_ibc_event(&event.try_into().unwrap());

        // Check should fail due to the invalid updating
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(matches!(
            ibc_vp
                .validate(&tx_data)
                .expect_err("validation succeeded unexpectedly"),
            IbcError::ClientError(_),
        ));
        // drop the transaction
        env.write_log.drop_tx();

        // Start a transaction to update the client
        let msg = ibc::msg_update_client(client_id.clone());
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // update the client with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("updating the client failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();

        // Start a transaction to upgrade the client
        let msg = ibc::msg_upgrade_client(client_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // upgrade the client with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("upgrading the client failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_connection_init_and_open() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        ibc::init_storage(&mut env.storage);
        let (client_id, client_state, writes) = ibc::prepare_client();
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start an invalid transaction
        let msg = ibc::msg_connection_open_init(client_id.clone());
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // get and increment the connection counter
        let counter_key = ibc::connection_counter_key();
        let counter = ibc::TestIbcActions
            .get_and_inc_counter(&counter_key)
            .expect("getting the counter failed");
        // insert a new opened connection
        let conn_id = ibc::connection_id(counter);
        let conn_key = ibc::connection_key(&conn_id).to_string();
        let mut connection = ibc::init_connection(&msg);
        ibc::open_connection(&mut connection);
        tx_host_env::write_bytes(&conn_key, connection.encode_vec().unwrap());
        let event = ibc::make_open_init_connection_event(&conn_id, &msg);
        tx_host_env::emit_ibc_event(&event.try_into().unwrap());

        // Check should fail due to directly opening a connection
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(matches!(
            ibc_vp
                .validate(&tx_data)
                .expect_err("validation succeeded unexpectedly"),
            IbcError::ConnectionError(_),
        ));
        // drop the transaction
        env.write_log.drop_tx();

        // Start a transaction for ConnectionOpenInit
        let msg = ibc::msg_connection_open_init(client_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // init a connection with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("creating a connection failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();
        // set a block header again
        env.storage.set_header(ibc::tm_dummy_header()).unwrap();

        // Start the next transaction for ConnectionOpenAck
        let msg = ibc::msg_connection_open_ack(conn_id, client_state);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // open the connection with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("opening the connection failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_connection_try_and_open() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        ibc::init_storage(&mut env.storage);
        let (client_id, client_state, writes) = ibc::prepare_client();
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction for ConnectionOpenTry
        let msg = ibc::msg_connection_open_try(client_id, client_state);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // open try a connection with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("creating a connection failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();
        // set a block header again
        env.storage.set_header(ibc::tm_dummy_header()).unwrap();

        // Start the next transaction for ConnectionOpenConfirm
        let conn_id = ibc::connection_id(0);
        let msg = ibc::msg_connection_open_confirm(conn_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // open the connection with the mssage
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("opening the connection failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_channel_init_and_open() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start an invalid transaction
        let port_id = ibc::port_id("test_port").expect("invalid port ID");
        let msg = ibc::msg_channel_open_init(port_id.clone(), conn_id.clone());
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // not bind a port
        // get and increment the channel counter
        let counter_key = ibc::channel_counter_key();
        let counter = ibc::TestIbcActions
            .get_and_inc_counter(&counter_key)
            .expect("getting the counter failed");
        // channel
        let channel_id = ibc::channel_id(counter);
        let port_channel_id = ibc::port_channel_id(port_id, channel_id.clone());
        let channel_key = ibc::channel_key(&port_channel_id).to_string();
        tx_host_env::write_bytes(
            &channel_key,
            msg.channel().encode_vec().unwrap(),
        );
        let event = ibc::make_open_init_channel_event(&channel_id, &msg);
        tx_host_env::emit_ibc_event(&event.try_into().unwrap());

        // Check should fail due to no port binding
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(matches!(
            ibc_vp
                .validate(&tx_data)
                .expect_err("validation succeeded unexpectedly"),
            IbcError::ChannelError(_),
        ));
        // drop the transaction
        env.write_log.drop_tx();

        // Start an invalid transaction
        let port_id = ibc::port_id("test_port").expect("invalid port ID");
        let msg = ibc::msg_channel_open_init(port_id.clone(), conn_id.clone());
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // bind a port
        ibc::TestIbcActions
            .bind_port(&port_id)
            .expect("binding the port failed");
        // get and increment the channel counter
        let counter_key = ibc::channel_counter_key();
        let counter = ibc::TestIbcActions
            .get_and_inc_counter(&counter_key)
            .expect("getting the counter failed");
        // insert a opened channel
        let channel_id = ibc::channel_id(counter);
        let port_channel_id = ibc::port_channel_id(port_id, channel_id.clone());
        let channel_key = ibc::channel_key(&port_channel_id).to_string();
        let mut channel = msg.channel.clone();
        ibc::open_channel(&mut channel);
        tx_host_env::write_bytes(&channel_key, channel.encode_vec().unwrap());
        let event = ibc::make_open_init_channel_event(&channel_id, &msg);
        tx_host_env::emit_ibc_event(&event.try_into().unwrap());

        // Check should fail due to directly opening a channel
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(matches!(
            ibc_vp
                .validate(&tx_data)
                .expect_err("validation succeeded unexpectedly"),
            IbcError::ChannelError(_),
        ));
        // drop the transaction
        env.write_log.drop_tx();

        // Start a transaction for ChannelOpenInit
        let port_id = ibc::port_id("test_port").expect("invalid port ID");
        let msg = ibc::msg_channel_open_init(port_id.clone(), conn_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // init a channel with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("creating a channel failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();

        // Start the next transaction for ChannelOpenAck
        let msg = ibc::msg_channel_open_ack(port_id, channel_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // open the channle with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("opening the channel failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_channel_try_and_open() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction for ChannelOpenTry
        let port_id = ibc::port_id("test_port").expect("invalid port ID");
        let msg = ibc::msg_channel_open_try(port_id.clone(), conn_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // try open a channel with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("creating a channel failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();

        // Start the next transaction for ChannelOpenConfirm
        let channel_id = ibc::channel_id(0);
        let msg = ibc::msg_channel_open_confirm(port_id, channel_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // open a channel with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("opening the channel failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_channel_close_init() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction to close the channel
        let msg = ibc::msg_channel_close_init(port_id, channel_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // close the channel with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("closing the channel failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_channel_close_confirm() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction to close the channel
        let msg = ibc::msg_channel_close_confirm(port_id, channel_id);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };

        // close the channel with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("closing the channel failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_send_token() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction to send a packet
        let msg =
            ibc::msg_transfer(port_id, channel_id, token.to_string(), &sender);
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // send the token and a packet with the data
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("sending a packet failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
        // Check if the token was escrowed
        let escrow = address::Address::Internal(
            address::InternalAddress::ibc_escrow_address(
                msg.source_port.to_string(),
                msg.source_channel.to_string(),
            ),
        );
        let (token_vp, _) = ibc::init_token_vp_from_tx(&env, &tx, &escrow);
        assert!(
            token_vp
                .validate(&tx_data)
                .expect("token validation failed unexpectedly")
        );

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();

        // Start the next transaction for receiving an ack
        let counterparty = ibc::dummy_channel_counterparty();
        let packet =
            ibc::packet_from_message(&msg, ibc::sequence(1), &counterparty);
        let msg = ibc::msg_packet_ack(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // ack the packet with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("the packet ack failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_burn_token() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction to send a packet
        // Set this chain is the sink zone
        let token = format!("{}/{}/{}", port_id, channel_id, token);
        let msg = ibc::msg_transfer(port_id, channel_id, token, &sender);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // send the token and a packet with the data
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("sending a packet failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
        // Check if the token was burned
        let burn =
            address::Address::Internal(address::InternalAddress::IbcBurn);
        let (token_vp, _) = ibc::init_token_vp_from_tx(&env, &tx, &burn);
        assert!(
            token_vp
                .validate(&tx_data)
                .expect("token validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_receive_token() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        let (token, receiver) = ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // packet
        let packet = ibc::received_packet(
            port_id,
            channel_id,
            ibc::sequence(1),
            token.to_string(),
            &receiver,
        );

        // Start a transaction to receive a packet
        let msg = ibc::msg_packet_recv(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // receive a packet with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("receiving a packet failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
        // Check if the token was minted
        let mint =
            address::Address::Internal(address::InternalAddress::IbcMint);
        let (token_vp, _) = ibc::init_token_vp_from_tx(&env, &tx, &mint);
        assert!(
            token_vp
                .validate(&tx_data)
                .expect("token validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_unescrow_token() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        let (token, receiver) = ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });
        // escrow in advance
        let counterparty = ibc::dummy_channel_counterparty();
        let escrow = address::Address::Internal(
            address::InternalAddress::ibc_escrow_address(
                port_id.to_string(),
                channel_id.to_string(),
            ),
        );
        let key = token::balance_key(&token, &escrow);
        let val = Amount::from(1_000_000_000u64).try_to_vec().unwrap();
        env.storage.write(&key, val).expect("write error");

        // Set this chain as the source zone
        let token = format!(
            "{}/{}/{}",
            counterparty.port_id().clone(),
            counterparty.channel_id().unwrap().clone(),
            token
        );
        // packet
        let packet = ibc::received_packet(
            port_id,
            channel_id,
            ibc::sequence(1),
            token,
            &receiver,
        );

        // Start a transaction to receive a packet
        let msg = ibc::msg_packet_recv(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // receive a packet with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("receiving a packet failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
        // Check if the token was unescrowed
        let (token_vp, _) = ibc::init_token_vp_from_tx(&env, &tx, &escrow);
        assert!(
            token_vp
                .validate(&tx_data)
                .expect("token validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_send_packet_unordered() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction to send a packet
        let msg =
            ibc::msg_transfer(port_id, channel_id, token.to_string(), &sender);
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // send a packet with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("sending a packet failed");

        // the transaction does something before senging a packet

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();

        // Start the next transaction for receiving an ack
        let counterparty = ibc::dummy_channel_counterparty();
        let packet =
            ibc::packet_from_message(&msg, ibc::sequence(1), &counterparty);
        let msg = ibc::msg_packet_ack(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // ack the packet with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("the packet ack failed");

        // the transaction does something after the ack

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_receive_packet_unordered() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        let (token, receiver) = ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // packet (sequence number isn't checked for the unordered channel)
        let packet = ibc::received_packet(
            port_id,
            channel_id,
            ibc::sequence(100),
            token.to_string(),
            &receiver,
        );

        // Start a transaction to receive a packet
        let msg = ibc::msg_packet_recv(packet);
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };
        // receive a packet with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("receiving a packet failed");

        // the transaction does something according to the packet

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_packet_timeout() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction to send a packet
        let mut msg =
            ibc::msg_transfer(port_id, channel_id, token.to_string(), &sender);
        ibc::set_timeout_height(&mut msg);
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        // send a packet with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("sending apacket failed");

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();

        // Start a transaction to notify the timeout
        let counterparty = ibc::dummy_channel_counterparty();
        let packet =
            ibc::packet_from_message(&msg, ibc::sequence(1), &counterparty);
        let msg = ibc::msg_timeout(packet.clone(), ibc::sequence(1));
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };

        // close the channel with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("closing the channel failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
        // Check if the token was refunded
        let escrow = address::Address::Internal(
            address::InternalAddress::ibc_escrow_address(
                packet.source_port.to_string(),
                packet.source_channel.to_string(),
            ),
        );
        let (token_vp, _) = ibc::init_token_vp_from_tx(&env, &tx, &escrow);
        assert!(
            token_vp
                .validate(&tx_data)
                .expect("token validation failed unexpectedly")
        );
    }

    #[test]
    fn test_ibc_timeout_on_close() {
        // The environment must be initialized first
        let mut env = TestTxEnv::default();
        init_tx_env(&mut env);

        // Set the initial state before starting transactions
        let (token, sender) = ibc::init_storage(&mut env.storage);
        let (client_id, _client_state, mut writes) = ibc::prepare_client();
        let (conn_id, conn_writes) = ibc::prepare_opened_connection(&client_id);
        writes.extend(conn_writes);
        let (port_id, channel_id, channel_writes) =
            ibc::prepare_opened_channel(&conn_id);
        writes.extend(channel_writes);
        writes.into_iter().for_each(|(key, val)| {
            env.storage.write(&key, val).expect("write error");
        });

        // Start a transaction to send a packet
        let msg =
            ibc::msg_transfer(port_id, channel_id, token.to_string(), &sender);
        let mut tx_data = vec![];
        msg.clone()
            .to_any()
            .encode(&mut tx_data)
            .expect("encoding failed");
        // send a packet with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("sending a packet failed");

        // Commit
        env.write_log.commit_tx();
        env.write_log.commit_block(&mut env.storage).unwrap();

        // Start a transaction to notify the timing-out on closed
        let counterparty = ibc::dummy_channel_counterparty();
        let packet =
            ibc::packet_from_message(&msg, ibc::sequence(1), &counterparty);
        let msg = ibc::msg_timeout_on_close(packet.clone(), ibc::sequence(1));
        let mut tx_data = vec![];
        msg.to_any().encode(&mut tx_data).expect("encoding failed");
        let tx = Tx {
            code: vec![],
            data: Some(tx_data.clone()),
            timestamp: DateTimeUtc::now(),
        };

        // close the channel with the message
        ibc::TestIbcActions
            .dispatch(&tx_data)
            .expect("closing the channel failed");

        // Check
        let (ibc_vp, _) = ibc::init_ibc_vp_from_tx(&env, &tx);
        assert!(
            ibc_vp
                .validate(&tx_data)
                .expect("validation failed unexpectedly")
        );
        // Check if the token was refunded
        let escrow = address::Address::Internal(
            address::InternalAddress::ibc_escrow_address(
                packet.source_port.to_string(),
                packet.source_channel.to_string(),
            ),
        );
        let (token_vp, _) = ibc::init_token_vp_from_tx(&env, &tx, &escrow);
        assert!(
            token_vp
                .validate(&tx_data)
                .expect("token validation failed unexpectedly")
        );
    }
}
