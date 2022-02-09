//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell
use super::*;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// INVARIANT: This method must be stateless.
    pub fn verify_header(
        &self,
        _req: shim::request::VerifyHeader,
    ) -> shim::response::VerifyHeader {
        Default::default()
    }

    /// Validate a transaction request. On success, the transaction will
    /// included in the mempool and propagated to peers, otherwise it will be
    /// rejected.
    ///
    /// Checks if the Tx can be deserialized from bytes. Checks the fees and
    /// signatures of the fee payer for a transaction if it is a wrapper tx.
    ///
    /// Checks validity of a decrypted tx or that a tx marked un-decryptable
    /// is in fact so. Also checks that decrypted txs were submitted in
    /// correct order.
    ///
    /// Error codes:
    ///   0: Ok
    ///   1: Invalid tx
    ///   2: Tx is invalidly signed
    ///   3: Wasm runtime error
    ///   4: Invalid order of decrypted txs
    ///   5. More decrypted txs than expected
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if the
    /// proposal is rejected (unless we can simply overwrite them in the
    /// next block).
    pub fn process_proposal(
        &mut self,
        req: shim::request::ProcessProposal,
    ) -> shim::response::ProcessProposal {
        let tx = match Tx::try_from(req.tx.as_ref()) {
            Ok(tx) => tx,
            Err(_) => {
                return shim::response::TxResult {
                    code: ErrorCodes::InvalidTx.into(),
                    info: "The submitted transaction was not deserializable"
                        .into(),
                }
                .into();
            }
        };
        // TODO: This should not be hardcoded
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        match process_tx(tx) {
            // This occurs if the wrapper tx signature is invalid
            Err(err) => TxResult {
                code: ErrorCodes::InvalidSig.into(),
                info: err.to_string(),
            },
            Ok(result) => match result {
                // If it is a raw transaction, we do no further validation
                TxType::Raw(_) => TxResult {
                    code: ErrorCodes::InvalidTx.into(),
                    info: "Transaction rejected: Non-encrypted transactions \
                           are not supported"
                        .into(),
                },
                TxType::Decrypted(tx) => match self.next_wrapper() {
                    Some(wrapper) => {
                        if wrapper.tx_hash != tx.hash_commitment() {
                            TxResult {
                                code: ErrorCodes::InvalidOrder.into(),
                                info: "Process proposal rejected a decrypted \
                                       transaction that violated the tx order \
                                       determined in the previous block"
                                    .into(),
                            }
                        } else if verify_decrypted_correctly(&tx, privkey) {
                            TxResult {
                                code: ErrorCodes::Ok.into(),
                                info: "Process Proposal accepted this \
                                       transaction"
                                    .into(),
                            }
                        } else {
                            TxResult {
                                code: ErrorCodes::InvalidTx.into(),
                                info: "The encrypted payload of tx was \
                                       incorrectly marked as un-decryptable"
                                    .into(),
                            }
                        }
                    }
                    None => TxResult {
                        code: ErrorCodes::ExtraTxs.into(),
                        info: "Received more decrypted txs than expected"
                            .into(),
                    },
                },
                TxType::Wrapper(tx) => {
                    // validate the ciphertext via Ferveo
                    if !tx.validate_ciphertext() {
                        TxResult {
                            code: ErrorCodes::InvalidTx.into(),
                            info: format!(
                                "The ciphertext of the wrapped tx {} is \
                                 invalid",
                                hash_tx(&req.tx)
                            ),
                        }
                    } else {
                        // check that the fee payer has sufficient balance
                        let balance = self
                            .get_balance(&tx.fee.token, &tx.fee_payer())
                            .unwrap_or_default();

                        if tx.fee.amount <= balance {
                            shim::response::TxResult {
                                code: ErrorCodes::Ok.into(),
                                info: "Process proposal accepted this \
                                       transaction"
                                    .into(),
                            }
                        } else {
                            shim::response::TxResult {
                                code: ErrorCodes::InvalidTx.into(),
                                info: "The address given does not have \
                                       sufficient balance to pay fee"
                                    .into(),
                            }
                        }
                    }
                }
            },
        }
        .into()
    }

    /// If we are not using ABCI++, we check the wrapper,
    /// decode it, and check the decoded payload all at once
    #[cfg(feature = "ABCI")]
    pub fn process_and_decode_proposal(
        &mut self,
        req: shim::request::ProcessProposal,
    ) -> shim::response::ProcessProposal {
        // check the wrapper tx
        let req_tx = match Tx::try_from(req.tx.as_ref()) {
            Ok(tx) => tx,
            Err(_) => {
                return shim::response::ProcessProposal {
                    result: shim::response::TxResult {
                        code: ErrorCodes::InvalidTx.into(),
                        info: "The submitted transaction was not \
                               deserializable"
                            .into(),
                    },
                    // this ensures that emitted events are of the correct type
                    tx: req.tx,
                };
            }
        };
        match process_tx(req_tx.clone()) {
            Ok(TxType::Wrapper(_)) => {}
            Ok(_) => {
                return shim::response::ProcessProposal {
                    result: shim::response::TxResult {
                        code: ErrorCodes::InvalidTx.into(),
                        info: "Transaction rejected: Non-encrypted \
                               transactions are not supported"
                            .into(),
                    },
                    // this ensures that emitted events are of the correct type
                    tx: req.tx,
                };
            }
            Err(_) => {
                // This will be caught later
            }
        }

        let mut wrapper_resp = self.process_proposal(req.clone());
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        if wrapper_resp.result.code == 0 {
            // if the wrapper passed, decode it
            if let Ok(TxType::Wrapper(wrapper)) = process_tx(req_tx) {
                let decoded = Tx::from(match wrapper.decrypt(privkey) {
                    Ok(tx) => DecryptedTx::Decrypted(tx),
                    _ => DecryptedTx::Undecryptable(wrapper.clone()),
                })
                .to_bytes();
                // we are not checking that txs are out of order
                self.storage.tx_queue.push(wrapper);
                // check the decoded tx
                let mut decoded_resp =
                    self.process_proposal(shim::request::ProcessProposal {
                        tx: decoded.clone(),
                    });
                // this ensures that emitted events are of the correct type
                if ErrorCodes::from_u32(decoded_resp.result.code).unwrap()
                    == ErrorCodes::Ok
                {
                    decoded_resp.tx = decoded;
                }
                decoded_resp
            } else {
                // This was checked above
                unreachable!()
            }
        } else {
            // this ensures that emitted events are of the correct type
            wrapper_resp.tx = req.tx;
            wrapper_resp
        }
    }

    #[cfg(not(feature = "ABCI"))]
    pub fn revert_proposal(
        &mut self,
        _req: shim::request::RevertProposal,
    ) -> shim::response::RevertProposal {
        Default::default()
    }
}

/// We test the failure cases of [`process_proposal`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_process_proposal {
    use anoma::types::address::xan;
    use anoma::types::key::*;
    use anoma::types::storage::Epoch;
    use anoma::types::token::Amount;
    use anoma::types::transaction::{Fee, Hash};
    use borsh::BorshDeserialize;
    #[cfg(not(feature = "ABCI"))]
    use tendermint_proto::abci::RequestInitChain;
    #[cfg(not(feature = "ABCI"))]
    use tendermint_proto::google::protobuf::Timestamp;
    #[cfg(feature = "ABCI")]
    use tendermint_proto_abci::abci::RequestInitChain;
    #[cfg(feature = "ABCI")]
    use tendermint_proto_abci::google::protobuf::Timestamp;

    use super::*;
    use crate::node::ledger::shell::test_utils::{gen_keypair, TestShell};
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::ProcessProposal;

    /// Test that if a wrapper tx is not signed, it is rejected
    /// by [`process_proposal`].
    #[test]
    fn test_unsigned_wrapper_rejected() {
        let mut shell = TestShell::new();
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        );
        let tx = Tx::new(
            vec![],
            Some(TxType::Wrapper(wrapper).try_to_vec().expect("Test failed")),
        )
        .to_bytes();
        #[allow(clippy::redundant_clone)]
        let request = ProcessProposal { tx: tx.clone() };

        let response = shell.process_proposal(request);
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidSig));
        assert_eq!(
            response.result.info,
            String::from("Expected signed WrapperTx data")
        );
        #[cfg(feature = "ABCI")]
        {
            assert_eq!(response.tx, tx);
            assert!(shell.shell.storage.tx_queue.is_empty())
        }
    }

    /// Test that a wrapper tx with invalid signature is rejected
    #[test]
    fn test_wrapper_bad_signature_rejected() {
        let mut shell = TestShell::new();
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let timestamp = tx.timestamp;
        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        )
        .sign(&keypair)
        .expect("Test failed");
        let new_tx = if let Some(Ok(SignedTxData::<common::SigScheme> {
            data: Some(data),
            sig,
        })) = wrapper
            .data
            .take()
            .map(|data| SignedTxData::try_from_slice(&data[..]))
        {
            let mut new_wrapper = if let TxType::Wrapper(wrapper) =
                <TxType as BorshDeserialize>::deserialize(&mut data.as_ref())
                    .expect("Test failed")
            {
                wrapper
            } else {
                panic!("Test failed")
            };

            // we mount a malleability attack to try and remove the fee
            new_wrapper.fee.amount = 0.into();
            let new_data = TxType::Wrapper(new_wrapper)
                .try_to_vec()
                .expect("Test failed");
            Tx {
                code: vec![],
                data: Some(
                    SignedTxData::<common::SigScheme> {
                        sig,
                        data: Some(new_data),
                    }
                    .try_to_vec()
                    .expect("Test failed"),
                ),
                timestamp,
            }
        } else {
            panic!("Test failed");
        };
        let request = ProcessProposal {
            tx: new_tx.to_bytes(),
        };
        let response = shell.process_proposal(request);
        let expected_error = "Signature verification failed: Invalid signature";
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidSig));
        assert!(
            response.result.info.contains(expected_error),
            "Result info {} doesn't contain the expected error {}",
            response.result.info,
            expected_error
        );
        #[cfg(feature = "ABCI")]
        {
            assert_eq!(response.tx, new_tx.to_bytes());
            assert!(shell.shell.storage.tx_queue.is_empty())
        }
    }

    /// Test that if the account submitting the tx is not known and the fee is
    /// non-zero, [`process_proposal`] rejects that tx
    #[test]
    fn test_wrapper_unknown_address() {
        let mut shell = TestShell::new();
        let keypair = crate::wallet::defaults::keys().remove(0).1;
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 1.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        )
        .sign(&keypair)
        .expect("Test failed");
        let request = ProcessProposal {
            tx: wrapper.to_bytes(),
        };
        let response = shell.process_proposal(request);
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            "The address given does not have sufficient balance to pay fee"
                .to_string(),
        );
        #[cfg(feature = "ABCI")]
        {
            assert_eq!(response.tx, wrapper.to_bytes());
            assert!(shell.shell.storage.tx_queue.is_empty())
        }
    }

    /// Test that if the account submitting the tx does
    /// not have sufficient balance to pay the fee,
    /// [`process_proposal`] rejects that tx
    #[test]
    fn test_wrapper_insufficient_balance_address() {
        let mut shell = TestShell::new();
        shell.init_chain(RequestInitChain {
            time: Some(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
            chain_id: ChainId::default().to_string(),
            ..Default::default()
        });
        let keypair = crate::wallet::defaults::daewon_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: Amount::whole(1_000_100),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        )
        .sign(&keypair)
        .expect("Test failed");

        let request = ProcessProposal {
            tx: wrapper.to_bytes(),
        };

        let response = shell.process_proposal(request);
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "The address given does not have sufficient balance to pay fee"
            )
        );
        #[cfg(feature = "ABCI")]
        {
            assert_eq!(response.tx, wrapper.to_bytes());
            assert!(shell.shell.storage.tx_queue.is_empty())
        }
    }

    #[cfg(not(feature = "ABCI"))]
    /// Test that if the expected order of decrypted txs is
    /// validated, [`process_proposal`] rejects it
    #[test]
    fn test_decrypted_txs_out_of_order() {
        let mut shell = TestShell::new();
        let keypair = gen_keypair();
        let mut txs = vec![];
        for i in 0..3 {
            let tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
            );
            let wrapper = WrapperTx::new(
                Fee {
                    amount: i.into(),
                    token: xan(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                tx.clone(),
            );
            shell.enqueue_tx(wrapper);
            txs.push(Tx::from(TxType::Decrypted(DecryptedTx::Decrypted(tx))));
        }
        let req_1 = ProcessProposal {
            tx: txs[0].to_bytes(),
        };
        let response_1 = shell.process_proposal(req_1);
        assert_eq!(response_1.result.code, u32::from(ErrorCodes::Ok));

        let req_2 = ProcessProposal {
            tx: txs[2].to_bytes(),
        };

        let response_2 = shell.process_proposal(req_2);
        assert_eq!(response_2.result.code, u32::from(ErrorCodes::InvalidOrder));
        assert_eq!(
            response_2.result.info,
            String::from(
                "Process proposal rejected a decrypted transaction that \
                 violated the tx order determined in the previous block"
            ),
        );
    }

    #[cfg(not(feature = "ABCI"))]
    /// Test that a tx incorrectly labelled as undecryptable
    /// is rejected by [`process_proposal`]
    #[test]
    fn test_incorrectly_labelled_as_undecryptable() {
        let mut shell = TestShell::new();
        let keypair = gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        );
        shell.enqueue_tx(wrapper.clone());

        let tx =
            Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(wrapper)));

        let request = ProcessProposal { tx: tx.to_bytes() };

        let response = shell.process_proposal(request);
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "The encrypted payload of tx was incorrectly marked as \
                 un-decryptable"
            ),
        )
    }

    /// Test that undecryptable txs are accepted
    #[test]
    fn test_undecryptable() {
        let mut shell = TestShell::new();
        shell.init_chain(RequestInitChain {
            time: Some(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
            chain_id: ChainId::default().to_string(),
            ..Default::default()
        });
        let keypair = crate::wallet::defaults::daewon_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        );
        wrapper.tx_hash = Hash([0; 32]);

        let tx = if !cfg!(feature = "ABCI") {
            shell.enqueue_tx(wrapper.clone());
            Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
                #[allow(clippy::redundant_clone)]
                wrapper.clone(),
            )))
        } else {
            wrapper.sign(&keypair).expect("Test failed")
        };

        let request = ProcessProposal { tx: tx.to_bytes() };
        let response = shell.process_proposal(request);
        println!("{}", response.result.info);
        assert_eq!(response.result.code, u32::from(ErrorCodes::Ok));
        #[cfg(feature = "ABCI")]
        {
            match process_tx(
                Tx::try_from(response.tx.as_ref()).expect("Test failed"),
            )
            .expect("Test failed")
            {
                TxType::Decrypted(DecryptedTx::Undecryptable(inner)) => {
                    assert_eq!(
                        hash_tx(inner.try_to_vec().unwrap().as_ref()),
                        hash_tx(wrapper.try_to_vec().unwrap().as_ref())
                    );
                    assert!(shell.shell.storage.tx_queue.is_empty())
                }
                _ => panic!("Test failed"),
            }
        }
    }

    #[cfg(not(feature = "ABCI"))]
    /// Test that if more decrypted txs are submitted to
    /// [`process_proposal`] than expected, they are rejected
    #[test]
    fn test_too_many_decrypted_txs() {
        let mut shell = TestShell::new();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );

        let tx = Tx::from(TxType::Decrypted(DecryptedTx::Decrypted(tx)));

        let request = ProcessProposal { tx: tx.to_bytes() };
        let response = shell.process_proposal(request);
        assert_eq!(response.result.code, u32::from(ErrorCodes::ExtraTxs));
        assert_eq!(
            response.result.info,
            String::from("Received more decrypted txs than expected"),
        );
    }

    /// Process Proposal should reject a RawTx, but not panic
    #[test]
    fn test_raw_tx_rejected() {
        let mut shell = TestShell::new();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let tx = Tx::from(TxType::Raw(tx));
        let request = ProcessProposal { tx: tx.to_bytes() };
        let response = shell.process_proposal(request);
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "Transaction rejected: Non-encrypted transactions are not \
                 supported"
            ),
        );
        #[cfg(feature = "ABCI")]
        {
            assert_eq!(response.tx, tx.to_bytes());
        }
    }
}
