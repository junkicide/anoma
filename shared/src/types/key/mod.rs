//! Cryptographic keys

use super::address::Address;
use std::fmt::Display;
use super::storage::{self, DbKeySeg, Key, KeySeg};
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use std::str::FromStr;

use std::hash::{Hash, Hasher};
use std::fmt::Debug;

use crate::types::address;
use sha2::{Digest, Sha256};
use thiserror::Error;

//pub mod ed25519d;
pub mod common;
pub mod secp256k1;
pub mod ed25519c;

const PK_STORAGE_KEY: &str = "public_key";

/// Obtain a storage key for user's public key.
pub fn pk_key(owner: &Address) -> storage::Key {
    Key::from(owner.to_db_key())
        .push(&PK_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Check if the given storage key is a public key. If it is, returns the owner.
pub fn is_pk_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(key)]
            if key == PK_STORAGE_KEY =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Represents an error in signature verification
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum VerifySigError {
    #[error("Signature verification failed: {0}")]
    SigVerifyError(String),
    #[error("Signature verification failed to encode the data: {0}")]
    DataEncodingError(std::io::Error),
    #[error("Transaction doesn't have any data with a signature.")]
    MissingData,
    #[error("Signature belongs to a different scheme from the public key.")]
    MismatchedScheme
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParsePublicKeyError {
    #[error("Invalid public key hex: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("Invalid public key encoding: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Parsed public key does not belong to desired scheme")]
    MismatchedScheme
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParseSignatureError {
    #[error("Invalid signature hex: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("Invalid signature encoding: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Parsed signature does not belong to desired scheme")]
    MismatchedScheme
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParseKeypairError {
    #[error("Invalid keypair hex: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("Invalid keypair encoding: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Parsed key pair does not belong to desired scheme")]
    MismatchedScheme,
    #[error("Given public and secret keys do not form key pair")]
    MismatchedParts,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParseSecretKeyError {
    #[error("Invalid secret key hex: {0}")]
    InvalidHex(hex::FromHexError),
    #[error("Invalid secret key encoding: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Parsed secret key does not belong to desired scheme")]
    MismatchedScheme
}

/// A value-to-value conversion that consumes the input value.

pub trait IntoRef<T>
{
    /// Performs the conversion.
    fn into_ref(&self) -> T;
}

/// Simple and safe type conversions that may fail in a controlled
/// way under some circumstances.

pub trait TryFromRef<T: ?Sized> : Sized {
    /// The type returned in the event of a conversion error.
    type Error;
    /// Performs the conversion.
    fn try_from_ref(value: &T) -> Result<Self, Self::Error>;
}

/// Associates a the given abstract representation to a type

pub trait Repr<U : ?Sized> {
    /// The type that can represent the implementing type
    type T: AsRef<U> + Send + Sync;
    /// The size of the above type
    const LENGTH: usize = 1;
}

/// Type capturing signature scheme IDs
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum SchemeType {
    /// Type identifier for Ed25519-consensus
    Ed25519Consensus,
    /// Type identifier for Secp256k1
    Secp256k1,
    /// Type identifier for Common
    Common,
}

/// Represents a signature

pub trait Signature : Hash
    + PartialOrd
    + IntoRef<<Self as Repr<[u8]>>::T>
    + TryFromRef<[u8], Error = ParseSignatureError>
    + BorshSerialize
    + BorshDeserialize
    + Repr<[u8]> {
        /// The scheme type of this implementation
        const TYPE: SchemeType;
    }

/// Represents a public key

pub trait PublicKey : BorshSerialize
    + BorshDeserialize
    + Ord
    + Clone
    + Display
    + Debug
    + PartialOrd
    + FromStr<Err = ParsePublicKeyError>
    + Hash
    + IntoRef<<Self as Repr<[u8]>>::T>
    + TryFromRef<[u8], Error = ParsePublicKeyError>
    + Repr<[u8]>
    + Send
    + Sync {
        /// The scheme type of this implementation
        const TYPE: SchemeType;
    }

/// Represents a secret key

pub trait SecretKey : BorshSerialize
    + BorshDeserialize
    + Display
    + FromStr<Err = ParseSecretKeyError>
    + IntoRef<<Self as Repr<[u8]>>::T>
    + TryFromRef<[u8], Error = ParseSecretKeyError>
    + Repr<[u8]>
    + Clone {
        /// The scheme type of this implementation
        const TYPE: SchemeType;
    }

/// Represents a keypair

pub trait Keypair : Display
    + IntoRef<(Self::PublicKey, Self::SecretKey)>
    + TryFromRef<(Self::PublicKey, Self::SecretKey), Error = ParseKeypairError>
    + FromStr<Err = ParseKeypairError>
    + IntoRef<<Self as Repr<[u8]>>::T>
    + TryFromRef<[u8], Error = ParseKeypairError>
    + BorshSerialize
    + BorshDeserialize
    + Repr<[u8]>
    + Debug
    + Sync
    + Send
    + Clone {
        /// The scheme type of this implementation
        const TYPE: SchemeType;
        /// Represents the public part of this keypair
        type PublicKey: PublicKey;
        /// Represents the secret part of this keypair
        type SecretKey: SecretKey;
        /// Get the public part of a given key pair
        fn public_part(&self) -> Self::PublicKey {
            IntoRef::<(Self::PublicKey, Self::SecretKey)>::into_ref(self).0
        }
        /// Get the secret part of a given key pair
        fn secret_part(&self) -> Self::SecretKey {
            IntoRef::<(Self::PublicKey, Self::SecretKey)>::into_ref(self).1
        }
    }

/// Represents a digital signature scheme. More precisely this trait captures
/// the concepts of public keys, private keys, and signatures as well as
/// the algorithms over these concepts to generate keys, sign messages, and
/// verify signatures.

pub trait SigScheme : Eq + Ord + Debug + Serialize + Default {
    /// Represents the signature for this scheme
    type Signature: 'static + Signature;
    /// Represents the public key for this scheme
    type PublicKey: 'static + PublicKey;
    /// Represents the secret key for this scheme
    type SecretKey: 'static + SecretKey;
    /// Represents the keypair for this scheme
    type Keypair: 'static + Keypair
        <PublicKey = Self::PublicKey, SecretKey = Self::SecretKey>;
    /// The scheme type of this implementation
    const TYPE: SchemeType;
    /// Generate a keypair.
    #[cfg(feature = "rand")]
    fn generate<R>(csprng: &mut R, sch: SchemeType) -> Option<Self::Keypair>
    where
        R: CryptoRng + RngCore;
    /// Sign the data with a key.
    fn sign(keypair: &Self::Keypair, data: impl AsRef<[u8]>)
    -> Self::Signature;
    /// Check that the public key matches the signature on the given data.
    fn verify_signature<T: BorshSerialize + BorshDeserialize>(
        pk: &Self::PublicKey,
        data: &T,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError>;
    /// Check that the public key matches the signature on the given raw data.
    fn verify_signature_raw(
        pk: &Self::PublicKey,
        data: &[u8],
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError>;
}

/// Shorthand to access byte array type that can represent public key
pub type PublicKeyRep<S> = <<S as SigScheme>::PublicKey as Repr<[u8]>>::T;
/// Shorthand to access byte array type that can represent secret key
pub type SecretKeyRep<S> = <<S as SigScheme>::SecretKey as Repr<[u8]>>::T;
/// Shorthand to access byte array type that can represent signature
pub type SignatureRep<S> = <<S as SigScheme>::Signature as Repr<[u8]>>::T;
/// Shorthand to access byte array type that can represent keypair
pub type KeypairRep<S> = <<S as SigScheme>::Keypair as Repr<[u8]>>::T;

/// Convert from one PublicKey type to another
pub fn try_from_pk<PK: PublicKey, QP: PublicKey>(pk: &PK) -> Result<QP, ParsePublicKeyError> {
    if PK::TYPE == QP::TYPE {
        QP::try_from_ref(pk.into_ref().as_ref())
    } else {
        Err(ParsePublicKeyError::MismatchedScheme)
    }
}

/// Convert from one SecretKey type to another
pub fn try_from_sk<PK: SecretKey, QP: SecretKey>(pk: &PK) -> Result<QP, ParseSecretKeyError> {
    if PK::TYPE == QP::TYPE {
        QP::try_from_ref(pk.into_ref().as_ref())
    } else {
        Err(ParseSecretKeyError::MismatchedScheme)
    }
}

/// Convert from one Keypair type to another
pub fn try_from_kp<PK: Keypair, QP: Keypair>(pk: &PK) -> Result<QP, ParseKeypairError> {
    if PK::TYPE == QP::TYPE {
        let kpu8: <PK as Repr<[u8]>>::T = pk.into_ref();
        QP::try_from_ref(kpu8.as_ref())
    } else {
        Err(ParseKeypairError::MismatchedScheme)
    }
}

/// Convert from one Signature type to another
pub fn try_from_sig<PK: Signature, QP: Signature>(pk: &PK) -> Result<QP, ParseSignatureError> {
    if PK::TYPE == QP::TYPE {
        let kpu8: <PK as Repr<[u8]>>::T = pk.into_ref();
        QP::try_from_ref(kpu8.as_ref())
    } else {
        Err(ParseSignatureError::MismatchedScheme)
    }
}

/// This can be used to sign an arbitrary tx. The signature is produced and
/// verified on the tx data concatenated with the tx code, however the tx code
/// itself is not part of this structure.
///
/// Because the signature is not checked by the ledger, we don't inline it into
/// the `Tx` type directly. Instead, the signature is attached to the `tx.data`,
/// which is can then be checked by a validity predicate wasm.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SignedTxData<S: SigScheme> {
    /// The original tx data bytes, if any
    pub data: Option<Vec<u8>>,
    /// The signature is produced on the tx data concatenated with the tx code
    /// and the timestamp.
    pub sig: S::Signature,
}

/// A generic signed data wrapper for Borsh encode-able data.
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct Signed<S: SigScheme, T: BorshSerialize + BorshDeserialize> {
    /// Arbitrary data to be signed
    pub data: T,
    /// The signature of the data
    pub sig: S::Signature,
}

impl<S, T> PartialEq for Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.sig == other.sig
    }
}

impl<S, T> Eq for Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize + Eq + PartialEq,
{
}

impl<S, T> Hash for Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize + Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.sig.hash(state);
    }
}

impl<S, T> PartialOrd for Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize + PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.data.partial_cmp(&other.data)
    }
}

impl<S, T> Signed<S, T>
where
    S: SigScheme,
    T: BorshSerialize + BorshDeserialize,
{
    /// Initialize a new signed data.
    pub fn new(keypair: &S::Keypair, data: T) -> Self {
        let to_sign = data
            .try_to_vec()
            .expect("Encoding data for signing shouldn't fail");
        let sig = S::sign(keypair, &to_sign);
        Self { data, sig }
    }

    /// Verify that the data has been signed by the secret key
    /// counterpart of the given public key.
    pub fn verify(&self, pk: &S::PublicKey) -> Result<(), VerifySigError> {
        let bytes = self
            .data
            .try_to_vec()
            .expect("Encoding data for verifying signature shouldn't fail");
        S::verify_signature_raw(pk, &bytes, &self.sig)
    }
}

/// Ed25519 public key hash
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct PublicKeyHash(pub(crate) String);

const PKH_HASH_LEN: usize = address::HASH_LEN;


impl From<PublicKeyHash> for String {
    fn from(pkh: PublicKeyHash) -> Self {
        pkh.0
    }
}

impl Display for PublicKeyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PublicKeyHash {
    type Err = PkhFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PKH_HASH_LEN {
            return Err(Self::Err::UnexpectedLen(s.len()));
        }
        Ok(Self(s.to_owned()))
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum PkhFromStringError {
    #[error("Wrong PKH len. Expected {PKH_HASH_LEN}, got {0}")]
    UnexpectedLen(usize),
}

impl<PK: PublicKey> From<&PK> for PublicKeyHash {
    fn from(pk: &PK) -> Self {
        let pk_bytes =
            pk.try_to_vec().expect("Public key encoding shouldn't fail");
        let mut hasher = Sha256::new();
        hasher.update(pk_bytes);
        // hex of the first 40 chars of the hash
        PublicKeyHash(format!(
            "{:.width$X}",
            hasher.finalize(),
            width = PKH_HASH_LEN
        ))
    }
}

/// Helpers for testing with keys.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::prelude::*;
    use rand::prelude::{StdRng, ThreadRng};
    use rand::{thread_rng, SeedableRng};
    use crate::types::key::ed25519c;
    use super::{SigScheme, SchemeType, TryFromRef};

    /// A keypair for tests
    pub fn keypair_1() -> <ed25519c::SigScheme as SigScheme>::Keypair {
        // generated from `cargo test gen_keypair -- --nocapture`
        let bytes = [
            33, 82, 91, 186, 100, 168, 220, 158, 185, 140, 63, 172, 3, 88, 52,
            113, 94, 30, 213, 84, 175, 184, 235, 169, 70, 175, 36, 252, 45,
            190, 138, 79, 210, 187, 198, 90, 69, 83, 156, 77, 199, 63, 208, 63,
            137, 102, 22, 229, 110, 195, 38, 174, 142, 127, 157, 224, 139, 212,
            239, 204, 58, 80, 108, 184,
        ];
        <ed25519c::SigScheme as SigScheme>::Keypair::try_from_ref(bytes.as_ref()).unwrap().into()
    }

    /// A keypair for tests
    pub fn keypair_2() -> <ed25519c::SigScheme as SigScheme>::Keypair {
        // generated from `cargo test gen_keypair -- --nocapture`
        let bytes = [
            27, 238, 157, 32, 131, 242, 184, 142, 146, 189, 24, 249, 68, 165,
            205, 71, 213, 158, 25, 253, 52, 217, 87, 52, 171, 225, 110, 131,
            238, 58, 94, 56, 218, 133, 189, 80, 14, 157, 68, 124, 151, 37, 127,
            173, 117, 91, 248, 234, 34, 13, 77, 148, 10, 75, 30, 191, 172, 85,
            175, 8, 36, 233, 18, 203,
        ];
        <ed25519c::SigScheme as SigScheme>::Keypair::try_from_ref(bytes.as_ref()).unwrap().into()
    }

    /// Generate an arbitrary [`Keypair`].
    pub fn arb_keypair<S: SigScheme>(id: SchemeType) -> impl Strategy<Value = S::Keypair> {
        any::<[u8; 32]>().prop_map(move |seed| {
            let mut rng = StdRng::from_seed(seed);
            S::generate(&mut rng, id).unwrap().into()
        })
    }

    /// Generate a new random [`Keypair`].
    pub fn gen_keypair<S: SigScheme>(id: SchemeType) -> S::Keypair {
        let mut rng: ThreadRng = thread_rng();
        S::generate(&mut rng, id).unwrap()
    }
}

#[cfg(test)]
macro_rules! sigscheme_test {
    ($name:ident, $type:ty, $sid:expr) => {
        pub mod $name {
            use super::*;

            /// Run `cargo test gen_keypair -- --nocapture` to generate a keypair.
            #[test]
            fn gen_keypair0() {
                use rand::prelude::ThreadRng;
                use rand::thread_rng;

                let mut rng: ThreadRng = thread_rng();
                let keypair = <$type>::generate(&mut rng, $sid).unwrap();
                let bytes: KeypairRep<$type> = keypair.into_ref();
                println!(
                    "keypair {:?}",
                    bytes
                );
            }
            /// Run `cargo test gen_keypair -- --nocapture` to generate a
            /// new keypair.
            #[test]
            fn gen_keypair1() {
                let keypair = testing::gen_keypair::<$type>($sid);
                let (public_key, secret_key) = keypair.into_ref();
                println!("Public key: {}", public_key);
                println!("Secret key: {}", secret_key);
            }
        }
    }
}

#[cfg(test)]
sigscheme_test!{ed25519_test, ed25519c::SigScheme, ed25519c::SigScheme::TYPE}
#[cfg(test)]
sigscheme_test!{common_ed25519_test, common::SigScheme, ed25519c::SigScheme::TYPE}
#[cfg(test)]
sigscheme_test!{secp256k1_test, secp256k1::SigScheme, secp256k1::SigScheme::TYPE}
#[cfg(test)]
sigscheme_test!{common_secp256k1_test, common::SigScheme, secp256k1::SigScheme::TYPE}
