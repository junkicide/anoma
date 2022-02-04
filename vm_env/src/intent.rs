use std::collections::HashSet;

use anoma::types::intent;
use anoma::types::key::*;

/// Tx imports and functions.
pub mod tx {
    pub use anoma::types::intent::*;

    use super::*;
    pub fn invalidate_exchange(intent: &Signed<ed25519c::SigScheme, Exchange>) {
        use crate::imports::tx;
        let key = intent::invalid_intent_key(&intent.data.addr);
        let mut invalid_intent: HashSet<ed25519c::Signature> =
            tx::read(&key.to_string()).unwrap_or_default();
        invalid_intent.insert(intent.sig.clone());
        tx::write(&key.to_string(), &invalid_intent)
    }
}

/// Vp imports and functions.
pub mod vp {
    pub use anoma::types::intent::*;

    use super::*;

    pub fn vp_exchange(intent: &Signed<ed25519c::SigScheme, Exchange>) -> bool {
        use crate::imports::vp;
        let key = intent::invalid_intent_key(&intent.data.addr);

        let invalid_intent_pre: HashSet<ed25519c::Signature> =
            vp::read_pre(&key.to_string()).unwrap_or_default();
        let invalid_intent_post: HashSet<ed25519c::Signature> =
            vp::read_post(&key.to_string()).unwrap_or_default();
        !invalid_intent_pre.contains(&intent.sig)
            && invalid_intent_post.contains(&intent.sig)
    }
}
