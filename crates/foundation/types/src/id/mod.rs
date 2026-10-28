//! IDs and counters (format spec section 4.1).
//!
//! Random IDs are generated in `crypthix-crypto` (FS-01); this module only checks and formats
//! them. Equality is plain byte equality: comparisons that decide authenticity run in constant
//! time inside `crypthix-crypto` (FS-15).

mod counter;
mod fixed_id;
pub(crate) mod hex;
mod parse_id_error;

pub(crate) use counter::parse_decimal;
pub use counter::{CertSeq, ConfigSeq, DeviceSetSeq, Epoch, KeyringGen, LogSeq, ObjectVersion};
pub use counter::{RootSeq, ShareSetVersion};
pub use fixed_id::{BlobId, DekId, DeviceId, KeyId, ObjectId, PackId, ShardId, ShareSetId};
pub use fixed_id::{SenderId, SlotId, VaultId, VaultNonce};
pub use parse_id_error::ParseIdError;
