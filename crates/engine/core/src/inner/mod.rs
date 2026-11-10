//! The inner plaintext of a data blob: `comp ‖ rsv ‖ u32be payload_len ‖ payload ‖ zero pad`,
//! padded to its Padmé length (FS-54).

mod comp;
mod decode_inner;
mod encode_inner;
mod inner_view;

pub use comp::Comp;
pub use decode_inner::decode_inner;
pub use encode_inner::encode_inner;
pub use inner_view::InnerView;
