//! Signature labels: the type label at the start of every signature input (FS-13).

use crate::label::labels::labels;

labels! {
    /// A label of the `sig/` class, naming one kind of signed structure.
    SigLabel, "sig",
    /// The vault config, signed by the master key.
    Config => "config",
    /// A device certificate, signed by the master key.
    DeviceCert => "device-cert",
    /// A device's proof of possession of its key.
    DevicePop => "device-pop",
    /// The device set, signed by the master key.
    DeviceSet => "device-set",
    /// A vault root, signed by a device.
    Root => "root",
    /// An object manifest, signed by a device.
    Manifest => "manifest",
    /// A genome log entry, signed by a device (P3).
    LogEntry => "log-entry",
    /// A snapshot root (P3).
    Snapshot => "snapshot",
    /// A device wrap of an epoch KEK (P4).
    EpochDeviceWrap => "epoch-device-wrap",
}
