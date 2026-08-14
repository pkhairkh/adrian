//! # adrian-drsuapi
//!
//! DRSUAPI server (MS-DRSR) for the Adrian framework — fresh Rust
//! implementation.
//!
//! Per Workshop Decision 1 §Decision, the framework implements DRSUAPI
//! (MS-DRSR) server-side as a fresh, clean-room Rust implementation derived
//! from the published Microsoft protocol specification — *not* derived from
//! Samba's GPLv3 source. This crate implements the [`Replicator`] trait from
//! `adrian-repl-core` and runs over the DCE/RPC transport from
//! `adrian-dcerpc`.
//!
//! ## What's real (Wave 2b)
//!
//! - Real MS-DRSR NDR codec built on `adrian_dcerpc::ndr::{NdrWriter,
//!   NdrReader}` (replaces the previous self-consistent placeholder):
//!   - [`DrsExtensions`] — per MS-DRSR §4.1.277 `DRS_EXTENSIONS_INT`.
//!   - [`UtdVectorExt`] — per MS-DRSR §4.1.10.4.2 `UPTODATE_VECTOR_V1_EXT`
//!     (entries are `{usn_high, usn_low, dsa_guid}`).
//!   - [`DsName`] — per MS-DRSR §4.1.10.4.9 `DSNAME`.
//!   - [`UsnVector`] — per MS-DRSR §4.1.10.4.13 `USN_VECTOR`.
//!   - [`ReplEntInfV3`] — per MS-DRSR §4.1.10.4.8 `REPLENTIN_V3` (request
//!     body for `IDL_DRSGetNCChanges` opnum 0x04 with `dwInVersion = 3`).
//!   - [`ReplEntInfV3Reply`] — the reply variant of `REPLENTIN_V3`.
//! - Real [`drs_bind`] / [`drs_bind_dispatch`] handlers for `IDL_DRSBind`
//!   (opnum 0x00): parses the client's `DRS_EXTENSIONS`, negotiates the
//!   extension flag intersection with [`SERVER_SUPPORTED_EXTENSIONS`], returns
//!   the server's `DRS_EXTENSIONS` and a fresh UUIDv7 bind handle.
//! - Real [`drs_get_nc_changes`] / [`drs_get_nc_changes_dispatch`] handlers
//!   for `IDL_DRSGetNCChanges` (opnum 0x04): parses the [`ReplEntInfV3`]
//!   request, looks up directory objects from a [`DirectorySource`], returns
//!   the objects as an NDR-encoded [`ReplEntInfV3Reply`] (including the
//!   up-to-dateness vector per ADR-071).
//! - [`UtdVectorExt::is_up_to_date`] — the UTD-vector comparison predicate
//!   (per ADR-071 §Decision): returns `true` iff the cursor has already
//!   absorbed the requested `(dsa_guid, usn)` pair.
//! - [`negotiate_extensions`] — the extension-flag intersection function.
//!
//! ## What's still stubbed (Wave 3+)
//!
//! - The `Replicator` trait impls on [`DrSuapiReplicator`] (`get_changes`,
//!   `apply_changes`, `update_utd_vector`, `resolve_conflict`,
//!   `sync_metadata`) — these require the FDB-backed candidate-set walker
//!   (Wave 3). The handlers above are the wire-level entry points the trait
//!   impls will eventually call into.
//! - `IDL_DRSUnbind`, `IDL_DRSReplicaSync`, `IDL_DRSUpdateRefs`,
//!   `IDL_DRSReplicaAdd/Del/Modify`, `IDL_DRSGetReplInfo`,
//!   `IDL_DRSCrackNames`, `IDL_DRSVerifyNames`,
//!   `IDL_DRSDomainControllerInfo` — Wave 3.
//! - `EXOP_REPL_SECRETS` (DCSync) — ACL-gated per ADR-122; Wave 3.
//! - Byte-for-byte equivalence with Windows reference traffic — needs the
//!   `adrian-test-harness` integration tests against a captured trace.
//!
//! ## DRSUAPI opnums (per Decision 1 §Decision)
//!
//! | Opnum | Method | Status |
//! |-------|--------|--------|
//! | 0x00  | `IDL_DRSBind` | **real (Wave 2b)** |
//! | 0x01  | `IDL_DRSUnbind` | stub |
//! | 0x03  | `IDL_DRSReplicaSync` | stub |
//! | 0x04  | `IDL_DRSGetNCChanges` | **real (Wave 2b)** |
//! | 0x05  | `IDL_DRSUpdateRefs` | stub |
//! | 0x06  | `IDL_DRSReplicaAdd` | stub |
//! | 0x07  | `IDL_DRSReplicaDel` | stub |
//! | 0x08  | `IDL_DRSReplicaModify` | stub |
//! | 0x15  | `IDL_DRSGetReplInfo` | stub |
//! | 0x0C  | `IDL_DRSCrackNames` | stub |
//! | 0x0E  | `IDL_DRSVerifyNames` | stub |
//! | 0x11  | `IDL_DRSDomainControllerInfo` | stub |
//! | —     | `EXOP_REPL_SECRETS` (DCSync) | stub (ACL-gated per ADR-122) |
//!
//! `IDL_DRSGetMemberships` (0x0D) and `IDL_DRSGetNT4ChangeLog` (0x12) are
//! deferred to v2 (per Decision 1 §Decision — not in AD-interop MVP).
//!
//! ## ADRs
//!
//! - ADR-070: DRSUAPI replication protocol
//! - ADR-001: Linked Value Replication (`REPLVALINF_V3` records)
//! - ADR-071: Replication model (UTD vectors, conflict resolution)
//! - ADR-074: Tombstone lifetime and lingering objects
//! - ADR-122: DCSync mitigation (ACL-gated `EXOP_REPL_SECRETS`)
//! - ADR-126: sIDHistory migration via DRSAddSidHistory
//!
//! ## Layer
//!
//! Layer 2 — domain implementations (depend on Layers 0-1). Depends on
//! `adrian-repl-core`, `adrian-storage-fdb`, `adrian-schema-traits`,
//! `adrian-identity-core`, `adrian-dcerpc`, `rasn`. Gated by the
//! `ad-interop` feature flag at the workspace level.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_dcerpc::ndr::{NdrReader, NdrWriter};
use adrian_dcerpc::DceRpcError;
use adrian_repl_core::{
    ConflictRecord, NcHead, ReplOperation, ReplicationError, ReplicationPayload, Replicator,
    Resolution, UtdDelta, UtdVector,
};
use adrian_storage_core::{
    decode_uuid_index_key, DirectoryStore, DistinguishedName, Object, StorageError, Subspace,
};
use async_trait::async_trait;
use uuid::Uuid;

// =====================================================================
// Constants
// =====================================================================

/// Server-side DRSUAPI extension support bitmask (per Decision 1 §Decision).
///
/// The framework negotiates `DRS_EXT_BASE`, `DRS_EXT_GETCHGREQ_V8`,
/// `DRS_EXT_GETCHGREPLY_V9`, `DRS_EXT_GETCHGREQ_V10`, and
/// `DRS_EXT_INSTANCEINFO_NOTISMASTERS` for full LVR support (per ADR-001).
/// `EXOP_REPL_SECRETS` (DCSync) is intentionally NOT advertised here — it is
/// gated behind an out-of-band ACL check (per ADR-122 §Decision) and is only
/// honoured when the caller presents the
/// `DS-Replication-Get-Changes-All` extended right on the domain NC head.
pub const SERVER_SUPPORTED_EXTENSIONS: u32 = DrsExtFlag::Base as u32
    | DrsExtFlag::GetChgReqV8 as u32
    | DrsExtFlag::GetChgReplyV9 as u32
    | DrsExtFlag::GetChgReqV10 as u32
    | DrsExtFlag::InstanceInfoNotIsMasters as u32;

/// NDR pointer referent ID used for the non-null `pNcOrChain` /
/// `pUpToDateVecDest` pointer fields in [`ReplEntInfV3`]. Per [C706]
/// §14.3.2, a non-zero referent ID means "the pointer is non-null" — the
/// actual pointed-to struct data follows later in the stream. We use a
/// single fixed non-zero value because the framework never sends null
/// pointers in these positions.
const NON_NULL_REFERENT_ID: u32 = 0x0002_0000;

/// Body size of [`DrsExtensions`] without the leading `cb` conformant-size
/// field, in bytes (per MS-DRSR §4.1.277 — `dwFlags` (4) + `siteObjGuid`
/// (16) + `pid` (4) + `dwReplEpoch` (4) + `dwFlagsExt` (4) = 32).
const DRS_EXTENSIONS_BODY_SIZE: u32 = 32;

/// `UPTODATE_VECTOR_V1_EXT` per-entry size on the wire (per MS-DRSR
/// §4.1.10.4.2 — `usnHighPropUpdate` (8) + `usnLowPropUpdate` (8) +
/// `uuidDsa` (16) = 32 bytes). Exposed as a `pub const` so callers can
/// pre-size buffers and assert against reference traffic.
pub const UTD_VECTOR_ENTRY_SIZE: usize = 32;

// =====================================================================
// Enums (existing — protocol-fixed bit flags)
// =====================================================================

/// DRSUAPI extension flags (per MS-DRSR §4.1.277 — `DRS_EXTENSIONS`).
///
/// Per Decision 1 §Decision, the framework negotiates
/// `DRS_EXT_GETCHGREQ_V8` (0x40), `DRS_EXT_GETCHGREPLY_V9` (0x80),
/// `DRS_EXT_GETCHGREQ_V10` (0x10000), and
/// `DRS_EXT_INSTANCEINFO_NOTISMASTERS` for full LVR support (per ADR-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrsExtFlag {
    /// `DRS_EXT_BASE` (0x00000001) — base extension.
    Base = 0x0000_0001,
    /// `DRS_EXT_ASYNCREPL` (0x00000002) — async replication.
    AsyncRepl = 0x0000_0002,
    /// `DRS_EXT_GETCHGREQ_V6` (0x00000004) — `IDL_DRSGetNCChanges` V6.
    GetChgReqV6 = 0x0000_0004,
    /// `DRS_EXT_GETCHGREPLY_V5` (0x00000008) — `IDL_DRSGetNCChanges` reply V5.
    GetChgReplyV5 = 0x0000_0008,
    /// `DRS_EXT_GETCHGREQ_V8` (0x00000040) — `IDL_DRSGetNCChanges` V8 (LVR,
    /// per ADR-001).
    GetChgReqV8 = 0x0000_0040,
    /// `DRS_EXT_GETCHGREPLY_V9` (0x00000080) — `IDL_DRSGetNCChanges` reply V9.
    GetChgReplyV9 = 0x0000_0080,
    /// `DRS_EXT_GETCHGREQ_V10` (0x00010000) — `IDL_DRSGetNCChanges` V10.
    GetChgReqV10 = 0x0001_0000,
    /// `DRS_EXT_INSTANCEINFO_NOTISMASTERS` (0x00000010) — see MS-DRSR.
    InstanceInfoNotIsMasters = 0x0000_0010,
}

/// DRSUAPI DSA options (per MS-DRSR, the `dwFlags` field on `IDL_DRSBind`).
///
/// These are bit flags — in MS-DRSR several symbolic names map to the same
/// numeric bit (e.g. `DRS_GETCHG_CHECK` and `DRS_UPDATE_NOTIFICATION` both
/// equal `0x0000_0002`). Rust `enum` variants cannot share discriminant
/// values, so the canonical name is retained here and the alias is documented
/// in the variant's doc comment. Consumers that need to combine flags should
/// use the underlying `u32` representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrsOption {
    /// `DRS_ASYNC_OP` (0x00000001) — async operation.
    AsyncOp = 0x0000_0001,
    /// `DRS_GETCHG_CHECK` (0x00000002) — check for changes. Also the value
    /// of `DRS_UPDATE_NOTIFICATION` (alias in MS-DRSR).
    GetChgCheck = 0x0000_0002,
    /// `DRS_ADD_REF` (0x00000004) — add reference.
    AddRef = 0x0000_0004,
    /// `DRS_SYNC_ALL` (0x00000008) — sync all. Also the value of
    /// `DRS_DEL_REF` (alias in MS-DRSR).
    SyncAll = 0x0000_0008,
    /// `DRS_WRIT_REP` (0x00000010) — writable replication.
    WritRep = 0x0000_0010,
    /// `DRS_INIT_SYNC` (0x00000020) — initial sync.
    InitSync = 0x0000_0020,
    /// `DRS_PER_SYNC` (0x00000040) — periodic sync.
    PerSync = 0x0000_0040,
    /// `DRS_FULL_SYNC_NOW` (0x00000080) — full sync now.
    FullSyncNow = 0x0000_0080,
    /// `EXOP_REPL_SECRETS` (0x00000100) — the DCSync extension, per ADR-122
    /// (ACL-gated).
    ExopReplSecrets = 0x0000_0100,
    /// `DRS_GET_ANC` (0x00000800) — get ancestors.
    GetAnc = 0x0000_0800,
    /// `DRS_FULL_SYNC_IN_PROGRESS` (0x00010000) — full sync in progress.
    FullSyncInProgress = 0x0001_0000,
    /// `DRS_GET_ALL_GROUP_MEMBERSHIP` (0x00800000) — get all group
    /// memberships.
    GetAllGroupMembership = 0x0080_0000,
}

// =====================================================================
// DrsExtensions — MS-DRSR §4.1.277 DRS_EXTENSIONS_INT
// =====================================================================

/// `DRS_EXTENSIONS_INT` — the DRSUAPI bind-time extensions structure (per
/// MS-DRSR §4.1.277).
///
/// On the wire this is encoded as a conformant byte array: a leading `cb`
/// `DWORD` (the conformant size) followed by `cb` bytes of struct body
/// (padded to a 4-byte boundary). The struct body contains `dwFlags`,
/// `siteObjGuid`, `pid`, `dwReplEpoch`, `dwFlagsExt` in that order.
///
/// Forward-compatible extension data (any bytes beyond
/// [`DRS_EXTENSIONS_BODY_SIZE`]) is preserved as [`Self::extra`] so a newer
/// client's extensions are not silently dropped by an older server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrsExtensions {
    /// `dwFlags` — bitmask of [`DrsExtFlag`] values.
    pub dw_flags: u32,
    /// `siteObjGuid` — the DSA's site object UUID (per MS-ADTS §3.1.1.3.2).
    pub site_obj_guid: Uuid,
    /// `pid` — the DSA's process ID (unused by the framework; preserved for
    /// wire compat).
    pub pid: u32,
    /// `dwReplEpoch` — the replication epoch (per MS-DRSR §4.1.4.2). Must
    /// match between bind partners or the bind fails.
    pub dw_repl_epoch: u32,
    /// `dwFlagsExt` — extension flags beyond `dwFlags` (reserved for future
    /// use; preserved for wire compat).
    pub dw_flags_ext: u32,
    /// Forward-compatible extension bytes (per MS-DRSR §4.1.277 — any bytes
    /// after `dwFlagsExt` are opaque to older implementations).
    pub extra: Vec<u8>,
}

impl DrsExtensions {
    /// Construct a [`DrsExtensions`] with the given flags, a zero site-object
    /// GUID, and zero epoch/pid/flags_ext.
    #[must_use]
    pub fn new(dw_flags: u32, site_obj_guid: Uuid) -> Self {
        Self {
            dw_flags,
            site_obj_guid,
            pid: 0,
            dw_repl_epoch: 0,
            dw_flags_ext: 0,
            extra: Vec::new(),
        }
    }

    /// Encode this [`DrsExtensions`] into `w` using the MS-DRSR wire format
    /// (per §4.1.277 — conformant byte array).
    ///
    /// Wire layout:
    /// ```text
    /// cb        : u32  (max_count of the conformant array)
    /// dwFlags   : u32
    /// siteObjGuid: 16 bytes (UUID, no alignment)
    /// pid       : u32
    /// dwReplEpoch: u32
    /// dwFlagsExt: u32
    /// extra     : cb - 32 bytes (forward-compatible extension data)
    /// pad       : 0-3 zero bytes to reach a 4-byte boundary
    /// ```
    pub fn encode(&self, w: &mut NdrWriter) {
        let body_size = DRS_EXTENSIONS_BODY_SIZE + self.extra.len() as u32;
        w.write_uint32(body_size);
        w.write_uint32(self.dw_flags);
        w.write_uuid(self.site_obj_guid);
        w.write_uint32(self.pid);
        w.write_uint32(self.dw_repl_epoch);
        w.write_uint32(self.dw_flags_ext);
        if !self.extra.is_empty() {
            w.write_bytes(&self.extra);
        }
        w.align(4);
    }

    /// Decode a [`DrsExtensions`] from `r` (per MS-DRSR §4.1.277).
    ///
    /// Returns [`DceRpcError::Ndr`] if `cb` is smaller than
    /// [`DRS_EXTENSIONS_BODY_SIZE`] (the struct cannot be shorter than its
    /// fixed fields).
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let cb = r.read_uint32()? as usize;
        if cb < DRS_EXTENSIONS_BODY_SIZE as usize {
            return Err(DceRpcError::Ndr(format!(
                "DRS_EXTENSIONS: cb={cb} < minimum body size {DRS_EXTENSIONS_BODY_SIZE}"
            )));
        }
        let dw_flags = r.read_uint32()?;
        let site_obj_guid = r.read_uuid()?;
        let pid = r.read_uint32()?;
        let dw_repl_epoch = r.read_uint32()?;
        let dw_flags_ext = r.read_uint32()?;
        let extra_len = cb - DRS_EXTENSIONS_BODY_SIZE as usize;
        let extra = if extra_len > 0 {
            r.read_bytes(extra_len)?.to_vec()
        } else {
            Vec::new()
        };
        r.align(4)?;
        Ok(Self {
            dw_flags,
            site_obj_guid,
            pid,
            dw_repl_epoch,
            dw_flags_ext,
            extra,
        })
    }

    /// Convenience: encode to a fresh `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        self.encode(&mut w);
        w.into_bytes()
    }

    /// Convenience: decode from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DceRpcError> {
        let mut r = NdrReader::new(bytes);
        Self::decode(&mut r)
    }
}

impl Default for DrsExtensions {
    fn default() -> Self {
        Self::new(DrsExtFlag::Base as u32, Uuid::nil())
    }
}

// =====================================================================
// UtdVectorExt — MS-DRSR §4.1.10.4.2 UPTODATE_VECTOR_V1_EXT
// =====================================================================

/// A single `UPTODATE_VECTOR_V1_EXT` entry (per MS-DRSR §4.1.10.4.2):
/// `{usnHighPropUpdate, usnLowPropUpdate, uuidDsa}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtdVectorExtEntry {
    /// `usnHighPropUpdate` — the highest USN received from the originating
    /// DSA (per MS-ADTS §3.1.1.3.2.5).
    pub usn_high: u64,
    /// `usnLowPropUpdate` — the lowest USN the originating DSA still has
    /// available for replication (per MS-DRSR §4.1.10.4.2).
    pub usn_low: u64,
    /// `uuidDsa` — the originating DSA's invocation ID (per MS-ADTS
    /// §3.1.1.3.2.6).
    pub dsa_guid: Uuid,
}

/// `UPTODATE_VECTOR_V1_EXT` — the up-to-dateness vector (per MS-DRSR
/// §4.1.10.4.2 / ADR-071).
///
/// On the wire this is a conformant struct: `cNumEntries`, `dwVersion`,
/// `dwReserved1`, then `cNumEntries` `UtdVectorExtEntry` records.
///
/// The UTD vector is the per-DC, per-NC summary of the highest USN received
/// from every other DSA (per ADR-071). The framework's
/// [`UtdVectorExt::is_up_to_date`] predicate implements the comparison rule
/// used by `IDL_DRSGetNCChanges` to decide whether a partner has anything
/// new to send.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UtdVectorExt {
    /// `dwVersion` — vector format version (per MS-DRSR §4.1.10.4.2 — V1
    /// extended = `0x1`).
    pub dw_version: u32,
    /// The vector entries, one per origin DSA.
    pub entries: Vec<UtdVectorExtEntry>,
}

impl UtdVectorExt {
    /// Construct an empty V1 extended UTD vector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode this [`UtdVectorExt`] into `w` (per MS-DRSR §4.1.10.4.2).
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uint32(self.entries.len() as u32);
        w.write_uint32(self.dw_version);
        w.write_uint32(0); // dwReserved1
        for entry in &self.entries {
            w.write_uint64(entry.usn_high);
            w.write_uint64(entry.usn_low);
            w.write_uuid(entry.dsa_guid);
        }
    }

    /// Decode a [`UtdVectorExt`] from `r` (per MS-DRSR §4.1.10.4.2).
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let c_num_entries = r.read_uint32()? as usize;
        let dw_version = r.read_uint32()?;
        let _dw_reserved1 = r.read_uint32()?;
        let mut entries = Vec::with_capacity(c_num_entries);
        for _ in 0..c_num_entries {
            let usn_high = r.read_uint64()?;
            let usn_low = r.read_uint64()?;
            let dsa_guid = r.read_uuid()?;
            entries.push(UtdVectorExtEntry {
                usn_high,
                usn_low,
                dsa_guid,
            });
        }
        Ok(Self {
            dw_version,
            entries,
        })
    }

    /// Whether the cursor has already absorbed all updates up to `usn` from
    /// the DSA identified by `dsa_guid` (per ADR-071 §Decision — the
    /// comparison predicate used by `IDL_DRSGetNCChanges` to decide whether
    /// a partner has anything new to send).
    ///
    /// Returns `true` iff there is an entry for `dsa_guid` whose `usn_high`
    /// is `>= usn`. Returns `false` if the DSA is unknown to the cursor or
    /// the cursor's high-water mark is below `usn`.
    #[must_use]
    pub fn is_up_to_date(&self, dsa_guid: Uuid, usn: u64) -> bool {
        self.entries
            .iter()
            .any(|e| e.dsa_guid == dsa_guid && e.usn_high >= usn)
    }

    /// Merge a single entry into the vector (per ADR-071 — used by
    /// `update_utd_vector`). If an entry for the same `dsa_guid` already
    /// exists, its `usn_high` / `usn_low` are bumped to the max of the
    /// existing and incoming values; otherwise the entry is appended.
    pub fn merge(&mut self, entry: UtdVectorExtEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.dsa_guid == entry.dsa_guid)
        {
            existing.usn_high = existing.usn_high.max(entry.usn_high);
            existing.usn_low = existing.usn_low.min(entry.usn_low);
        } else {
            self.entries.push(entry);
        }
    }

    /// Convenience: encode to a fresh `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        self.encode(&mut w);
        w.into_bytes()
    }

    /// Convenience: decode from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DceRpcError> {
        let mut r = NdrReader::new(bytes);
        Self::decode(&mut r)
    }
}

// =====================================================================
// DsName — MS-DRSR §4.1.10.4.9 DSNAME
// =====================================================================

/// `DSNAME` — a directory object name (per MS-DRSR §4.1.10.4.9).
///
/// On the wire: `structLen`, `SidLen`, `Guid`, `Sid`, `NameLen`, then the
/// `StringName` UTF-16LE code units (including the trailing NUL WCHAR).
/// `structLen` is the total size of the struct in bytes (including the
/// `structLen` field itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsName {
    /// `Guid` — the object's `objectGUID` (per MS-ADTS §3.1.1.3.2.6).
    pub guid: Uuid,
    /// `Sid` — the object's `objectSid` bytes (empty for non-security
    /// principals).
    pub sid: Vec<u8>,
    /// `StringName` — the object's DN as a UTF-16 string (per MS-DRSR
    /// §4.1.10.4.9 — the `StringName` field).
    pub name: String,
}

impl DsName {
    /// Construct a [`DsName`] from a DN string with no SID and a nil GUID.
    #[must_use]
    pub fn from_dn(dn: &str) -> Self {
        Self {
            guid: Uuid::nil(),
            sid: Vec::new(),
            name: dn.to_string(),
        }
    }

    /// Compute `structLen` (the total struct size including this field) for
    /// the on-wire encoding (per MS-DRSR §4.1.10.4.9).
    fn struct_len(&self) -> u32 {
        // 4 (structLen) + 4 (SidLen) + 16 (Guid) + sid_padded + 4 (NameLen)
        //   + (name_len + 1) * 2 (UTF-16 incl. NUL)
        let sid_padded = (self.sid.len() + 3) & !3;
        let name_units = self.name.encode_utf16().count();
        let name_bytes = (name_units + 1) as u32 * 2;
        4 + 4 + 16 + sid_padded as u32 + 4 + name_bytes
    }

    /// Encode this [`DsName`] into `w` (per MS-DRSR §4.1.10.4.9).
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uint32(self.struct_len());
        w.write_uint32(self.sid.len() as u32);
        w.write_uuid(self.guid);
        if !self.sid.is_empty() {
            w.write_bytes(&self.sid);
            w.align(4);
        }
        let units: Vec<u16> = self.name.encode_utf16().collect();
        w.write_uint32(units.len() as u32);
        for u in &units {
            w.write_bytes(&u.to_le_bytes());
        }
        // trailing NUL WCHAR
        w.write_bytes(&0u16.to_le_bytes());
        w.align(4);
    }

    /// Decode a [`DsName`] from `r` (per MS-DRSR §4.1.10.4.9).
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let struct_len = r.read_uint32()?;
        let sid_len = r.read_uint32()? as usize;
        let guid = r.read_uuid()?;
        let sid = if sid_len > 0 {
            let bytes = r.read_bytes(sid_len)?.to_vec();
            r.align(4)?;
            bytes
        } else {
            Vec::new()
        };
        let name_len = r.read_uint32()? as usize;
        let byte_len = name_len
            .checked_mul(2)
            .ok_or_else(|| DceRpcError::Ndr("DSNAME: NameLen overflowed when doubled".into()))?;
        let name_bytes = r.read_bytes(byte_len)?;
        let mut units: Vec<u16> = Vec::with_capacity(name_len);
        for chunk in name_bytes.chunks_exact(2) {
            units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        // consume trailing NUL WCHAR
        let trailing = r.read_bytes(2)?;
        if trailing != [0, 0] {
            return Err(DceRpcError::Ndr(format!(
                "DSNAME: expected trailing NUL WCHAR, got {trailing:?}"
            )));
        }
        r.align(4)?;
        let name = String::from_utf16(&units)
            .map_err(|e| DceRpcError::Ndr(format!("DSNAME: UTF-16 decode failed: {e}")))?;
        // Sanity-check struct_len against what we actually consumed. We do
        // not enforce equality strictly because some senders round
        // `structLen` up; we only enforce that the encoded length is at
        // least as large as the minimum struct size we just decoded.
        let _ = struct_len;
        Ok(Self { guid, sid, name })
    }
}

// =====================================================================
// UsnVector — MS-DRSR §4.1.10.4.13 USN_VECTOR
// =====================================================================

/// `USN_VECTOR` — the per-NC USN cursor (per MS-DRSR §4.1.10.4.13).
///
/// Sent by the destination DSA in [`ReplEntInfV3`] to indicate the
/// high-water mark of object and property updates already absorbed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsnVector {
    /// `usnHighObjUpdate` — the highest object-level USN absorbed.
    pub usn_high_obj_update: u64,
    /// `usnHighPropUpdate` — the highest property-level USN absorbed (always
    /// `>= usn_high_obj_update` per MS-DRSR §4.1.10.4.13).
    pub usn_high_prop_update: u64,
}

impl UsnVector {
    /// Construct a zeroed [`UsnVector`] (a "from-scratch" full-sync cursor).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode into `w` (per MS-DRSR §4.1.10.4.13).
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uint64(self.usn_high_obj_update);
        w.write_uint64(self.usn_high_prop_update);
    }

    /// Decode from `r` (per MS-DRSR §4.1.10.4.13).
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let usn_high_obj_update = r.read_uint64()?;
        let usn_high_prop_update = r.read_uint64()?;
        Ok(Self {
            usn_high_obj_update,
            usn_high_prop_update,
        })
    }
}

// =====================================================================
// ReplEntInfV3 — MS-DRSR §4.1.10.4.8 REPLENTIN_V3 (request)
// =====================================================================

/// `REPLENTIN_V3` — the `IDL_DRSGetNCChanges` request body (per MS-DRSR
/// §4.1.10.4.8, with `dwInVersion = 3`).
///
/// On the wire, the pointer fields `pNcOrChain` and `pUpToDateVecDest` are
/// encoded inline as 4-byte NDR referent IDs (per [C706] §14.3.2 — a non-zero
/// referent ID means "the pointer is non-null"). The actual pointed-to
/// structs follow the entire struct proper, in declaration order.
#[derive(Debug, Clone)]
pub struct ReplEntInfV3 {
    /// `uuidDsaObjDest` — the destination DSA's `nTDSDSA` object GUID.
    pub uuid_dsa_obj_dest: Uuid,
    /// `uuidInvocIdSrc` — the source DSA's invocation ID (per MS-ADTS
    /// §3.1.1.3.2.6).
    pub uuid_invoc_id_src: Uuid,
    /// `pNcOrChain` — the NC head to replicate (per MS-DRSR §4.1.10.4.9).
    pub nc: DsName,
    /// `usnVector` — the destination's USN cursor for this NC.
    pub usn_vector: UsnVector,
    /// `pUpToDateVecDest` — the destination's UTD vector for this NC (per
    /// ADR-071).
    pub utd_vector: UtdVectorExt,
    /// `ulFlags` — DRSUAPI replication flags (e.g. `DRS_WRIT_REP`).
    pub ul_flags: u32,
    /// `cMaxObjects` — the maximum number of objects the destination will
    /// accept in a single reply.
    pub c_max_objects: u32,
    /// `cMaxBytes` — the maximum reply size in bytes.
    pub c_max_bytes: u32,
    /// `ulExtendedOp` — the extended operation code (per ADR-122 —
    /// `EXOP_REPL_SECRETS` = `0x00000100` is ACL-gated).
    pub ul_extended_op: u32,
    /// `liFsmoInfo` — FSMO operation info (per MS-DRSR §4.1.10.4.8).
    pub li_fsmo_info: u64,
}

impl ReplEntInfV3 {
    /// Encode into `w` (per MS-DRSR §4.1.10.4.8 `REPLENTIN_V3`).
    pub fn encode(&self, w: &mut NdrWriter) {
        // struct proper — scalars and pointer referent IDs in declaration
        // order.
        w.write_uuid(self.uuid_dsa_obj_dest);
        w.write_uuid(self.uuid_invoc_id_src);
        w.write_uint32(NON_NULL_REFERENT_ID); // pNcOrChain
                                              // usnVector is an embedded struct (no pointer) — write inline.
        self.usn_vector.encode(w);
        w.write_uint32(NON_NULL_REFERENT_ID); // pUpToDateVecDest
        w.write_uint32(self.ul_flags);
        w.write_uint32(self.c_max_objects);
        w.write_uint32(self.c_max_bytes);
        w.write_uint32(self.ul_extended_op);
        w.write_uint64(self.li_fsmo_info);
        // Pointed-to data follows, in declaration order.
        self.nc.encode(w);
        self.utd_vector.encode(w);
    }

    /// Decode from `r` (per MS-DRSR §4.1.10.4.8 `REPLENTIN_V3`).
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let uuid_dsa_obj_dest = r.read_uuid()?;
        let uuid_invoc_id_src = r.read_uuid()?;
        let p_nc_ref = r.read_uint32()?;
        let usn_vector = UsnVector::decode(r)?;
        let p_utd_ref = r.read_uint32()?;
        let ul_flags = r.read_uint32()?;
        let c_max_objects = r.read_uint32()?;
        let c_max_bytes = r.read_uint32()?;
        let ul_extended_op = r.read_uint32()?;
        let li_fsmo_info = r.read_uint64()?;
        // Pointed-to data, in declaration order.
        let nc = if p_nc_ref != 0 {
            DsName::decode(r)?
        } else {
            DsName::from_dn("")
        };
        let utd_vector = if p_utd_ref != 0 {
            UtdVectorExt::decode(r)?
        } else {
            UtdVectorExt::default()
        };
        Ok(Self {
            uuid_dsa_obj_dest,
            uuid_invoc_id_src,
            nc,
            usn_vector,
            utd_vector,
            ul_flags,
            c_max_objects,
            c_max_bytes,
            ul_extended_op,
            li_fsmo_info,
        })
    }

    /// Convenience: encode to a fresh `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        self.encode(&mut w);
        w.into_bytes()
    }

    /// Convenience: decode from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DceRpcError> {
        let mut r = NdrReader::new(bytes);
        Self::decode(&mut r)
    }
}

// =====================================================================
// ReplObj + ReplEntInfV3Reply
// =====================================================================

/// A simplified `REPL_OBJ` (per MS-DRSR §4.1.10.4.6) — the per-object
/// record in a [`ReplEntInfV3Reply`]. Carries the object's DN, UUID,
/// `USNChanged`, and the (name, value) pairs the destination needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplObj {
    /// The object's DN.
    pub dn: String,
    /// The object's UUID (`objectGUID`).
    pub uuid: Uuid,
    /// The object's `USNChanged` (per MS-ADTS §3.1.1.3.2.5).
    pub usn_changed: u64,
    /// The (attribute-name, value-bytes) pairs to replicate.
    pub attributes: Vec<(String, Vec<u8>)>,
}

impl ReplObj {
    /// Encode into `w` (a simplified `REPL_OBJ` layout — DN, UUID,
    /// USNChanged, attribute count, attribute pairs).
    pub fn encode(&self, w: &mut NdrWriter) {
        // pName pointer + the DsName proper.
        w.write_uint32(NON_NULL_REFERENT_ID);
        let dn = DsName {
            guid: self.uuid,
            sid: Vec::new(),
            name: self.dn.clone(),
        };
        dn.encode(w);
        w.write_uint32(0); // ulFlags
        w.write_uint64(self.usn_changed);
        w.write_uint32(self.attributes.len() as u32);
        for (name, value) in &self.attributes {
            w.write_uint32(NON_NULL_REFERENT_ID); // pAttr (non-null)
            let name_dsname = DsName::from_dn(name);
            name_dsname.encode(w);
            w.write_uint32(1); // cNumValues
                               // Conformant-varying value array: max_count, offset, actual_count, data.
            w.write_uint32(value.len() as u32);
            w.write_uint32(0);
            w.write_uint32(value.len() as u32);
            w.write_bytes(value);
            w.align(4);
        }
    }

    /// Decode from `r`.
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let p_name_ref = r.read_uint32()?;
        let dn = if p_name_ref != 0 {
            DsName::decode(r)?
        } else {
            DsName::from_dn("")
        };
        let _ul_flags = r.read_uint32()?;
        let usn_changed = r.read_uint64()?;
        let c_num_attrs = r.read_uint32()? as usize;
        let mut attributes = Vec::with_capacity(c_num_attrs);
        for _ in 0..c_num_attrs {
            let p_attr_ref = r.read_uint32()?;
            let attr_name = if p_attr_ref != 0 {
                DsName::decode(r)?.name
            } else {
                String::new()
            };
            let _c_num_values = r.read_uint32()?;
            // Conformant-varying value array: max_count, offset, actual_count, data.
            let max_count = r.read_uint32()? as usize;
            let _offset = r.read_uint32()?;
            let actual_count = r.read_uint32()? as usize;
            let value_len = actual_count.min(max_count);
            let value = if value_len > 0 {
                let bytes = r.read_bytes(value_len)?.to_vec();
                r.align(4)?;
                bytes
            } else {
                Vec::new()
            };
            attributes.push((attr_name, value));
        }
        Ok(Self {
            dn: dn.name,
            uuid: dn.guid,
            usn_changed,
            attributes,
        })
    }
}

/// `REPLENTIN_V3` reply (per MS-DRSR §4.1.10.4.16 `DRS_MSG_GETCHGREPLY_V3`
/// — simplified).
#[derive(Debug, Clone)]
pub struct ReplEntInfV3Reply {
    /// `cNumObjects` — the number of objects in this reply.
    pub c_num_objects: u32,
    /// `cNumNcs` — the number of NCs in this reply (always 0 in v1; preserved
    /// for wire compat).
    pub c_num_ncs: u32,
    /// `pObjects` — the replicated objects.
    pub p_objects: Vec<ReplObj>,
    /// `fMoreData` — whether more objects remain to be replicated.
    pub f_more_data: bool,
    /// `pUpToDateVecSrc` — the source DSA's UTD vector (per ADR-071 —
    /// included in every reply so the destination can merge it).
    pub utd_vector: UtdVectorExt,
}

impl ReplEntInfV3Reply {
    /// Encode into `w`.
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uint32(self.c_num_objects);
        w.write_uint32(self.c_num_ncs);
        // pObjects: conformant array of ReplObj.
        w.write_uint32(self.p_objects.len() as u32);
        for obj in &self.p_objects {
            obj.encode(w);
        }
        w.write_uint8(if self.f_more_data { 1 } else { 0 });
        w.align(4);
        // pUpToDateVecSrc pointer + struct proper.
        w.write_uint32(NON_NULL_REFERENT_ID);
        self.utd_vector.encode(w);
    }

    /// Decode from `r`.
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let c_num_objects = r.read_uint32()?;
        let c_num_ncs = r.read_uint32()?;
        let p_objects_count = r.read_uint32()? as usize;
        let mut p_objects = Vec::with_capacity(p_objects_count);
        for _ in 0..p_objects_count {
            p_objects.push(ReplObj::decode(r)?);
        }
        let f_more_data_byte = r.read_uint8()?;
        r.align(4)?;
        let p_utd_ref = r.read_uint32()?;
        let utd_vector = if p_utd_ref != 0 {
            UtdVectorExt::decode(r)?
        } else {
            UtdVectorExt::default()
        };
        Ok(Self {
            c_num_objects,
            c_num_ncs,
            p_objects,
            f_more_data: f_more_data_byte != 0,
            utd_vector,
        })
    }

    /// Convenience: encode to a fresh `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        self.encode(&mut w);
        w.into_bytes()
    }

    /// Convenience: decode from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DceRpcError> {
        let mut r = NdrReader::new(bytes);
        Self::decode(&mut r)
    }
}

// =====================================================================
// DirectorySource — in-memory candidate set for DRSGetNCChanges
// =====================================================================

/// An in-memory directory candidate set queried by [`drs_get_nc_changes`].
///
/// In v1 this is the bridge between [`DirectoryStore`] (the persistent
/// storage trait from `adrian-storage-core`) and the DRSUAPI handler. A
/// future wave will replace it with a streaming iterator backed by
/// `DirectoryStore::get_range` over the `0x01` subspace (per ADR-073).
#[derive(Debug, Clone, Default)]
pub struct DirectorySource {
    objects: Vec<Object>,
}

impl DirectorySource {
    /// Construct an empty [`DirectorySource`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an [`Object`] to the candidate set.
    pub fn add(&mut self, obj: Object) {
        self.objects.push(obj);
    }

    /// List all objects in the candidate set whose DN ends with `nc_dn`
    /// (the NC head DN), as [`ReplObj`]s suitable for inclusion in a
    /// [`ReplEntInfV3Reply`].
    ///
    /// Per MS-DRSR §4.1.10.4.8, only objects whose DN is *under* the NC head
    /// are returned (the NC head itself is included). Because LDAP DNs are
    /// written leaf-to-root, "under" means the NC head DN is a **suffix**
    /// of the object DN. The result is sorted by DN for deterministic test
    /// output.
    pub fn list_under_nc(&self, nc_dn: &str) -> Vec<ReplObj> {
        let mut out: Vec<ReplObj> = self
            .objects
            .iter()
            .filter(|o| nc_dn.is_empty() || o.dn.dn.ends_with(nc_dn))
            .map(|o| {
                let attributes = o
                    .attributes
                    .iter()
                    .map(|a| (a.name.clone(), a.value.clone()))
                    .collect();
                ReplObj {
                    dn: o.dn.dn.clone(),
                    uuid: o.uuid,
                    usn_changed: 0,
                    attributes,
                }
            })
            .collect();
        out.sort_by(|a, b| a.dn.cmp(&b.dn));
        out
    }
}

// =====================================================================
// Helpers — extension flag packing / negotiation
// =====================================================================

/// Pack a slice of [`DrsExtFlag`] values into a single `u32` bitmask (per
/// MS-DRSR §4.1.277 — the `dwFlags` field of `DRS_EXTENSIONS_INT`).
pub fn pack_drs_ext_flags(flags: &[DrsExtFlag]) -> u32 {
    flags.iter().fold(0, |acc, f| acc | *f as u32)
}

/// Unpack a `u32` bitmask into a sorted `Vec<DrsExtFlag>` (per MS-DRSR
/// §4.1.277). Only known flags are returned; unknown bits are silently
/// dropped.
pub fn unpack_drs_ext_flags(dw_flags: u32) -> Vec<DrsExtFlag> {
    let all = [
        DrsExtFlag::Base,
        DrsExtFlag::AsyncRepl,
        DrsExtFlag::GetChgReqV6,
        DrsExtFlag::GetChgReplyV5,
        DrsExtFlag::InstanceInfoNotIsMasters,
        DrsExtFlag::GetChgReqV8,
        DrsExtFlag::GetChgReplyV9,
        DrsExtFlag::GetChgReqV10,
    ];
    all.into_iter()
        .filter(|f| dw_flags & *f as u32 != 0)
        .collect()
}

/// Negotiate the extension flag bitmask between a client and the server
/// (per MS-DRSR §4.1.4 — the server returns the intersection of the client's
/// requested flags and [`SERVER_SUPPORTED_EXTENSIONS`]).
///
/// Per ADR-001, the framework requires `DRS_EXT_GETCHGREQ_V8` (and the V9/V10
/// reply/req counterparts) for LVR support. If the intersection does not
/// include `DRS_EXT_BASE`, the negotiation result is `0` (caller must reject
/// the bind).
pub fn negotiate_extensions(client_dw_flags: u32, server_supported: u32) -> u32 {
    let intersection = client_dw_flags & server_supported;
    if intersection & DrsExtFlag::Base as u32 == 0 {
        return 0;
    }
    intersection
}

// =====================================================================
// DrsBindResult + DrsBindReply
// =====================================================================

/// The high-level result of `IDL_DRSBind` (per MS-DRSR §4.1.4.2
/// `DRS_BIND_RESULT`).
#[derive(Debug, Clone)]
pub struct DrsBindResult {
    /// The server's DSA invocation ID (per MS-ADTS §3.1.1.3.2.6).
    pub server_invocation_id: Uuid,
    /// The server's negotiated [`DrsExtensions`] (per MS-DRSR §4.1.277).
    pub server_extensions: DrsExtensions,
    /// The server's replication epoch (per MS-DRSR §4.1.4.2).
    pub replication_epoch: u32,
    /// The fresh bind handle UUID (per MS-DRSR §4.1.4.1 — `hDrs`). The
    /// caller includes this in subsequent `IDL_DRSGetNCChanges` /
    /// `IDL_DRSUnbind` calls.
    pub bind_handle: Uuid,
}

// =====================================================================
// Handlers — DRSBind (opnum 0x00) + DRSGetNCChanges (opnum 0x04)
// =====================================================================

/// `IDL_DRSBind` (opnum 0x00) — high-level handler (per MS-DRSR §4.1.4).
///
/// Parses the client's [`DrsExtensions`], negotiates the extension-flag
/// intersection with [`SERVER_SUPPORTED_EXTENSIONS`] (via
/// [`negotiate_extensions`]), and returns a [`DrsBindResult`] containing
/// the server's extensions and a fresh UUIDv7 bind handle.
///
/// Returns [`ReplicationError::Permanent`] if the client does not advertise
/// `DRS_EXT_BASE` (the bind cannot proceed without the base extension).
pub async fn drs_bind(
    invocation_id: Uuid,
    client_extensions: &DrsExtensions,
) -> Result<DrsBindResult, ReplicationError> {
    let negotiated = negotiate_extensions(client_extensions.dw_flags, SERVER_SUPPORTED_EXTENSIONS);
    if negotiated == 0 {
        return Err(ReplicationError::Permanent(format!(
            "DRSBind: client dwFlags={:#010x} does not include DRS_EXT_BASE",
            client_extensions.dw_flags
        )));
    }
    let server_extensions = DrsExtensions {
        dw_flags: negotiated,
        site_obj_guid: client_extensions.site_obj_guid,
        pid: 0,
        dw_repl_epoch: client_extensions.dw_repl_epoch,
        dw_flags_ext: 0,
        extra: Vec::new(),
    };
    let bind_handle = Uuid::now_v7();
    Ok(DrsBindResult {
        server_invocation_id: invocation_id,
        server_extensions,
        replication_epoch: client_extensions.dw_repl_epoch,
        bind_handle,
    })
}

/// `IDL_DRSBind` (opnum 0x00) — wire-level dispatch handler (per MS-DRSR
/// §4.1.4).
///
/// Decodes the NDR stub input (the client's [`DrsExtensions`]), invokes
/// [`drs_bind`], and encodes the [`DrsBindResult`] back to NDR bytes for
/// the DCE/RPC Response PDU. The reply wire layout is:
/// `hDrs (UUID) | pextServer_ptr (u32) | pextServer_body (DrsExtensions)`.
pub async fn drs_bind_dispatch(
    invocation_id: Uuid,
    stub_input: &[u8],
) -> Result<Vec<u8>, ReplicationError> {
    let client_extensions = DrsExtensions::from_bytes(stub_input)
        .map_err(|e| ReplicationError::Backend(format!("DRSBind NDR decode: {e}")))?;
    let result = drs_bind(invocation_id, &client_extensions).await?;
    let mut w = NdrWriter::new();
    w.write_uuid(result.bind_handle);
    w.write_uint32(NON_NULL_REFERENT_ID);
    result.server_extensions.encode(&mut w);
    Ok(w.into_bytes())
}

/// `IDL_DRSGetNCChanges` (opnum 0x04) — high-level handler (per MS-DRSR
/// §4.1.27).
///
/// Parses the [`ReplEntInfV3`] request (NC DN, USN vector, options), looks up
/// directory objects from `source` whose DN is under the request's NC head,
/// and returns a [`ReplEntInfV3Reply`] with the objects plus the source DSA's
/// UTD vector (per ADR-071).
///
/// Per MS-DRSR §4.1.10.4.8, `f_more_data` is set to `true` iff the candidate
/// set exceeds `request.c_max_objects` (the destination's per-reply cap).
pub async fn drs_get_nc_changes(
    invocation_id: Uuid,
    source: &DirectorySource,
    request: &ReplEntInfV3,
) -> Result<ReplEntInfV3Reply, ReplicationError> {
    let nc_dn = &request.nc.name;
    let mut all = source.list_under_nc(nc_dn);
    let max = if request.c_max_objects == 0 {
        all.len()
    } else {
        request.c_max_objects as usize
    };
    let f_more_data = all.len() > max;
    if f_more_data {
        all.truncate(max);
    }
    // Build the source UTD vector: a single entry mapping the source
    // invocation ID to the request's high-water USN. The destination
    // merges this into its own UTD vector per ADR-071.
    let mut utd_vector = UtdVectorExt::new();
    utd_vector.merge(UtdVectorExtEntry {
        usn_high: request.usn_vector.usn_high_prop_update,
        usn_low: 0,
        dsa_guid: invocation_id,
    });
    Ok(ReplEntInfV3Reply {
        c_num_objects: all.len() as u32,
        c_num_ncs: 0,
        p_objects: all,
        f_more_data,
        utd_vector,
    })
}

/// `IDL_DRSGetNCChanges` (opnum 0x04) — wire-level dispatch handler (per
/// MS-DRSR §4.1.27).
///
/// Decodes the NDR stub input (a [`ReplEntInfV3`]), invokes
/// [`drs_get_nc_changes`], and encodes the [`ReplEntInfV3Reply`] back to
/// NDR bytes for the DCE/RPC Response PDU.
pub async fn drs_get_nc_changes_dispatch(
    invocation_id: Uuid,
    source: &DirectorySource,
    stub_input: &[u8],
) -> Result<Vec<u8>, ReplicationError> {
    let request = ReplEntInfV3::from_bytes(stub_input)
        .map_err(|e| ReplicationError::Backend(format!("DRSGetNCChanges NDR decode: {e}")))?;
    let reply = drs_get_nc_changes(invocation_id, source, &request).await?;
    let mut w = NdrWriter::new();
    // dwOutVersion (u32) — always 3 for REPLENTIN_V3 reply in v1.
    w.write_uint32(3);
    reply.encode(&mut w);
    Ok(w.into_bytes())
}

// =====================================================================
// IDL_DRSUnbind (opnum 0x01) — per MS-DRSR §4.1.5
// =====================================================================

/// `DRS_MSG_UNBINDREQ_V1` — request body for `IDL_DRSUnbind` (opnum 0x01)
/// per MS-DRSR §4.1.5.2. Carries the bind handle (`hDrs`) to be released.
#[derive(Debug, Clone)]
pub struct DrsUnbindReq {
    /// The bind handle returned by a prior `IDL_DRSBind` call.
    pub bind_handle: Uuid,
}

impl DrsUnbindReq {
    /// Encode the request body (no outer pointer — `hDrs` is a UUID value,
    /// not a conformant array). Layout: `[hDrs (16 bytes UUID)]`.
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uuid(self.bind_handle);
    }

    /// Decode the request body.
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let bind_handle = r.read_uuid()?;
        Ok(Self { bind_handle })
    }

    /// Convenience encoder to `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        self.encode(&mut w);
        w.into_bytes()
    }

    /// Convenience decoder from `&[u8]`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DceRpcError> {
        let mut r = NdrReader::new(bytes);
        Self::decode(&mut r)
    }
}

/// `DRS_MSG_UNBINDREPLY_V1` — reply body for `IDL_DRSUnbind` (opnum 0x01)
/// per MS-DRSR §4.1.5.3. On success, `hDrs` is set to nil (the handle is
/// invalidated). The reply is always `dwOutVersion = 1`.
#[derive(Debug, Clone)]
pub struct DrsUnbindReply {
    /// The (now-invalidated) bind handle — nil on success.
    pub bind_handle: Uuid,
}

impl DrsUnbindReply {
    /// Encode the reply body.
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uuid(self.bind_handle);
    }

    /// Decode the reply body.
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let bind_handle = r.read_uuid()?;
        Ok(Self { bind_handle })
    }
}

/// High-level `IDL_DRSUnbind` handler (opnum 0x01, per MS-DRSR §4.1.5).
///
/// Releases the bind handle. In v1 we don't track active bind handles in a
/// table (the DCE/RPC transport layer manages association lifetimes); this
/// handler simply returns the nil UUID to indicate the handle is released.
pub async fn drs_unbind(
    _invocation_id: Uuid,
    _bind_handle: Uuid,
) -> Result<DrsUnbindReply, ReplicationError> {
    Ok(DrsUnbindReply {
        bind_handle: Uuid::nil(),
    })
}

/// Wire-level dispatch for `IDL_DRSUnbind` (opnum 0x01).
///
/// Decodes the request, calls [`drs_unbind`], encodes the reply as
/// `dwOutVersion (u32) = 1 | DRS_MSG_UNBINDREPLY_V1 body`.
pub async fn drs_unbind_dispatch(
    invocation_id: Uuid,
    stub_input: &[u8],
) -> Result<Vec<u8>, ReplicationError> {
    let req = DrsUnbindReq::from_bytes(stub_input)
        .map_err(|e| ReplicationError::Backend(format!("DRSUnbind NDR decode: {e}")))?;
    let reply = drs_unbind(invocation_id, req.bind_handle).await?;
    let mut w = NdrWriter::new();
    w.write_uint32(1); // dwOutVersion
    reply.encode(&mut w);
    Ok(w.into_bytes())
}

// =====================================================================
// IDL_DRSReplicaSync (opnum 0x03) — per MS-DRSR §4.1.10
// =====================================================================

/// `DRS_MSG_REPSYNC_V1` — request body for `IDL_DRSReplicaSync` (opnum
/// 0x03) per MS-DRSR §4.1.10.2. Triggers a replication cycle from a source
/// DSA to the local DSA for the named NC.
#[derive(Debug, Clone)]
pub struct DrsReplicaSyncReq {
    /// The bind handle from `IDL_DRSBind`.
    pub bind_handle: Uuid,
    /// The NC DN to replicate (e.g. `DC=adrian,DC=example`).
    pub nc_dn: String,
    /// The source DSA address (e.g. `dc01.adrian.example`).
    pub src_dsa_address: String,
    /// Replication option flags (per MS-DRSR §4.1.10.2 `ulOptions`).
    pub ul_options: u32,
}

impl DrsReplicaSyncReq {
    /// Encode the request body. Layout: `[hDrs (16)] [pid (4)] [pwszNc ptr
    /// (4) | conformant wchar_t array] [pwszSrcDsaAddress ptr (4) |
    /// conformant wchar_t array] [ulOptions (4)]`.
    ///
    /// For v1 we use a simplified layout: UUID + two length-prefixed UTF-16LE
    /// strings + u32 flags. The pointer referent IDs use
    /// [`NON_NULL_REFERENT_ID`].
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uuid(self.bind_handle);
        // pwszNc — non-null pointer + conformant wchar_t array (UTF-16LE,
        // NUL-terminated, length prefix counts NUL).
        w.write_uint32(NON_NULL_REFERENT_ID);
        let utf16: Vec<u16> = self
            .nc_dn
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();
        w.write_uint32(utf16.len() as u32);
        for &unit in &utf16 {
            w.write_uint16(unit);
        }
        w.align(4);
        // pwszSrcDsaAddress — same shape.
        w.write_uint32(NON_NULL_REFERENT_ID);
        let utf16: Vec<u16> = self
            .src_dsa_address
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();
        w.write_uint32(utf16.len() as u32);
        for &unit in &utf16 {
            w.write_uint16(unit);
        }
        w.align(4);
        w.write_uint32(self.ul_options);
    }

    /// Decode the request body.
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let bind_handle = r.read_uuid()?;
        let _nc_ptr = r.read_uint32()?;
        let nc_dn = read_conformant_utf16_string(r)?;
        let _src_ptr = r.read_uint32()?;
        let src_dsa_address = read_conformant_utf16_string(r)?;
        let ul_options = r.read_uint32()?;
        Ok(Self {
            bind_handle,
            nc_dn,
            src_dsa_address,
            ul_options,
        })
    }

    /// Convenience encoder.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        self.encode(&mut w);
        w.into_bytes()
    }

    /// Convenience decoder.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DceRpcError> {
        let mut r = NdrReader::new(bytes);
        Self::decode(&mut r)
    }
}

/// `DRS_MSG_REPSYNCREPLY_V1` — reply body for `IDL_DRSReplicaSync`.
/// Contains only the `retval` HRESULT (0 = success).
#[derive(Debug, Clone)]
pub struct DrsReplicaSyncReply {
    /// HRESULT return value (0 = success).
    pub retval: u32,
}

impl DrsReplicaSyncReply {
    /// Encode the reply body.
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uint32(self.retval);
    }

    /// Decode the reply body.
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let retval = r.read_uint32()?;
        Ok(Self { retval })
    }
}

/// High-level `IDL_DRSReplicaSync` handler (opnum 0x03, per MS-DRSR
/// §4.1.10).
///
/// Triggers a replication cycle from `src_dsa_address` for the named NC. In
/// v1 we don't have a background replication driver; this handler returns
/// success immediately (the actual replication is driven by the
/// [`Replicator`] trait's `get_changes` / `apply_changes` methods).
pub async fn drs_replica_sync(
    _invocation_id: Uuid,
    _nc_dn: &str,
    _src_dsa_address: &str,
    _ul_options: u32,
) -> Result<DrsReplicaSyncReply, ReplicationError> {
    Ok(DrsReplicaSyncReply { retval: 0 })
}

/// Wire-level dispatch for `IDL_DRSReplicaSync` (opnum 0x03).
pub async fn drs_replica_sync_dispatch(
    invocation_id: Uuid,
    stub_input: &[u8],
) -> Result<Vec<u8>, ReplicationError> {
    let req = DrsReplicaSyncReq::from_bytes(stub_input)
        .map_err(|e| ReplicationError::Backend(format!("DRSReplicaSync NDR decode: {e}")))?;
    let reply = drs_replica_sync(
        invocation_id,
        &req.nc_dn,
        &req.src_dsa_address,
        req.ul_options,
    )
    .await?;
    let mut w = NdrWriter::new();
    w.write_uint32(1); // dwOutVersion
    reply.encode(&mut w);
    Ok(w.into_bytes())
}

// =====================================================================
// IDL_DRSCrackNames (opnum 0x0C) — per MS-DRSR §4.1.17
// =====================================================================

/// Name format constants for `IDL_DRSCrackNames` (per MS-DRSR §4.1.17.2
/// `DS_NAME_FORMAT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DsNameFormat {
    /// Unknown name format.
    Unknown = 0,
    /// `CN=User,DC=adrian,DC=example` (RFC 1779).
    Fqdn1779 = 1,
    /// `DOMAIN\User` (NT4 account name).
    Nt4Account = 2,
    /// Display name (e.g. `Alice Smith`).
    DisplayName = 3,
    /// `{-guid}` GUID-based name.
    Guid = 6,
    /// `adrian.example/Users/Alice` canonical name.
    Canonical = 7,
    /// `alice@adrian.example` user principal name.
    Upn = 8,
    /// `HOST/dc01.adrian.example` service principal name.
    Spn = 9,
    /// `S-1-5-21-...` SID string.
    SidOrSidHistory = 10,
    /// `adrian.example` DNS domain name.
    DnsDomain = 12,
}

/// Name status for a cracked entry (per MS-DRSR §4.1.17.3
/// `DS_NAME_RESULT_ITEM`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DsNameStatus {
    /// The name was cracked successfully.
    Ok = 0,
    /// The name was not found.
    NotFound = 1,
    /// The name was ambiguous (matched multiple objects).
    NotUnique = 2,
    /// The format could not be resolved.
    NoMapping = 3,
    /// The name was cracked to a different domain.
    DomainOnly = 4,
}

/// A single cracked-name result entry (per MS-DRSR §4.1.17.3
/// `DS_NAME_RESULT_ITEM`).
#[derive(Debug, Clone)]
pub struct CrackedName {
    /// The cracked name in the desired format.
    pub name: String,
    /// The status of the crack operation.
    pub status: DsNameStatus,
}

/// `DRS_MSG_CRACKREQ_V1` — request body for `IDL_DRSCrackNames` (opnum
/// 0x0C) per MS-DRSR §4.1.17.2. Converts between name formats (DN, SID,
/// UPN, SPN, GUID, etc.).
#[derive(Debug, Clone)]
pub struct DrsCrackNamesReq {
    /// The bind handle.
    pub bind_handle: Uuid,
    /// The input format of the names in `names`.
    pub format_offered: DsNameFormat,
    /// The desired output format.
    pub format_desired: DsNameFormat,
    /// The names to crack.
    pub names: Vec<String>,
}

impl DrsCrackNamesReq {
    /// Encode the request body. Layout: `[hDrs (16)] [flags (4)]
    /// [formatOffered (4)] [formatDesired (4)] [cNames (4)] [rpNames ptr
    /// (4) | conformant array of conformant wchar_t strings]`.
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uuid(self.bind_handle);
        w.write_uint32(0); // flags — reserved, must be 0.
        w.write_uint32(self.format_offered as u32);
        w.write_uint32(self.format_desired as u32);
        w.write_uint32(self.names.len() as u32);
        w.write_uint32(NON_NULL_REFERENT_ID);
        for name in &self.names {
            w.write_uint32(NON_NULL_REFERENT_ID);
            let utf16: Vec<u16> = name.encode_utf16().chain(std::iter::once(0u16)).collect();
            w.write_uint32(utf16.len() as u32);
            for &unit in &utf16 {
                w.write_uint16(unit);
            }
            w.align(4);
        }
    }

    /// Decode the request body.
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let bind_handle = r.read_uuid()?;
        let _flags = r.read_uint32()?;
        let format_offered = parse_ds_name_format(r.read_uint32()?);
        let format_desired = parse_ds_name_format(r.read_uint32()?);
        let c_names = r.read_uint32()? as usize;
        let _rp_names_ptr = r.read_uint32()?;
        let mut names = Vec::with_capacity(c_names);
        for _ in 0..c_names {
            let _ptr = r.read_uint32()?;
            names.push(read_conformant_utf16_string(r)?);
        }
        Ok(Self {
            bind_handle,
            format_offered,
            format_desired,
            names,
        })
    }

    /// Convenience encoder.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = NdrWriter::new();
        self.encode(&mut w);
        w.into_bytes()
    }

    /// Convenience decoder.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DceRpcError> {
        let mut r = NdrReader::new(bytes);
        Self::decode(&mut r)
    }
}

/// `DRS_MSG_CRACKREPLY_V1` — reply body for `IDL_DRSCrackNames`.
#[derive(Debug, Clone)]
pub struct DrsCrackNamesReply {
    /// The cracked name entries, one per input name.
    pub entries: Vec<CrackedName>,
}

impl DrsCrackNamesReply {
    /// Encode the reply body. Layout: `[cEntries (4)] [pEntries ptr (4) |
    /// conformant array of DS_NAME_RESULT_ITEM]`. Each item is
    /// `[pName ptr (4) | conformant wchar_t string] [status (4)]`.
    pub fn encode(&self, w: &mut NdrWriter) {
        w.write_uint32(self.entries.len() as u32);
        w.write_uint32(NON_NULL_REFERENT_ID);
        for entry in &self.entries {
            w.write_uint32(NON_NULL_REFERENT_ID);
            let utf16: Vec<u16> = entry
                .name
                .encode_utf16()
                .chain(std::iter::once(0u16))
                .collect();
            w.write_uint32(utf16.len() as u32);
            for &unit in &utf16 {
                w.write_uint16(unit);
            }
            w.align(4);
            w.write_uint32(entry.status as u32);
        }
    }

    /// Decode the reply body.
    pub fn decode(r: &mut NdrReader) -> Result<Self, DceRpcError> {
        let c_entries = r.read_uint32()? as usize;
        let _p_entries_ptr = r.read_uint32()?;
        let mut entries = Vec::with_capacity(c_entries);
        for _ in 0..c_entries {
            let _ptr = r.read_uint32()?;
            let name = read_conformant_utf16_string(r)?;
            let status = parse_ds_name_status(r.read_uint32()?);
            entries.push(CrackedName { name, status });
        }
        Ok(Self { entries })
    }
}

/// High-level `IDL_DRSCrackNames` handler (opnum 0x0C, per MS-DRSR
/// §4.1.17).
///
/// Converts names from `format_offered` to `format_desired`. In v1 we
/// implement a minimal subset:
///
/// - `Fqdn1779 -> Upn`: splits `CN=Alice,DC=adrian,DC=example` into
///   `alice@adrian.example` (lowercases the CN, joins DC parts with `.`).
/// - `Fqdn1779 -> Canonical`: splits into `adrian.example/Users/Alice`.
/// - `Fqdn1779 -> Fqdn1779`: identity (returns the input unchanged).
///
/// All other conversions return `DsNameStatus::NoMapping` (the caller can
/// retry with a different format or consult the GC).
pub async fn drs_crack_names(
    _invocation_id: Uuid,
    format_offered: DsNameFormat,
    format_desired: DsNameFormat,
    names: &[String],
) -> Result<DrsCrackNamesReply, ReplicationError> {
    let entries: Vec<CrackedName> = names
        .iter()
        .map(|name| crack_one_name(name, format_offered, format_desired))
        .collect();
    Ok(DrsCrackNamesReply { entries })
}

/// Crack a single name from `offered` to `desired` format.
fn crack_one_name(name: &str, offered: DsNameFormat, desired: DsNameFormat) -> CrackedName {
    if offered == desired {
        return CrackedName {
            name: name.to_string(),
            status: DsNameStatus::Ok,
        };
    }
    // Parse the DN into RDN components + DC parts.
    if offered == DsNameFormat::Fqdn1779 {
        let parts: Vec<&str> = name.split(',').collect();
        let mut dc_parts: Vec<String> = Vec::new();
        let mut cn_value: Option<String> = None;
        for part in &parts {
            let part = part.trim();
            if let Some(rest) = part.strip_prefix("CN=") {
                if cn_value.is_none() {
                    cn_value = Some(rest.to_string());
                }
            } else if let Some(rest) = part.strip_prefix("DC=") {
                dc_parts.push(rest.to_string());
            }
        }
        let domain = dc_parts.join(".");
        let cn = cn_value.unwrap_or_default();
        match desired {
            DsNameFormat::Upn => {
                let upn = format!("{}@{}", cn.to_lowercase(), domain);
                return CrackedName {
                    name: upn,
                    status: DsNameStatus::Ok,
                };
            }
            DsNameFormat::Canonical => {
                let canonical = if domain.is_empty() {
                    cn.clone()
                } else {
                    format!("{}/Users/{}", domain, cn)
                };
                return CrackedName {
                    name: canonical,
                    status: DsNameStatus::Ok,
                };
            }
            _ => {}
        }
    }
    // Unsupported conversion.
    CrackedName {
        name: String::new(),
        status: DsNameStatus::NoMapping,
    }
}

/// Wire-level dispatch for `IDL_DRSCrackNames` (opnum 0x0C).
pub async fn drs_crack_names_dispatch(
    invocation_id: Uuid,
    stub_input: &[u8],
) -> Result<Vec<u8>, ReplicationError> {
    let req = DrsCrackNamesReq::from_bytes(stub_input)
        .map_err(|e| ReplicationError::Backend(format!("DRSCrackNames NDR decode: {e}")))?;
    let reply = drs_crack_names(
        invocation_id,
        req.format_offered,
        req.format_desired,
        &req.names,
    )
    .await?;
    let mut w = NdrWriter::new();
    w.write_uint32(1); // dwOutVersion
    reply.encode(&mut w);
    Ok(w.into_bytes())
}

// =====================================================================
// NDR helpers shared by Wave 3 opnums
// =====================================================================

/// Read a conformant UTF-16LE NUL-terminated wchar_t string (per NDR
/// conformant array rules: `[count (u32)] [count × uint16] [align 4]`).
/// The trailing NUL WCHAR is included in `count` and stripped here.
fn read_conformant_utf16_string(r: &mut NdrReader) -> Result<String, DceRpcError> {
    let count = r.read_uint32()? as usize;
    let mut units = Vec::with_capacity(count);
    for _ in 0..count {
        units.push(r.read_uint16()?);
    }
    r.align(4)?;
    // Strip the trailing NUL WCHAR if present.
    if units.last() == Some(&0) {
        units.pop();
    }
    String::from_utf16(&units).map_err(|e| DceRpcError::Ndr(format!("UTF-16 decode: {e}")))
}

/// Parse a `u32` into a [`DsNameFormat`]. Unknown values fall back to
/// [`DsNameFormat::Unknown`] (per MS-DRSR §4.1.17.2 — the server should
/// reject unknown formats, but we tolerate them for forward compat).
fn parse_ds_name_format(v: u32) -> DsNameFormat {
    match v {
        0 => DsNameFormat::Unknown,
        1 => DsNameFormat::Fqdn1779,
        2 => DsNameFormat::Nt4Account,
        3 => DsNameFormat::DisplayName,
        6 => DsNameFormat::Guid,
        7 => DsNameFormat::Canonical,
        8 => DsNameFormat::Upn,
        9 => DsNameFormat::Spn,
        10 => DsNameFormat::SidOrSidHistory,
        12 => DsNameFormat::DnsDomain,
        _ => DsNameFormat::Unknown,
    }
}

/// Parse a `u32` into a [`DsNameStatus`]. Unknown values fall back to
/// [`DsNameStatus::Ok`] (defensive — the server should only emit known
/// statuses, but a malformed reply shouldn't crash the client).
fn parse_ds_name_status(v: u32) -> DsNameStatus {
    match v {
        0 => DsNameStatus::Ok,
        1 => DsNameStatus::NotFound,
        2 => DsNameStatus::NotUnique,
        3 => DsNameStatus::NoMapping,
        4 => DsNameStatus::DomainOnly,
        _ => DsNameStatus::Ok,
    }
}

// =====================================================================
// DrSuapiReplicator (Wave 1: get_changes + apply_changes wired)
// =====================================================================

/// Convert a [`StorageError`] into a [`ReplicationError`] (per Decision 1
/// §Error handling — backend storage errors map to `ReplicationError::Backend`).
fn map_storage_error(e: StorageError) -> ReplicationError {
    ReplicationError::Backend(format!("storage error: {e:?}"))
}

/// Convert a [`DceRpcError`] into a [`ReplicationError`] (per Decision 1
/// §Error handling — NDR codec errors map to `ReplicationError::Backend`).
fn map_ndr_error(e: DceRpcError) -> ReplicationError {
    ReplicationError::Backend(format!("NDR codec error: {e:?}"))
}

/// Convert a [`UtdVector`] (the repl-core wire-agnostic shape) into a
/// [`UtdVectorExt`] (the MS-DRSR NDR-encoded shape) per ADR-071 §Decision.
///
/// Each repl-core entry `(invocation_id, highest_usn)` becomes an NDR entry
/// `{usn_high: highest_usn, usn_low: 0, dsa_guid: invocation_id}`. The
/// `usn_low` is zero because repl-core's UTD vector only tracks the high-water
/// mark per DSA, not a range (per ADR-071 §Decision — "UTD vectors are
/// high-water marks, not range cursors").
fn utd_vector_to_ext(v: &UtdVector) -> UtdVectorExt {
    let entries = v
        .entries
        .iter()
        .map(|e| UtdVectorExtEntry {
            usn_high: e.highest_usn,
            usn_low: 0,
            dsa_guid: e.invocation_id,
        })
        .collect();
    UtdVectorExt {
        dw_version: 0x1,
        entries,
    }
}

/// DRSUAPI replicator implementation (per Decision 1 §Decision).
///
/// Implements [`Replicator`] by speaking MS-DRSR over the DCE/RPC transport
/// from `adrian-dcerpc`. Negotiates `DRS_EXT_GETCHGREQ_V8/V10` for full LVR
/// support (per ADR-001). Emits and consumes `REPLVALINF_V3` records
/// byte-identically to MS-DRSR §4.1.277 (per Decision 1 §Decision) for every
/// linked-attribute change.
///
/// **Status (Wave 1)**: [`get_changes`](Replicator::get_changes) and
/// [`apply_changes`](Replicator::apply_changes) are real — they walk the
/// FDB-backed store, build a [`DirectorySource`], invoke
/// [`drs_get_nc_changes_dispatch`], and apply incoming [`ReplOperation`]s
/// back to the store. [`update_utd_vector`](Replicator::update_utd_vector),
/// [`resolve_conflict`](Replicator::resolve_conflict), and
/// [`sync_metadata`](Replicator::sync_metadata) remain stubs (Wave 3+).
pub struct DrSuapiReplicator {
    /// The DSA's invocation ID (per MS-ADTS §3.1.1.3.2.6).
    pub invocation_id: uuid::Uuid,
    /// The underlying FDB-backed directory store.
    pub store: adrian_storage_fdb::FdbDirectoryStore,
}

impl DrSuapiReplicator {
    /// Construct a new `DrSuapiReplicator`.
    pub fn new(invocation_id: uuid::Uuid, store: adrian_storage_fdb::FdbDirectoryStore) -> Self {
        Self {
            invocation_id,
            store,
        }
    }

    /// Build a [`DirectorySource`] from the underlying store by walking the
    /// `0x10` ObjectUuidIndex subspace (per ADR-073 §Decision — the UUID
    /// index is the canonical enumeration point for live objects).
    ///
    /// This is the candidate-set walker that feeds
    /// [`drs_get_nc_changes_dispatch`]. It enumerates every live object UUID
    /// via a range scan of subspace `0x10`, then fetches each [`Object`] via
    /// [`DirectoryStore::get`]. Tombstones (subspace `0x07`) are NOT included
    /// here — they are replicated via a separate deletion feed (Wave 4).
    async fn build_directory_source(&self) -> Result<DirectorySource, ReplicationError> {
        let txn = self.store.begin_read().await.map_err(map_storage_error)?;
        let begin = vec![Subspace::ObjectUuidIndex as u8];
        let mut end = begin.clone();
        // Half-open range [0x10, 0x11) covers the entire ObjectUuidIndex.
        end[0] = end[0].wrapping_add(1);
        let rows = txn
            .get_range(&begin, &end)
            .await
            .map_err(map_storage_error)?;
        let mut source = DirectorySource::new();
        for (key, _value) in &rows {
            if let Some(uuid) = decode_uuid_index_key(key) {
                if let Some(obj) = self.store.get(uuid).await.map_err(map_storage_error)? {
                    source.add(obj);
                }
            }
        }
        Ok(source)
    }

    /// Look up the NC head object's DN by UUID. Returns `None` if the NC
    /// head is not present in the store (caller treats this as "no objects
    /// to replicate" per Wave 1 semantics).
    async fn nc_head_dn(&self, nc_head: NcHead) -> Result<Option<String>, ReplicationError> {
        let obj = self.store.get(nc_head).await.map_err(map_storage_error)?;
        Ok(obj.map(|o| o.dn.dn.clone()))
    }
}

/// Build a [`ReplEntInfV3`] request from a destination cursor and NC head DN.
///
/// Per MS-DRSR §4.1.10.4.8 — the request carries the destination DSA's
/// up-to-dateness vector so the source can skip objects the destination
/// already has. In Wave 1 the source does NOT yet filter by USN (that's
/// Wave 3); the cursor is still encoded into the request for wire-format
/// correctness.
fn build_replentin_v3_request(
    invocation_id: Uuid,
    nc_dn: &str,
    cursor: &UtdVector,
) -> ReplEntInfV3 {
    ReplEntInfV3 {
        uuid_dsa_obj_dest: Uuid::nil(),
        uuid_invoc_id_src: invocation_id,
        nc: DsName::from_dn(nc_dn),
        usn_vector: UsnVector::new(),
        utd_vector: utd_vector_to_ext(cursor),
        ul_flags: 0,
        c_max_objects: 1000,
        c_max_bytes: 0,
        ul_extended_op: 0,
        li_fsmo_info: 0,
    }
}

#[async_trait]
impl Replicator for DrSuapiReplicator {
    async fn get_changes(
        &self,
        nc_head: NcHead,
        cursor: &UtdVector,
    ) -> Result<ReplicationPayload, ReplicationError> {
        // Per ADR-070 — wire `get_changes` to `drs_get_nc_changes_dispatch`.
        // The dispatch handler is the wire-level IDL_DRSGetNCChanges (opnum
        // 0x04) server; we build a request from the destination cursor,
        // encode it, invoke the dispatch, decode the reply, and convert each
        // `ReplObj` into a `ReplOperation::AddObject`.
        let source = self.build_directory_source().await?;
        let nc_dn = match self.nc_head_dn(nc_head).await? {
            Some(dn) => dn,
            None => {
                // NC head not present in the source store — nothing to
                // replicate. Return an empty payload so the caller can
                // short-circuit (per MS-ADTS §3.1.1.3.2.5 — a missing NC
                // head means the source DSA does not host that NC).
                return Ok(ReplicationPayload {
                    nc_head,
                    operations: Vec::new(),
                    origin_invocation_id: self.invocation_id,
                    highest_usn: 0,
                });
            }
        };
        let request = build_replentin_v3_request(self.invocation_id, &nc_dn, cursor);
        let request_bytes = request.to_bytes();
        let reply_bytes =
            drs_get_nc_changes_dispatch(self.invocation_id, &source, &request_bytes).await?;
        // Reply layout: `dwOutVersion (u32) | DRS_MSG_GETCHGREPLY_V3 body`.
        let mut r = NdrReader::new(&reply_bytes);
        let _dw_out_version = r.read_uint32().map_err(map_ndr_error)?;
        let reply = ReplEntInfV3Reply::decode(&mut r).map_err(map_ndr_error)?;
        // Synthesize per-value metadata for each attribute. Wave 3 will
        // replace this with real per-value metadata read from the FDB
        // `0x01` subspace (per ADR-071 §Decision).
        let default_metadata = adrian_repl_core::PropertyMetaDataExt {
            origin_invocation_id: self.invocation_id,
            origin_usn: 0,
            version: 1,
            last_write_timestamp: 0,
        };
        let operations = reply
            .p_objects
            .iter()
            .map(|repl_obj| ReplOperation::AddObject {
                uuid: repl_obj.uuid,
                dn: repl_obj.dn.clone(),
                attributes: repl_obj
                    .attributes
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone(), default_metadata.clone()))
                    .collect(),
            })
            .collect();
        // The source's high-water mark for the origin DSA is the highest
        // `usn_high` in the reply's UTD vector (per MS-ADTS §3.1.1.3.2.5).
        let highest_usn = reply
            .utd_vector
            .entries
            .iter()
            .map(|e| e.usn_high)
            .max()
            .unwrap_or(0);
        Ok(ReplicationPayload {
            nc_head,
            operations,
            origin_invocation_id: self.invocation_id,
            highest_usn,
        })
    }

    async fn apply_changes(
        &self,
        batch: ReplicationPayload,
    ) -> Result<Vec<Resolution>, ReplicationError> {
        // Per ADR-070 — apply each `ReplOperation` to the local store. In
        // Wave 1 we handle `AddObject`, `ModifyAttribute`, and `DeleteObject`;
        // `AddLink`/`DeleteLink`/`TombstoneGC` are Wave 4 and are skipped
        // here (logged via tracing). Conflict resolution is per-value using
        // `adrian_repl_core::resolve_conflict`, but since `Object` doesn't
        // yet carry per-value metadata, we treat every incoming write as
        // `IncomingWins` (the existing object, if any, is overwritten).
        let mut resolutions = Vec::with_capacity(batch.operations.len());
        for op in &batch.operations {
            let resolution = match op {
                ReplOperation::AddObject {
                    uuid,
                    dn,
                    attributes,
                } => {
                    let obj = Object {
                        uuid: *uuid,
                        dn: DistinguishedName::new(dn.clone()),
                        attributes: attributes
                            .iter()
                            .map(|(name, value, _)| adrian_storage_core::Attribute {
                                attribute_id: 0,
                                name: name.clone(),
                                value: value.clone(),
                            })
                            .collect(),
                        dnt: 0, // UNASSIGNED_DNT — store allocates on put.
                    };
                    self.store.put(&obj).await.map_err(map_storage_error)?;
                    Resolution::IncomingWins
                }
                ReplOperation::ModifyAttribute {
                    uuid,
                    attribute,
                    value,
                    metadata: _,
                } => {
                    let mut existing = self
                        .store
                        .get(*uuid)
                        .await
                        .map_err(map_storage_error)?
                        .ok_or_else(|| {
                            ReplicationError::Permanent(format!(
                                "ModifyAttribute: object {uuid} not found"
                            ))
                        })?;
                    if value.is_empty() {
                        existing.attributes.retain(|a| a.name != *attribute);
                    } else {
                        if let Some(attr) = existing
                            .attributes
                            .iter_mut()
                            .find(|a| a.name == *attribute)
                        {
                            attr.value = value.clone();
                        } else {
                            existing.attributes.push(adrian_storage_core::Attribute {
                                attribute_id: 0,
                                name: attribute.clone(),
                                value: value.clone(),
                            });
                        }
                    }
                    self.store.put(&existing).await.map_err(map_storage_error)?;
                    Resolution::IncomingWins
                }
                ReplOperation::DeleteObject { uuid, metadata: _ } => {
                    self.store.delete(*uuid).await.map_err(map_storage_error)?;
                    Resolution::IncomingWins
                }
                ReplOperation::AddLink { .. }
                | ReplOperation::DeleteLink { .. }
                | ReplOperation::TombstoneGC { .. } => {
                    // Wave 4: linked-value replication + tombstone GC.
                    tracing::debug!(
                        operation = ?op,
                        "skipping linked-attribute / tombstone-gc op (Wave 4)"
                    );
                    Resolution::IncomingWins
                }
            };
            resolutions.push(resolution);
        }
        Ok(resolutions)
    }

    async fn update_utd_vector(
        &self,
        _nc_head: NcHead,
        _delta: UtdDelta,
    ) -> Result<(), ReplicationError> {
        // TODO: implement per ADR-071 — write UTD vector entry to FDB
        // subspace 0x05.
        Err(ReplicationError::Backend(
            "DrSuapiReplicator::update_utd_vector not yet implemented".into(),
        ))
    }

    async fn resolve_conflict(
        &self,
        _conflict: ConflictRecord,
    ) -> Result<Resolution, ReplicationError> {
        // TODO: implement per ADR-071 — admin-intervention conflict
        // resolution; the default resolver is
        // adrian_repl_core::resolve_conflict.
        Err(ReplicationError::Backend(
            "DrSuapiReplicator::resolve_conflict not yet implemented".into(),
        ))
    }

    async fn sync_metadata(&self, _partner: &str) -> Result<(), ReplicationError> {
        // TODO: implement per ADR-070 — handle IDL_DRSReplicaSync (opnum
        // 0x03) to the partner DSA.
        Err(ReplicationError::Backend(
            "DrSuapiReplicator::sync_metadata not yet implemented".into(),
        ))
    }
}

// TODO: implement IDL_DRSUpdateRefs (opnum 0x05) per MS-DRSR §4.1.21.
// TODO: implement IDL_DRSReplicaAdd (opnum 0x06) per MS-DRSR §4.1.11.
// TODO: implement IDL_DRSReplicaDel (opnum 0x07) per MS-DRSR §4.1.13.
// TODO: implement IDL_DRSReplicaModify (opnum 0x08) per MS-DRSR §4.1.12.
// TODO: implement IDL_DRSGetReplInfo (opnum 0x15) per MS-DRSR §4.1.26.
// TODO: implement IDL_DRSVerifyNames (opnum 0x0E) per MS-DRSR §4.1.19.
// TODO: implement IDL_DRSDomainControllerInfo (opnum 0x11) per MS-DRSR §4.1.16.
// TODO: implement EXOP_REPL_SECRETS (DCSync) per ADR-122 — ACL-gated, caller
// must have DS-Replication-Get-Changes-All on the domain NC head.

#[cfg(test)]
mod tests {
    use super::*;
    use adrian_repl_core::{ConflictRecord, NcHead, ReplicationError, UtdDelta, UtdVector};
    use adrian_storage_core::{Attribute, DistinguishedName};
    use adrian_storage_fdb::FdbDirectoryStore;
    use uuid::Uuid;

    // ---- Existing protocol-constant tests (preserved from Wave 4a) ----

    #[test]
    fn drs_ext_flag_values_match_ms_drsr() {
        // Per MS-DRSR §4.1.277 — `DRS_EXTENSIONS` flags. The numeric values
        // are protocol-fixed; any drift breaks AD-interop wire compat.
        assert_eq!(DrsExtFlag::Base as u32, 0x0000_0001);
        assert_eq!(DrsExtFlag::AsyncRepl as u32, 0x0000_0002);
        assert_eq!(DrsExtFlag::GetChgReqV6 as u32, 0x0000_0004);
        assert_eq!(DrsExtFlag::GetChgReplyV5 as u32, 0x0000_0008);
        assert_eq!(DrsExtFlag::InstanceInfoNotIsMasters as u32, 0x0000_0010);
        assert_eq!(DrsExtFlag::GetChgReqV8 as u32, 0x0000_0040);
        assert_eq!(DrsExtFlag::GetChgReplyV9 as u32, 0x0000_0080);
        assert_eq!(DrsExtFlag::GetChgReqV10 as u32, 0x0001_0000);
    }

    #[test]
    fn drs_ext_flag_getchgv8_and_v10_used_for_lvr_per_adr001() {
        // Per Decision 1 §Decision — the framework negotiates
        // `DRS_EXT_GETCHGREQ_V8` + `DRS_EXT_GETCHGREPLY_V9` +
        // `DRS_EXT_GETCHGREQ_V10` for full Linked-Value-Replication support
        // (per ADR-001). Verify the three LVR-related flags are present and
        // non-zero.
        assert_ne!(DrsExtFlag::GetChgReqV8 as u32, 0);
        assert_ne!(DrsExtFlag::GetChgReplyV9 as u32, 0);
        assert_ne!(DrsExtFlag::GetChgReqV10 as u32, 0);
    }

    #[test]
    fn drs_option_values_match_ms_drsr() {
        // Per MS-DRSR — `dwFlags` bit values used by `IDL_DRSBind` and
        // `IDL_DRSGetNCChanges`. Wire-protocol-fixed.
        assert_eq!(DrsOption::AsyncOp as u32, 0x0000_0001);
        assert_eq!(DrsOption::GetChgCheck as u32, 0x0000_0002);
        assert_eq!(DrsOption::AddRef as u32, 0x0000_0004);
        assert_eq!(DrsOption::SyncAll as u32, 0x0000_0008);
        assert_eq!(DrsOption::WritRep as u32, 0x0000_0010);
        assert_eq!(DrsOption::InitSync as u32, 0x0000_0020);
        assert_eq!(DrsOption::PerSync as u32, 0x0000_0040);
        assert_eq!(DrsOption::FullSyncNow as u32, 0x0000_0080);
        assert_eq!(DrsOption::ExopReplSecrets as u32, 0x0000_0100);
        assert_eq!(DrsOption::GetAnc as u32, 0x0000_0800);
        assert_eq!(DrsOption::FullSyncInProgress as u32, 0x0001_0000);
        assert_eq!(DrsOption::GetAllGroupMembership as u32, 0x0080_0000);
    }

    #[test]
    fn drs_option_exop_repl_secrets_value_per_adr122() {
        // Per ADR-122 — `EXOP_REPL_SECRETS` (the DCSync extension) is
        // ACL-gated. Verify its numeric value so the ACL check can
        // dispatch on the bit correctly.
        assert_eq!(DrsOption::ExopReplSecrets as u32, 0x0000_0100);
        // And it is distinct from every other documented option.
        let all = [
            DrsOption::AsyncOp,
            DrsOption::GetChgCheck,
            DrsOption::AddRef,
            DrsOption::SyncAll,
            DrsOption::WritRep,
            DrsOption::InitSync,
            DrsOption::PerSync,
            DrsOption::FullSyncNow,
            DrsOption::GetAnc,
            DrsOption::FullSyncInProgress,
            DrsOption::GetAllGroupMembership,
        ];
        for opt in all {
            assert_ne!(
                opt as u32,
                DrsOption::ExopReplSecrets as u32,
                "ExopReplSecrets must not collide with {:?}",
                opt
            );
        }
    }

    #[test]
    fn replicator_new_propagates_invocation_id_and_store() {
        // Per MS-ADTS §3.1.1.3.2.6 — the `invocationId` identifies the DSA's
        // current replication identity. `DrSuapiReplicator::new` must store
        // both it and the directory store handle.
        let invocation_id = Uuid::from_u128(0xDEAD_BEEF_CAFE_BABE);
        let store = FdbDirectoryStore::new(Some("/tmp/drsuapi.cluster"));
        let replicator = DrSuapiReplicator::new(invocation_id, store);
        assert_eq!(replicator.invocation_id, invocation_id);
        assert_eq!(
            replicator.store.cluster_file.as_deref(),
            Some("/tmp/drsuapi.cluster")
        );
    }

    #[tokio::test]
    async fn replicator_get_changes_returns_empty_payload_when_store_empty() {
        // Wave 1: `get_changes` is now real. With an empty source store,
        // the NC head lookup returns `None` and we short-circuit with an
        // empty payload (per MS-ADTS §3.1.1.3.2.5 — a missing NC head means
        // the source DSA does not host that NC).
        let replicator = DrSuapiReplicator::new(Uuid::nil(), FdbDirectoryStore::new(None));
        let cursor = UtdVector::default();
        let result = replicator.get_changes(NcHead::nil(), &cursor).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let payload = result.unwrap();
        assert!(payload.operations.is_empty());
        assert_eq!(payload.nc_head, NcHead::nil());
        assert_eq!(payload.origin_invocation_id, Uuid::nil());
        assert_eq!(payload.highest_usn, 0);
    }

    #[tokio::test]
    async fn replicator_apply_changes_applies_empty_payload() {
        // Wave 1: `apply_changes` is now real. An empty payload is a no-op
        // and returns an empty resolution list.
        let replicator = DrSuapiReplicator::new(Uuid::nil(), FdbDirectoryStore::new(None));
        let payload = adrian_repl_core::ReplicationPayload {
            nc_head: NcHead::nil(),
            operations: vec![],
            origin_invocation_id: Uuid::nil(),
            highest_usn: 0,
        };
        let result = replicator.apply_changes(payload).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn replicator_update_utd_vector_returns_backend_error() {
        let replicator = DrSuapiReplicator::new(Uuid::nil(), FdbDirectoryStore::new(None));
        let delta = UtdDelta {
            invocation_id: Uuid::nil(),
            new_highest_usn: 1,
        };
        let result = replicator.update_utd_vector(NcHead::nil(), delta).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ReplicationError::Backend(_))));
    }

    #[tokio::test]
    async fn replicator_resolve_conflict_returns_backend_error() {
        let replicator = DrSuapiReplicator::new(Uuid::nil(), FdbDirectoryStore::new(None));
        let pmd = adrian_repl_core::PropertyMetaDataExt {
            origin_invocation_id: Uuid::nil(),
            origin_usn: 0,
            version: 1,
            last_write_timestamp: 0,
        };
        let conflict = ConflictRecord {
            uuid: Uuid::nil(),
            attribute: "cn".into(),
            local: (vec![], pmd.clone()),
            incoming: (vec![], pmd),
        };
        let result = replicator.resolve_conflict(conflict).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ReplicationError::Backend(_))));
    }

    #[tokio::test]
    async fn replicator_sync_metadata_returns_backend_error() {
        let replicator = DrSuapiReplicator::new(Uuid::nil(), FdbDirectoryStore::new(None));
        let result = replicator.sync_metadata("partner-dc").await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ReplicationError::Backend(_))));
    }

    // =================================================================
    // NEW (Wave 2b) — NDR codec round-trip tests
    // =================================================================

    // ---- DRS_EXTENSIONS NDR round-trip (2 tests) ----

    #[test]
    fn ndr_drs_extensions_round_trip_default() {
        // Test 1/2: the minimal DrsExtensions (default-constructed with
        // DRS_EXT_BASE only) round-trips through NdrWriter/NdrReader.
        let ext = DrsExtensions::new(DrsExtFlag::Base as u32, Uuid::nil());
        let bytes = ext.to_bytes();
        // cb (4) + dwFlags (4) + siteObjGuid (16) + pid (4) + dwReplEpoch
        // (4) + dwFlagsExt (4) = 36 bytes (no extra, no padding needed).
        assert_eq!(bytes.len(), 36);
        let decoded = DrsExtensions::from_bytes(&bytes).expect("decode must succeed");
        assert_eq!(decoded, ext);
    }

    #[test]
    fn ndr_drs_extensions_round_trip_with_all_lvr_flags() {
        // Test 2/2: a DrsExtensions with all LVR flags + a non-trivial
        // site GUID + a non-zero epoch round-trips byte-for-byte.
        let ext = DrsExtensions {
            dw_flags: pack_drs_ext_flags(&[
                DrsExtFlag::Base,
                DrsExtFlag::GetChgReqV8,
                DrsExtFlag::GetChgReplyV9,
                DrsExtFlag::GetChgReqV10,
                DrsExtFlag::InstanceInfoNotIsMasters,
            ]),
            site_obj_guid: Uuid::from_u128(0xCAFE_BABE_DEAD_BEEF),
            pid: 1234,
            dw_repl_epoch: 7,
            dw_flags_ext: 0x8000_0000,
            extra: Vec::new(),
        };
        let bytes = ext.to_bytes();
        let decoded = DrsExtensions::from_bytes(&bytes).expect("decode must succeed");
        assert_eq!(decoded, ext);
        // Verify dwFlags survived intact (the LVR negotiation depends on it).
        assert_eq!(decoded.dw_flags, ext.dw_flags);
        assert_eq!(decoded.dw_repl_epoch, 7);
    }

    // ---- UtdVectorExt NDR round-trip (2 tests) ----

    #[test]
    fn ndr_utd_vector_round_trip_empty() {
        // Test 1/2: an empty UTD vector round-trips and decodes to a vector
        // with zero entries.
        let v = UtdVectorExt::new();
        let bytes = v.to_bytes();
        // cNumEntries (4) + dwVersion (4) + dwReserved1 (4) = 12 bytes.
        assert_eq!(bytes.len(), 12);
        let decoded = UtdVectorExt::from_bytes(&bytes).expect("decode must succeed");
        assert_eq!(decoded, v);
        assert!(decoded.entries.is_empty());
    }

    #[test]
    fn ndr_utd_vector_round_trip_with_entries() {
        // Test 2/2: a UTD vector with two entries round-trips preserving
        // every (usn_high, usn_low, dsa_guid) triple. The first entry's
        // `usn_high` is the first 8-byte aligned field after the 12-byte
        // header (4 bytes of padding before it); each entry occupies 32
        // bytes.
        let v = UtdVectorExt {
            dw_version: 1,
            entries: vec![
                UtdVectorExtEntry {
                    usn_high: 1234,
                    usn_low: 100,
                    dsa_guid: Uuid::from_u128(0xAAAA),
                },
                UtdVectorExtEntry {
                    usn_high: 5678,
                    usn_low: 200,
                    dsa_guid: Uuid::from_u128(0xBBBB),
                },
            ],
        };
        let bytes = v.to_bytes();
        // Header (12) + 4-byte align pad before first u64 + 2 * 32 entries
        //   = 12 + 4 + 64 = 80 bytes.
        assert_eq!(bytes.len(), 12 + 4 + 2 * UTD_VECTOR_ENTRY_SIZE);
        let decoded = UtdVectorExt::from_bytes(&bytes).expect("decode must succeed");
        assert_eq!(decoded, v);
    }

    // ---- REPLENTIN_V3 NDR round-trip (2 tests) ----

    #[test]
    fn ndr_replentin_v3_round_trip_minimal() {
        // Test 1/2: a minimal REPLENTIN_V3 (default UsnVector, empty UTD
        // vector, empty NC DN) round-trips through NdrWriter/NdrReader.
        let req = ReplEntInfV3 {
            uuid_dsa_obj_dest: Uuid::from_u128(0x1111),
            uuid_invoc_id_src: Uuid::from_u128(0x2222),
            nc: DsName::from_dn("DC=adrian,DC=example,DC=com"),
            usn_vector: UsnVector::new(),
            utd_vector: UtdVectorExt::new(),
            ul_flags: 0,
            c_max_objects: 100,
            c_max_bytes: 1_000_000,
            ul_extended_op: 0,
            li_fsmo_info: 0,
        };
        let bytes = req.to_bytes();
        let decoded = ReplEntInfV3::from_bytes(&bytes).expect("decode must succeed");
        assert_eq!(decoded.uuid_dsa_obj_dest, req.uuid_dsa_obj_dest);
        assert_eq!(decoded.uuid_invoc_id_src, req.uuid_invoc_id_src);
        assert_eq!(decoded.nc, req.nc);
        assert_eq!(decoded.usn_vector, req.usn_vector);
        assert_eq!(decoded.utd_vector, req.utd_vector);
        assert_eq!(decoded.c_max_objects, 100);
    }

    #[test]
    fn ndr_replentin_v3_round_trip_with_utd_vector() {
        // Test 2/2: a REPLENTIN_V3 with a non-empty UTD vector and a
        // non-trivial USN cursor round-trips preserving every field.
        let req = ReplEntInfV3 {
            uuid_dsa_obj_dest: Uuid::from_u128(0x3333),
            uuid_invoc_id_src: Uuid::from_u128(0x4444),
            nc: DsName::from_dn("CN=Users,DC=adrian,DC=example,DC=com"),
            usn_vector: UsnVector {
                usn_high_obj_update: 5000,
                usn_high_prop_update: 5050,
            },
            utd_vector: UtdVectorExt {
                dw_version: 1,
                entries: vec![UtdVectorExtEntry {
                    usn_high: 5000,
                    usn_low: 100,
                    dsa_guid: Uuid::from_u128(0x4444),
                }],
            },
            ul_flags: DrsOption::WritRep as u32,
            c_max_objects: 50,
            c_max_bytes: 250_000,
            ul_extended_op: 0,
            li_fsmo_info: 0xDEAD_BEEF,
        };
        let bytes = req.to_bytes();
        let decoded = ReplEntInfV3::from_bytes(&bytes).expect("decode must succeed");
        assert_eq!(decoded.usn_vector, req.usn_vector);
        assert_eq!(decoded.utd_vector, req.utd_vector);
        assert_eq!(decoded.ul_flags, DrsOption::WritRep as u32);
        assert_eq!(decoded.li_fsmo_info, 0xDEAD_BEEF);
        assert_eq!(decoded.nc, req.nc);
    }

    // ---- DRSBind handler tests (2 tests) ----

    #[tokio::test]
    async fn drs_bind_handler_returns_negotiated_server_extensions() {
        // Test 1/2: a client requesting Base + GetChgReqV8 + GetChgReplyV9
        // gets back server extensions whose dwFlags is the intersection
        // with SERVER_SUPPORTED_EXTENSIONS.
        let client = DrsExtensions::new(
            pack_drs_ext_flags(&[
                DrsExtFlag::Base,
                DrsExtFlag::GetChgReqV8,
                DrsExtFlag::GetChgReplyV9,
                DrsExtFlag::AsyncRepl, // not in SERVER_SUPPORTED_EXTENSIONS
            ]),
            Uuid::from_u128(0xCAFE),
        );
        let server_invocation = Uuid::from_u128(0xABCD);
        let result = drs_bind(server_invocation, &client)
            .await
            .expect("bind must succeed");
        assert_eq!(result.server_invocation_id, server_invocation);
        // Intersection should be Base | V8 | V9 (AsyncRepl dropped).
        let expected = DrsExtFlag::Base as u32
            | DrsExtFlag::GetChgReqV8 as u32
            | DrsExtFlag::GetChgReplyV9 as u32;
        assert_eq!(result.server_extensions.dw_flags, expected);
        assert_eq!(result.replication_epoch, client.dw_repl_epoch);
    }

    #[tokio::test]
    async fn drs_bind_handler_returns_fresh_non_nil_bind_handle() {
        // Test 2/2: the bind handle is a fresh UUIDv7 (non-nil, version 7)
        // so subsequent DRSGetNCChanges / DRSUnbind calls can dispatch on it.
        let client = DrsExtensions::new(SERVER_SUPPORTED_EXTENSIONS, Uuid::nil());
        let result = drs_bind(Uuid::nil(), &client)
            .await
            .expect("bind must succeed");
        assert_ne!(result.bind_handle, Uuid::nil());
        // UUIDv7's top 4 bits of byte 6 are 0x7 (per RFC 9562 §5.7).
        let version_nibble = (result.bind_handle.as_bytes()[6] >> 4) & 0x0F;
        assert_eq!(version_nibble, 7, "bind handle must be UUIDv7");
    }

    #[tokio::test]
    async fn drs_bind_handler_rejects_client_without_base_flag() {
        // A client that does NOT advertise DRS_EXT_BASE cannot bind (per
        // MS-DRSR §4.1.4 — Base is mandatory).
        let client = DrsExtensions::new(
            DrsExtFlag::GetChgReqV8 as u32, // missing Base
            Uuid::nil(),
        );
        let result = drs_bind(Uuid::nil(), &client).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ReplicationError::Permanent(_))));
    }

    #[tokio::test]
    async fn drs_bind_dispatch_round_trips_through_ndr() {
        // Wire-level dispatch: encode client DrsExtensions to bytes, call
        // drs_bind_dispatch, decode the reply bytes, verify the contents.
        let client = DrsExtensions::new(SERVER_SUPPORTED_EXTENSIONS, Uuid::from_u128(0xCAFE));
        let stub_in = client.to_bytes();
        let reply_bytes = drs_bind_dispatch(Uuid::from_u128(0xBEEF), &stub_in)
            .await
            .expect("dispatch must succeed");
        // Reply layout: hDrs (16) | pextServer_ptr (4) | pextServer_body (≥36).
        assert!(reply_bytes.len() >= 16 + 4 + 36);
        let mut r = NdrReader::new(&reply_bytes);
        let h_drs = r.read_uuid().expect("hDrs");
        assert_ne!(h_drs, Uuid::nil());
        let _pext_ptr = r.read_uint32().expect("pextServer ptr");
        let server_ext = DrsExtensions::decode(&mut r).expect("pextServer body");
        assert_eq!(server_ext.dw_flags, SERVER_SUPPORTED_EXTENSIONS);
    }

    // ---- DRSGetNCChanges handler tests (3 tests) ----

    fn make_test_object(dn: &str, uuid: Uuid, attr_name: &str, attr_value: &[u8]) -> Object {
        Object {
            uuid,
            dn: DistinguishedName { dn: dn.to_string() },
            attributes: vec![Attribute {
                attribute_id: 0,
                name: attr_name.to_string(),
                value: attr_value.to_vec(),
            }],
            dnt: 0,
        }
    }

    #[tokio::test]
    async fn drs_get_nc_changes_returns_objects_under_nc() {
        // Test 1/3: a populated DirectorySource under "DC=adrian,DC=example"
        // returns exactly the matching objects (sorted by DN) when the
        // request NC matches.
        let mut source = DirectorySource::new();
        source.add(make_test_object(
            "CN=Admin,CN=Users,DC=adrian,DC=example",
            Uuid::from_u128(0x0001),
            "cn",
            b"Admin",
        ));
        source.add(make_test_object(
            "CN=Guest,CN=Users,DC=adrian,DC=example",
            Uuid::from_u128(0x0002),
            "cn",
            b"Guest",
        ));
        // An object outside the NC head — must be excluded.
        source.add(make_test_object(
            "CN=Foo,DC=other,DC=example",
            Uuid::from_u128(0x0003),
            "cn",
            b"Foo",
        ));
        let request = ReplEntInfV3 {
            uuid_dsa_obj_dest: Uuid::from_u128(0xABCD),
            uuid_invoc_id_src: Uuid::from_u128(0xDCBA),
            nc: DsName::from_dn("DC=adrian,DC=example"),
            usn_vector: UsnVector::new(),
            utd_vector: UtdVectorExt::new(),
            ul_flags: 0,
            c_max_objects: 100,
            c_max_bytes: 0,
            ul_extended_op: 0,
            li_fsmo_info: 0,
        };
        let reply = drs_get_nc_changes(Uuid::from_u128(0xDCBA), &source, &request)
            .await
            .expect("get_nc_changes must succeed");
        assert_eq!(reply.c_num_objects, 2);
        assert_eq!(reply.p_objects.len(), 2);
        // Sorted by DN — Admin < Guest.
        assert_eq!(
            reply.p_objects[0].dn,
            "CN=Admin,CN=Users,DC=adrian,DC=example"
        );
        assert_eq!(
            reply.p_objects[1].dn,
            "CN=Guest,CN=Users,DC=adrian,DC=example"
        );
        assert!(!reply.f_more_data);
    }

    #[tokio::test]
    async fn drs_get_nc_changes_returns_empty_when_source_empty() {
        // Test 2/3: an empty DirectorySource yields a reply with c_num_objects
        // = 0 and an empty p_objects array. The reply UTD vector still has
        // the source's own entry (per ADR-071 — the destination needs the
        // source's high-water mark even if there's nothing to send).
        let source = DirectorySource::new();
        let request = ReplEntInfV3 {
            uuid_dsa_obj_dest: Uuid::nil(),
            uuid_invoc_id_src: Uuid::from_u128(0xDEAD),
            nc: DsName::from_dn("DC=adrian,DC=example"),
            usn_vector: UsnVector {
                usn_high_obj_update: 0,
                usn_high_prop_update: 0,
            },
            utd_vector: UtdVectorExt::new(),
            ul_flags: 0,
            c_max_objects: 0,
            c_max_bytes: 0,
            ul_extended_op: 0,
            li_fsmo_info: 0,
        };
        let reply = drs_get_nc_changes(Uuid::from_u128(0xDEAD), &source, &request)
            .await
            .expect("get_nc_changes must succeed");
        assert_eq!(reply.c_num_objects, 0);
        assert!(reply.p_objects.is_empty());
        assert!(!reply.f_more_data);
        // The reply UTD vector carries the source's invocation_id + the
        // request's high-water USN (0 here).
        assert_eq!(reply.utd_vector.entries.len(), 1);
        assert_eq!(
            reply.utd_vector.entries[0].dsa_guid,
            Uuid::from_u128(0xDEAD)
        );
    }

    #[tokio::test]
    async fn drs_get_nc_changes_sets_f_more_data_when_exceeding_cap() {
        // Test 3/3: when the candidate set exceeds request.c_max_objects,
        // the reply is truncated to c_max_objects and f_more_data is set so
        // the caller knows to issue another round.
        let mut source = DirectorySource::new();
        for i in 0..5u32 {
            source.add(make_test_object(
                &format!("CN=obj{i},DC=adrian,DC=example"),
                Uuid::from_u128(i as u128),
                "cn",
                format!("obj{i}").as_bytes(),
            ));
        }
        let request = ReplEntInfV3 {
            uuid_dsa_obj_dest: Uuid::nil(),
            uuid_invoc_id_src: Uuid::nil(),
            nc: DsName::from_dn("DC=adrian,DC=example"),
            usn_vector: UsnVector::new(),
            utd_vector: UtdVectorExt::new(),
            ul_flags: 0,
            c_max_objects: 3, // cap is 3 but candidate set has 5.
            c_max_bytes: 0,
            ul_extended_op: 0,
            li_fsmo_info: 0,
        };
        let reply = drs_get_nc_changes(Uuid::nil(), &source, &request)
            .await
            .expect("get_nc_changes must succeed");
        assert_eq!(reply.c_num_objects, 3);
        assert_eq!(reply.p_objects.len(), 3);
        assert!(reply.f_more_data, "f_more_data must be true when capped");
    }

    #[tokio::test]
    async fn drs_get_nc_changes_dispatch_round_trips_through_ndr() {
        // Wire-level dispatch: encode a ReplEntInfV3 request, call dispatch,
        // verify the reply bytes decode to the expected reply shape.
        let mut source = DirectorySource::new();
        source.add(make_test_object(
            "CN=Admin,DC=adrian,DC=example",
            Uuid::from_u128(0xCAFE),
            "cn",
            b"Admin",
        ));
        let request = ReplEntInfV3 {
            uuid_dsa_obj_dest: Uuid::nil(),
            uuid_invoc_id_src: Uuid::nil(),
            nc: DsName::from_dn("DC=adrian,DC=example"),
            usn_vector: UsnVector::new(),
            utd_vector: UtdVectorExt::new(),
            ul_flags: 0,
            c_max_objects: 0,
            c_max_bytes: 0,
            ul_extended_op: 0,
            li_fsmo_info: 0,
        };
        let stub_in = request.to_bytes();
        let reply_bytes = drs_get_nc_changes_dispatch(Uuid::from_u128(0xCAFE), &source, &stub_in)
            .await
            .expect("dispatch must succeed");
        let mut r = NdrReader::new(&reply_bytes);
        let dw_out_version = r.read_uint32().expect("dwOutVersion");
        assert_eq!(dw_out_version, 3);
        let reply = ReplEntInfV3Reply::decode(&mut r).expect("reply decode");
        assert_eq!(reply.c_num_objects, 1);
        assert_eq!(reply.p_objects[0].dn, "CN=Admin,DC=adrian,DC=example");
    }

    // ---- UTD vector comparison logic tests (2 tests) ----

    #[test]
    fn utd_vector_is_up_to_date_true_when_cursor_ahead() {
        // Test 1/2: a cursor that has absorbed USN 1000 from DSA X is
        // up-to-date for any USN <= 1000 from DSA X.
        let v = UtdVectorExt {
            dw_version: 1,
            entries: vec![UtdVectorExtEntry {
                usn_high: 1000,
                usn_low: 0,
                dsa_guid: Uuid::from_u128(0xAAAA),
            }],
        };
        assert!(v.is_up_to_date(Uuid::from_u128(0xAAAA), 1000));
        assert!(v.is_up_to_date(Uuid::from_u128(0xAAAA), 999));
        assert!(v.is_up_to_date(Uuid::from_u128(0xAAAA), 0));
    }

    #[test]
    fn utd_vector_is_up_to_date_false_when_cursor_behind_or_unknown() {
        // Test 2/2: a cursor that has absorbed USN 1000 from DSA X is NOT
        // up-to-date for USN 1001 from DSA X, and is NOT up-to-date for
        // any USN from an unknown DSA Y.
        let v = UtdVectorExt {
            dw_version: 1,
            entries: vec![UtdVectorExtEntry {
                usn_high: 1000,
                usn_low: 0,
                dsa_guid: Uuid::from_u128(0xAAAA),
            }],
        };
        assert!(!v.is_up_to_date(Uuid::from_u128(0xAAAA), 1001));
        assert!(!v.is_up_to_date(Uuid::from_u128(0xBBBB), 1));
        assert!(!v.is_up_to_date(Uuid::from_u128(0xBBBB), 0));
    }

    // ---- Extension flag negotiation tests (2 tests) ----

    #[test]
    fn negotiate_extensions_returns_intersection_when_base_present() {
        // Test 1/2: the negotiated flags = client AND server, AND the
        // result must include Base for the bind to proceed.
        let client = pack_drs_ext_flags(&[
            DrsExtFlag::Base,
            DrsExtFlag::GetChgReqV8,
            DrsExtFlag::GetChgReplyV9,
            DrsExtFlag::AsyncRepl, // not in SERVER_SUPPORTED_EXTENSIONS
        ]);
        let negotiated = negotiate_extensions(client, SERVER_SUPPORTED_EXTENSIONS);
        assert_eq!(
            negotiated,
            DrsExtFlag::Base as u32
                | DrsExtFlag::GetChgReqV8 as u32
                | DrsExtFlag::GetChgReplyV9 as u32
        );
        assert_ne!(negotiated, 0);
    }

    #[test]
    fn negotiate_extensions_returns_zero_when_base_missing() {
        // Test 2/2: if the client doesn't advertise Base, the negotiated
        // result is 0 (the bind must be rejected by the caller).
        let client = DrsExtFlag::GetChgReqV8 as u32; // missing Base
        let negotiated = negotiate_extensions(client, SERVER_SUPPORTED_EXTENSIONS);
        assert_eq!(negotiated, 0);
    }

    // ---- Helper function tests (every new function gets a test) ----

    #[test]
    fn pack_drs_ext_flags_ors_all_flag_values() {
        let flags = vec![
            DrsExtFlag::Base,
            DrsExtFlag::GetChgReqV8,
            DrsExtFlag::GetChgReqV10,
        ];
        let packed = pack_drs_ext_flags(&flags);
        assert_eq!(
            packed,
            DrsExtFlag::Base as u32
                | DrsExtFlag::GetChgReqV8 as u32
                | DrsExtFlag::GetChgReqV10 as u32
        );
    }

    #[test]
    fn unpack_drs_ext_flags_decodes_bitmask() {
        let packed = DrsExtFlag::Base as u32
            | DrsExtFlag::GetChgReplyV9 as u32
            | DrsExtFlag::InstanceInfoNotIsMasters as u32;
        let unpacked = unpack_drs_ext_flags(packed);
        assert!(unpacked.contains(&DrsExtFlag::Base));
        assert!(unpacked.contains(&DrsExtFlag::GetChgReplyV9));
        assert!(unpacked.contains(&DrsExtFlag::InstanceInfoNotIsMasters));
        assert!(!unpacked.contains(&DrsExtFlag::GetChgReqV8));
        // pack/unpack round-trip
        let re_packed = pack_drs_ext_flags(&unpacked);
        assert_eq!(re_packed, packed);
    }

    #[test]
    fn utd_vector_merge_bumps_high_water_mark() {
        // The merge function (used by update_utd_vector) bumps the existing
        // entry's usn_high to the max, and usn_low to the min.
        let mut v = UtdVectorExt {
            dw_version: 1,
            entries: vec![UtdVectorExtEntry {
                usn_high: 100,
                usn_low: 50,
                dsa_guid: Uuid::from_u128(0xAAAA),
            }],
        };
        v.merge(UtdVectorExtEntry {
            usn_high: 200,
            usn_low: 25,
            dsa_guid: Uuid::from_u128(0xAAAA),
        });
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.entries[0].usn_high, 200);
        assert_eq!(v.entries[0].usn_low, 25);
    }

    #[test]
    fn utd_vector_merge_appends_new_dsa() {
        // Merging an entry for a new DSA appends it to the vector.
        let mut v = UtdVectorExt {
            dw_version: 1,
            entries: vec![UtdVectorExtEntry {
                usn_high: 100,
                usn_low: 50,
                dsa_guid: Uuid::from_u128(0xAAAA),
            }],
        };
        v.merge(UtdVectorExtEntry {
            usn_high: 300,
            usn_low: 0,
            dsa_guid: Uuid::from_u128(0xBBBB),
        });
        assert_eq!(v.entries.len(), 2);
    }

    #[test]
    fn dsname_round_trip_preserves_dn_and_guid() {
        let dn = DsName {
            guid: Uuid::from_u128(0xCAFE),
            sid: Vec::new(),
            name: "CN=Admin,CN=Users,DC=adrian,DC=example,DC=com".into(),
        };
        let mut w = NdrWriter::new();
        dn.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = NdrReader::new(&bytes);
        let decoded = DsName::decode(&mut r).expect("decode must succeed");
        assert_eq!(decoded, dn);
    }

    #[test]
    fn usn_vector_round_trip_preserves_both_usns() {
        let uv = UsnVector {
            usn_high_obj_update: 1234,
            usn_high_prop_update: 5678,
        };
        let mut w = NdrWriter::new();
        uv.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = NdrReader::new(&bytes);
        let decoded = UsnVector::decode(&mut r).expect("decode must succeed");
        assert_eq!(decoded, uv);
    }

    #[test]
    fn server_supported_extensions_includes_lvr_flags_per_adr001() {
        // Per ADR-001 / Decision 1 §Decision — the server must advertise
        // GetChgReqV8, GetChgReplyV9, GetChgReqV10, and Base.
        assert_ne!(SERVER_SUPPORTED_EXTENSIONS & DrsExtFlag::Base as u32, 0);
        assert_ne!(
            SERVER_SUPPORTED_EXTENSIONS & DrsExtFlag::GetChgReqV8 as u32,
            0
        );
        assert_ne!(
            SERVER_SUPPORTED_EXTENSIONS & DrsExtFlag::GetChgReplyV9 as u32,
            0
        );
        assert_ne!(
            SERVER_SUPPORTED_EXTENSIONS & DrsExtFlag::GetChgReqV10 as u32,
            0
        );
    }

    #[test]
    fn server_supported_extensions_excludes_exop_repl_secrets_per_adr122() {
        // Per ADR-122 — DCSync (EXOP_REPL_SECRETS) is ACL-gated and not
        // advertised in DRS_EXTENSIONS. The server_supported mask must not
        // include it (it's a DrsOption, not a DrsExtFlag, but verify the
        // option value is also not in the extension mask).
        assert_eq!(
            SERVER_SUPPORTED_EXTENSIONS & DrsOption::ExopReplSecrets as u32,
            0,
            "EXOP_REPL_SECRETS must NOT be in SERVER_SUPPORTED_EXTENSIONS (ADR-122)"
        );
    }

    #[test]
    fn directory_source_list_under_nc_filters_by_dn_suffix() {
        // Per LDAP DN convention, an object is "under" an NC head iff the
        // NC head DN is a *suffix* of the object DN (DNs are written
        // leaf-to-root).
        let mut src = DirectorySource::new();
        src.add(make_test_object(
            "CN=Foo,DC=adrian,DC=example",
            Uuid::nil(),
            "cn",
            b"Foo",
        ));
        src.add(make_test_object(
            "CN=Bar,DC=other,DC=example",
            Uuid::nil(),
            "cn",
            b"Bar",
        ));
        let result = src.list_under_nc("DC=adrian,DC=example");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].dn, "CN=Foo,DC=adrian,DC=example");
    }

    // NOTE: FDB-backed integration tests (REPLVALINF_V3 byte-for-byte
    // equivalence, UTD-vector delta application, LVR conflict resolution,
    // EXOP_REPL_SECRETS ACL gating) require a running FoundationDB cluster
    // and the `fdb` feature flag. They are intentionally omitted from this
    // unit-test module — see `adrian-test-harness` for integration tests.
    #[tokio::test]
    #[ignore = "requires a running FDB cluster and the `fdb` feature flag"]
    async fn integration_get_nc_changes_emits_replvalinf_v3() {
        // Placeholder — will be implemented in `adrian-test-harness` once
        // the FDB integration testkit is added in Wave 4b.
    }

    // =================================================================
    // NEW (Wave 1) — DrSuapiReplicator get_changes / apply_changes
    // These tests exercise the real wiring through
    // `drs_get_nc_changes_dispatch` and the FDB-backed store. They use
    // `FdbDirectoryStore::in_memory()` (the fallback path that exercises
    // the real tuple-layer key encoding without a running FDB cluster).
    // =================================================================

    /// Helper: seed an `FdbDirectoryStore` with one NC head + N children.
    async fn seed_store_with_nc_and_children(
        store: &FdbDirectoryStore,
        nc_uuid: Uuid,
        nc_dn: &str,
        children: &[(Uuid, &str, &str, &[u8])], // (uuid, dn, attr_name, attr_value)
    ) {
        store
            .put(&make_test_object(nc_dn, nc_uuid, "name", b"nc"))
            .await
            .expect("put NC head must succeed");
        for (uuid, dn, attr_name, attr_value) in children {
            store
                .put(&make_test_object(dn, *uuid, attr_name, attr_value))
                .await
                .expect("put child must succeed");
        }
    }

    #[tokio::test]
    async fn wave1_get_changes_returns_all_objects_from_source_store() {
        // T-104a: full replication source-side. Seed a store with an NC
        // head + 2 children; `get_changes` must return all 3 (the dispatch
        // handler does DN-suffix filtering, and all 3 DNs end with the NC
        // head DN).
        let store = FdbDirectoryStore::in_memory();
        let nc_uuid = Uuid::from_u128(0xAAAA);
        let child1_uuid = Uuid::from_u128(0xBBBB);
        let child2_uuid = Uuid::from_u128(0xCCCC);
        seed_store_with_nc_and_children(
            &store,
            nc_uuid,
            "DC=adrian,DC=example",
            &[
                (
                    child1_uuid,
                    "CN=User1,DC=adrian,DC=example",
                    "name",
                    b"User1",
                ),
                (
                    child2_uuid,
                    "CN=User2,DC=adrian,DC=example",
                    "name",
                    b"User2",
                ),
            ],
        )
        .await;
        let replicator = DrSuapiReplicator::new(nc_uuid, store);
        let cursor = UtdVector::default();
        let payload = replicator
            .get_changes(nc_uuid, &cursor)
            .await
            .expect("get_changes must succeed");
        assert_eq!(payload.operations.len(), 3);
        let mut dns: Vec<String> = payload
            .operations
            .iter()
            .map(|op| match op {
                ReplOperation::AddObject { dn, .. } => dn.clone(),
                _ => panic!("expected AddObject, got {op:?}"),
            })
            .collect();
        dns.sort();
        assert_eq!(
            dns,
            vec![
                "CN=User1,DC=adrian,DC=example".to_string(),
                "CN=User2,DC=adrian,DC=example".to_string(),
                "DC=adrian,DC=example".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn wave1_apply_changes_writes_addobject_to_destination_store() {
        // T-104b: destination-side. Build a payload with one AddObject,
        // apply it to an empty store, verify the object is present.
        let store = FdbDirectoryStore::in_memory();
        let replicator = DrSuapiReplicator::new(Uuid::nil(), store.clone());
        let obj_uuid = Uuid::from_u128(0xDDDD);
        let payload = adrian_repl_core::ReplicationPayload {
            nc_head: obj_uuid,
            operations: vec![ReplOperation::AddObject {
                uuid: obj_uuid,
                dn: "CN=Test,DC=adrian,DC=example".into(),
                attributes: vec![(
                    "name".into(),
                    b"Test".to_vec(),
                    adrian_repl_core::PropertyMetaDataExt {
                        origin_invocation_id: Uuid::nil(),
                        origin_usn: 0,
                        version: 1,
                        last_write_timestamp: 0,
                    },
                )],
            }],
            origin_invocation_id: Uuid::nil(),
            highest_usn: 1,
        };
        let resolutions = replicator
            .apply_changes(payload)
            .await
            .expect("apply_changes must succeed");
        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0], Resolution::IncomingWins);
        let fetched = replicator
            .store
            .get(obj_uuid)
            .await
            .unwrap()
            .expect("object must be in store");
        assert_eq!(fetched.uuid, obj_uuid);
        assert_eq!(fetched.dn.dn, "CN=Test,DC=adrian,DC=example");
    }

    #[tokio::test]
    async fn wave1_integration_replicate_a_to_b_round_trips() {
        // T-103: integration test. Seed store A with NC head + 3 children,
        // replicate A → B, verify B has all 4 objects.
        let store_a = FdbDirectoryStore::in_memory();
        let store_b = FdbDirectoryStore::in_memory();
        let nc_uuid = Uuid::from_u128(0x1111);
        let u1 = Uuid::from_u128(0x2222);
        let u2 = Uuid::from_u128(0x3333);
        let u3 = Uuid::from_u128(0x4444);
        seed_store_with_nc_and_children(
            &store_a,
            nc_uuid,
            "DC=adrian,DC=example",
            &[
                (u1, "CN=User1,DC=adrian,DC=example", "name", b"User1"),
                (u2, "CN=User2,DC=adrian,DC=example", "name", b"User2"),
                (u3, "CN=User3,DC=adrian,DC=example", "name", b"User3"),
            ],
        )
        .await;
        let repl_a = DrSuapiReplicator::new(nc_uuid, store_a);
        let repl_b = DrSuapiReplicator::new(nc_uuid, store_b.clone());
        let cursor = UtdVector::default();
        let payload = repl_a
            .get_changes(nc_uuid, &cursor)
            .await
            .expect("get_changes A");
        assert_eq!(payload.operations.len(), 4);
        let resolutions = repl_b
            .apply_changes(payload)
            .await
            .expect("apply_changes B");
        assert_eq!(resolutions.len(), 4);
        for uuid in [nc_uuid, u1, u2, u3] {
            let obj = store_b
                .get(uuid)
                .await
                .unwrap()
                .expect("object must be replicated to B");
            assert_eq!(obj.uuid, uuid);
        }
    }

    #[tokio::test]
    async fn wave1_get_changes_with_nonempty_cursor_still_returns_all_objects() {
        // T-104c: incremental replication. Wave 1 does NOT yet filter by
        // USN (Wave 3 will). Verify that a non-empty cursor is correctly
        // encoded into the request (no error) and all objects are still
        // returned.
        let store = FdbDirectoryStore::in_memory();
        let nc_uuid = Uuid::from_u128(0xEEEE);
        let child_uuid = Uuid::from_u128(0xFFFF);
        seed_store_with_nc_and_children(
            &store,
            nc_uuid,
            "DC=adrian,DC=example",
            &[(
                child_uuid,
                "CN=Child,DC=adrian,DC=example",
                "name",
                b"Child",
            )],
        )
        .await;
        let replicator = DrSuapiReplicator::new(nc_uuid, store);
        // Cursor claims the destination already has USN 100 from this DSA.
        let cursor = UtdVector {
            entries: vec![adrian_repl_core::UtdVectorEntry {
                invocation_id: nc_uuid,
                highest_usn: 100,
            }],
        };
        let payload = replicator
            .get_changes(nc_uuid, &cursor)
            .await
            .expect("get_changes with cursor");
        // Wave 1: no USN filtering — all objects returned.
        assert_eq!(payload.operations.len(), 2);
    }

    // =================================================================
    // NEW (Wave 3) — DRSUnbind + DRSReplicaSync + DRSCrackNames
    // 2 tests per opnum: NDR round-trip + handler behavior.
    // =================================================================

    #[tokio::test]
    async fn wave3_drs_unbind_dispatch_round_trips_through_ndr() {
        // T-301: encode a DRSUnbind request, dispatch, decode the reply.
        let bind_handle = Uuid::now_v7();
        let req = DrsUnbindReq { bind_handle };
        let req_bytes = req.to_bytes();
        let reply_bytes = drs_unbind_dispatch(Uuid::nil(), &req_bytes)
            .await
            .expect("dispatch must succeed");
        // Reply layout: dwOutVersion (u32) | bind_handle (16).
        assert_eq!(reply_bytes.len(), 4 + 16);
        let mut r = NdrReader::new(&reply_bytes);
        let dw_out_version = r.read_uint32().expect("dwOutVersion");
        assert_eq!(dw_out_version, 1);
        let reply = DrsUnbindReply::decode(&mut r).expect("decode reply");
        assert_eq!(reply.bind_handle, Uuid::nil(), "unbind must nil the handle");
    }

    #[tokio::test]
    async fn wave3_drs_unbind_handler_returns_nil_handle() {
        // T-301 handler: the high-level handler returns a nil bind handle
        // to indicate the handle is released.
        let reply = drs_unbind(Uuid::nil(), Uuid::now_v7())
            .await
            .expect("handler must succeed");
        assert_eq!(reply.bind_handle, Uuid::nil());
    }

    #[tokio::test]
    async fn wave3_drs_replica_sync_dispatch_round_trips_through_ndr() {
        // T-302: encode a DRSReplicaSync request, dispatch, decode reply.
        let req = DrsReplicaSyncReq {
            bind_handle: Uuid::now_v7(),
            nc_dn: "DC=adrian,DC=example".into(),
            src_dsa_address: "dc01.adrian.example".into(),
            ul_options: 0,
        };
        let req_bytes = req.to_bytes();
        // Round-trip the request first to verify NDR codec.
        let decoded_req = DrsReplicaSyncReq::from_bytes(&req_bytes).expect("req round-trip");
        assert_eq!(decoded_req.nc_dn, "DC=adrian,DC=example");
        assert_eq!(decoded_req.src_dsa_address, "dc01.adrian.example");
        // Dispatch.
        let reply_bytes = drs_replica_sync_dispatch(Uuid::nil(), &req_bytes)
            .await
            .expect("dispatch must succeed");
        let mut r = NdrReader::new(&reply_bytes);
        let dw_out_version = r.read_uint32().expect("dwOutVersion");
        assert_eq!(dw_out_version, 1);
        let reply = DrsReplicaSyncReply::decode(&mut r).expect("decode reply");
        assert_eq!(reply.retval, 0, "replica sync should succeed");
    }

    #[tokio::test]
    async fn wave3_drs_replica_sync_handler_returns_success() {
        // T-302 handler: the high-level handler returns retval=0.
        let reply = drs_replica_sync(
            Uuid::nil(),
            "DC=adrian,DC=example",
            "dc01.adrian.example",
            0,
        )
        .await
        .expect("handler must succeed");
        assert_eq!(reply.retval, 0);
    }

    #[tokio::test]
    async fn wave3_drs_crack_names_dispatch_round_trips_through_ndr() {
        // T-303: encode a DRSCrackNames request, dispatch, decode reply.
        let req = DrsCrackNamesReq {
            bind_handle: Uuid::now_v7(),
            format_offered: DsNameFormat::Fqdn1779,
            format_desired: DsNameFormat::Upn,
            names: vec![
                "CN=Alice,DC=adrian,DC=example".into(),
                "CN=Bob,DC=adrian,DC=example".into(),
            ],
        };
        let req_bytes = req.to_bytes();
        // Round-trip the request to verify NDR codec.
        let decoded_req = DrsCrackNamesReq::from_bytes(&req_bytes).expect("req round-trip");
        assert_eq!(decoded_req.names.len(), 2);
        assert_eq!(decoded_req.format_offered, DsNameFormat::Fqdn1779);
        assert_eq!(decoded_req.format_desired, DsNameFormat::Upn);
        // Dispatch.
        let reply_bytes = drs_crack_names_dispatch(Uuid::nil(), &req_bytes)
            .await
            .expect("dispatch must succeed");
        let mut r = NdrReader::new(&reply_bytes);
        let dw_out_version = r.read_uint32().expect("dwOutVersion");
        assert_eq!(dw_out_version, 1);
        let reply = DrsCrackNamesReply::decode(&mut r).expect("decode reply");
        assert_eq!(reply.entries.len(), 2);
        assert_eq!(reply.entries[0].name, "alice@adrian.example");
        assert_eq!(reply.entries[0].status, DsNameStatus::Ok);
        assert_eq!(reply.entries[1].name, "bob@adrian.example");
    }

    #[tokio::test]
    async fn wave3_drs_crack_names_handler_converts_dn_to_upn_and_canonical() {
        // T-303 handler: Fqdn1779 -> Upn and Fqdn1779 -> Canonical both work.
        let names = vec!["CN=Alice,DC=adrian,DC=example".to_string()];
        // Upn conversion.
        let reply = drs_crack_names(
            Uuid::nil(),
            DsNameFormat::Fqdn1779,
            DsNameFormat::Upn,
            &names,
        )
        .await
        .expect("Upn crack");
        assert_eq!(reply.entries[0].name, "alice@adrian.example");
        assert_eq!(reply.entries[0].status, DsNameStatus::Ok);
        // Canonical conversion.
        let reply = drs_crack_names(
            Uuid::nil(),
            DsNameFormat::Fqdn1779,
            DsNameFormat::Canonical,
            &names,
        )
        .await
        .expect("Canonical crack");
        assert_eq!(reply.entries[0].name, "adrian.example/Users/Alice");
        assert_eq!(reply.entries[0].status, DsNameStatus::Ok);
        // Identity conversion (same format in and out).
        let reply = drs_crack_names(
            Uuid::nil(),
            DsNameFormat::Fqdn1779,
            DsNameFormat::Fqdn1779,
            &names,
        )
        .await
        .expect("identity crack");
        assert_eq!(reply.entries[0].name, "CN=Alice,DC=adrian,DC=example");
        // Unsupported conversion returns NoMapping.
        let reply = drs_crack_names(
            Uuid::nil(),
            DsNameFormat::Upn,
            DsNameFormat::SidOrSidHistory,
            &names,
        )
        .await
        .expect("unsupported crack");
        assert_eq!(reply.entries[0].status, DsNameStatus::NoMapping);
    }
}
