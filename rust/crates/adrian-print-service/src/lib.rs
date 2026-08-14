#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # adrian-print-service
//!
//! IPP Everywhere print service (RFC 8011). Replaces MS-RPRN; integrates with
//! CUPS on Linux/macOS and the Windows print spooler via IPP driver model.
//!
//! ## Coverage (Wave 4)
//!
//! - Minimal IPP 1.1 / 2.0 wire codec (version, operation, request-id,
//!   attribute-groups, end-of-attributes tag, data) per RFC 8011 §3.1.
//! - IPP operations: `Print-Job` (0x0002), `Create-Job` (0x0005),
//!   `Send-Document` (0x0006), `Get-Job-Attributes` (0x0009),
//!   `Get-Printer-Attributes` (0x000B).
//! - Spool directory: submitted jobs are written to a configurable
//!   directory as `<job-id>.bin` for downstream rendering (CUPS
//!   filter pipeline, IPP Everywhere driverless conversion).
//! - axum router exposing `POST /ipp` for the IPP endpoint.
//!
//! ## ADRs
//!
//! - ADR-046: Drop MS-RPRN; adopt IPP Everywhere
//! - ADR-047: Offline files out of scope (print not affected)

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex;

// ============================================================================
// Errors
// ============================================================================

/// Print service error.
#[derive(Debug, Error)]
pub enum PrintError {
    /// IPP protocol error (version-not-supported, malformed request, etc).
    #[error("ipp: {0}")]
    Ipp(String),
    /// Printer not found in the registry.
    #[error("printer not found: {0}")]
    PrinterNotFound(String),
    /// Spooler error (disk full, spool dir not writable, etc).
    #[error("spooler: {0}")]
    Spooler(String),
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ============================================================================
// IPP wire constants — RFC 8011 §3.1
// ============================================================================

/// IPP versions (RFC 8011 §3.1.1). Encoded as two bytes: major.minor.
pub mod ipp_version {
    /// IPP 1.0 = `0x0100`.
    pub const IPP_1_0: u16 = 0x0100;
    /// IPP 1.1 = `0x0101`.
    pub const IPP_1_1: u16 = 0x0101;
    /// IPP 2.0 = `0x0200`.
    pub const IPP_2_0: u16 = 0x0200;
}

/// IPP operation IDs (RFC 8011 §4.1.1 / §4.2.1 / §4.2.6 / §4.2.10 / §4.2.13).
pub mod ipp_op {
    /// `0x0002` — Print-Job.
    pub const PRINT_JOB: u16 = 0x0002;
    /// `0x0005` — Create-Job.
    pub const CREATE_JOB: u16 = 0x0005;
    /// `0x0006` — Send-Document.
    pub const SEND_DOCUMENT: u16 = 0x0006;
    /// `0x0009` — Get-Job-Attributes.
    pub const GET_JOB_ATTRIBUTES: u16 = 0x0009;
    /// `0x000B` — Get-Printer-Attributes.
    pub const GET_PRINTER_ATTRIBUTES: u16 = 0x000B;
}

/// IPP status codes (RFC 8011 §4.1.6 / §13).
pub mod ipp_status {
    /// `0x0000` — successful-ok.
    pub const SUCCESSFUL_OK: u16 = 0x0000;
    /// `0x0400` — client-error-bad-request.
    pub const CLIENT_ERROR_BAD_REQUEST: u16 = 0x0400;
    /// `0x040A` — client-error-not-found.
    pub const CLIENT_ERROR_NOT_FOUND: u16 = 0x040A;
    /// `0x0500` — server-error-internal-error.
    pub const SERVER_ERROR_INTERNAL_ERROR: u16 = 0x0500;
    /// `0x0503` — server-error-version-not-supported.
    pub const SERVER_ERROR_VERSION_NOT_SUPPORTED: u16 = 0x0503;
    /// `0x0501` — server-error-operation-not-supported.
    pub const SERVER_ERROR_OPERATION_NOT_SUPPORTED: u16 = 0x0501;
}

/// IPP attribute-group tags (RFC 8011 §3.1.3).
pub mod ipp_tag {
    /// `0x01` — operation-attributes-tag.
    pub const OPERATION: u8 = 0x01;
    /// `0x02` — job-attributes-tag.
    pub const JOB: u8 = 0x02;
    /// `0x04` — printer-attributes-tag.
    pub const PRINTER: u8 = 0x04;
    /// `0x03` — end-of-attributes-tag.
    pub const END: u8 = 0x03;
    /// `0x42` — nameWithoutLanguage.
    pub const NAME_WITHOUT_LANG: u8 = 0x42;
    /// `0x44` — textWithoutLanguage.
    pub const TEXT_WITHOUT_LANG: u8 = 0x44;
    /// `0x21` — integer.
    pub const INTEGER: u8 = 0x21;
    /// `0x23` — enum.
    pub const ENUM: u8 = 0x23;
    /// `0x35` — uri.
    pub const URI: u8 = 0x35;
    /// `0x41` — keyword.
    pub const KEYWORD: u8 = 0x41;
}

// ============================================================================
// IPP wire types
// ============================================================================

/// A single IPP attribute (name + one or more values).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppAttribute {
    /// Tag (value type — see [`ipp_tag`]).
    pub tag: u8,
    /// Attribute name (ASCII).
    pub name: String,
    /// One or more values (most attributes have one; multi-valued
    /// attributes repeat the value encoding without re-emitting the
    /// name).
    pub values: Vec<IppValue>,
}

/// A single IPP value. Encoded per the attribute's tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IppValue {
    /// Integer (4 bytes signed).
    Integer(i32),
    /// Enum (4 bytes unsigned).
    Enum(u32),
    /// textWithoutLanguage / nameWithoutLanguage / keyword / uri —
    /// a length-prefixed UTF-8 string.
    Text(String),
}

/// An IPP request (RFC 8011 §3.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppRequest {
    /// Version (e.g. [`ipp_version::IPP_1_1`]).
    pub version: u16,
    /// Operation ID (e.g. [`ipp_op::PRINT_JOB`]).
    pub operation: u16,
    /// Request ID (client-assigned; matches response).
    pub request_id: u32,
    /// Attribute groups (operation, job, printer, etc).
    pub attribute_groups: Vec<(u8, Vec<IppAttribute>)>,
    /// Document data (for Print-Job / Send-Document).
    pub data: Vec<u8>,
}

/// An IPP response (RFC 8011 §3.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppResponse {
    /// Version (echoes the request).
    pub version: u16,
    /// Status code (e.g. [`ipp_status::SUCCESSFUL_OK`]).
    pub status: u16,
    /// Request ID (echoes the request).
    pub request_id: u32,
    /// Attribute groups in the response.
    pub attribute_groups: Vec<(u8, Vec<IppAttribute>)>,
    /// Document data in the response (rarely used).
    pub data: Vec<u8>,
}

impl IppRequest {
    /// Encode the IPP request to bytes per RFC 8011 §3.1.1.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.data.len());
        // Version (2 bytes): major.minor.
        out.push((self.version >> 8) as u8);
        out.push((self.version & 0xFF) as u8);
        // Operation (2 bytes big-endian).
        out.extend_from_slice(&self.operation.to_be_bytes());
        // Request ID (4 bytes big-endian).
        out.extend_from_slice(&self.request_id.to_be_bytes());
        // Attribute groups.
        for (group_tag, attrs) in &self.attribute_groups {
            out.push(*group_tag);
            for attr in attrs {
                encode_attribute(&mut out, attr);
            }
        }
        // End-of-attributes-tag.
        out.push(ipp_tag::END);
        // Document data.
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode an IPP request from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, PrintError> {
        if buf.len() < 8 {
            return Err(PrintError::Ipp(format!(
                "request too short: {} < 8",
                buf.len()
            )));
        }
        let version = ((buf[0] as u16) << 8) | (buf[1] as u16);
        let operation = u16::from_be_bytes([buf[2], buf[3]]);
        let request_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut pos = 8usize;
        let mut attribute_groups: Vec<(u8, Vec<IppAttribute>)> = Vec::new();
        let mut current_group: u8 = 0;
        let mut current_attrs: Vec<IppAttribute> = Vec::new();
        let mut current_attr_name: Option<String> = None;
        let mut current_tag: u8 = 0;
        let mut current_values: Vec<IppValue> = Vec::new();
        while pos < buf.len() {
            let tag = buf[pos];
            pos += 1;
            // Delimiter tag (0x00..0x05) — starts a new group / ends attrs.
            if tag <= 0x05 {
                // Flush any in-progress attribute.
                if let Some(name) = current_attr_name.take() {
                    current_attrs.push(IppAttribute {
                        tag: current_tag,
                        name,
                        values: std::mem::take(&mut current_values),
                    });
                }
                if !current_attrs.is_empty() || current_group != 0 {
                    attribute_groups.push((current_group, std::mem::take(&mut current_attrs)));
                }
                current_group = tag;
                if tag == ipp_tag::END {
                    break;
                }
                continue;
            }
            // Value tag — read the attribute name (length-prefixed) on
            // the first value of each attribute, then the value.
            if pos + 2 > buf.len() {
                return Err(PrintError::Ipp("truncated attribute name length".into()));
            }
            let name_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2;
            if pos + name_len > buf.len() {
                return Err(PrintError::Ipp("truncated attribute name".into()));
            }
            let name = String::from_utf8_lossy(&buf[pos..pos + name_len]).into_owned();
            pos += name_len;
            if pos + 2 > buf.len() {
                return Err(PrintError::Ipp("truncated attribute value length".into()));
            }
            let val_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2;
            if pos + val_len > buf.len() {
                return Err(PrintError::Ipp("truncated attribute value".into()));
            }
            let val_bytes = &buf[pos..pos + val_len];
            pos += val_len;
            let value = decode_value(tag, val_bytes)?;
            // If name is non-empty, this is a new attribute (flush the previous).
            if !name.is_empty() {
                if let Some(prev_name) = current_attr_name.take() {
                    current_attrs.push(IppAttribute {
                        tag: current_tag,
                        name: prev_name,
                        values: std::mem::take(&mut current_values),
                    });
                }
                current_attr_name = Some(name);
                current_tag = tag;
            }
            current_values.push(value);
        }
        // Flush the last group if no END tag was seen (malformed but
        // recoverable). If we did see END, current_group is END (0x03)
        // and we must NOT push it (END is a delimiter, not a group).
        if current_group != ipp_tag::END {
            if let Some(name) = current_attr_name.take() {
                current_attrs.push(IppAttribute {
                    tag: current_tag,
                    name,
                    values: std::mem::take(&mut current_values),
                });
            }
            if !current_attrs.is_empty() {
                attribute_groups.push((current_group, std::mem::take(&mut current_attrs)));
            }
        }
        // The remainder (after END tag) is the document data.
        let data_start = pos;
        let data = if data_start < buf.len() {
            buf[data_start..].to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            version,
            operation,
            request_id,
            attribute_groups,
            data,
        })
    }

    /// Look up the first value of an attribute by name (case-insensitive).
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&IppValue> {
        for (_, attrs) in &self.attribute_groups {
            for attr in attrs {
                if attr.name.eq_ignore_ascii_case(name) {
                    return attr.values.first();
                }
            }
        }
        None
    }
}

impl IppResponse {
    /// Build a minimal successful response echoing the request's version
    /// and request-id.
    #[must_use]
    pub fn new_success(version: u16, request_id: u32) -> Self {
        Self {
            version,
            status: ipp_status::SUCCESSFUL_OK,
            request_id,
            attribute_groups: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Build an error response with the given status and message.
    #[must_use]
    pub fn new_error(version: u16, request_id: u32, status: u16, message: &str) -> Self {
        let mut resp = Self {
            version,
            status,
            request_id,
            attribute_groups: Vec::new(),
            data: Vec::new(),
        };
        // Operation-attributes group with a status-message attribute.
        resp.attribute_groups.push((
            ipp_tag::OPERATION,
            vec![IppAttribute {
                tag: ipp_tag::TEXT_WITHOUT_LANG,
                name: "status-message".to_string(),
                values: vec![IppValue::Text(message.to_string())],
            }],
        ));
        resp
    }

    /// Encode the IPP response to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.data.len());
        out.push((self.version >> 8) as u8);
        out.push((self.version & 0xFF) as u8);
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&self.request_id.to_be_bytes());
        for (group_tag, attrs) in &self.attribute_groups {
            out.push(*group_tag);
            for attr in attrs {
                encode_attribute(&mut out, attr);
            }
        }
        out.push(ipp_tag::END);
        out.extend_from_slice(&self.data);
        out
    }
}

fn encode_attribute(out: &mut Vec<u8>, attr: &IppAttribute) {
    for (i, value) in attr.values.iter().enumerate() {
        out.push(attr.tag);
        if i == 0 {
            // Emit the name on the first value.
            out.extend_from_slice(&(attr.name.len() as u16).to_be_bytes());
            out.extend_from_slice(attr.name.as_bytes());
        } else {
            // Empty name for additional values (RFC 8011 §3.1.4).
            out.extend_from_slice(&0u16.to_be_bytes());
        }
        let (val_bytes, _val_tag) = encode_value(value);
        out.extend_from_slice(&(val_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&val_bytes);
    }
}

fn encode_value(value: &IppValue) -> (Vec<u8>, u8) {
    match value {
        IppValue::Integer(n) => (n.to_be_bytes().to_vec(), ipp_tag::INTEGER),
        IppValue::Enum(n) => (n.to_be_bytes().to_vec(), ipp_tag::ENUM),
        IppValue::Text(s) => (s.as_bytes().to_vec(), ipp_tag::TEXT_WITHOUT_LANG),
    }
}

fn decode_value(tag: u8, bytes: &[u8]) -> Result<IppValue, PrintError> {
    match tag {
        ipp_tag::INTEGER => {
            if bytes.len() != 4 {
                return Err(PrintError::Ipp(format!(
                    "integer attribute must be 4 bytes, got {}",
                    bytes.len()
                )));
            }
            let n = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok(IppValue::Integer(n))
        }
        ipp_tag::ENUM => {
            if bytes.len() != 4 {
                return Err(PrintError::Ipp(format!(
                    "enum attribute must be 4 bytes, got {}",
                    bytes.len()
                )));
            }
            let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok(IppValue::Enum(n))
        }
        ipp_tag::NAME_WITHOUT_LANG
        | ipp_tag::TEXT_WITHOUT_LANG
        | ipp_tag::KEYWORD
        | ipp_tag::URI => Ok(IppValue::Text(String::from_utf8_lossy(bytes).into_owned())),
        _ => Err(PrintError::Ipp(format!(
            "unsupported IPP value tag: 0x{tag:02x}"
        ))),
    }
}

// ============================================================================
// Print spooler — tracks jobs and writes document data to disk
// ============================================================================

/// A submitted print job.
#[derive(Clone, Debug)]
pub struct PrintJob {
    /// Job ID (server-assigned, monotonically increasing).
    pub id: u32,
    /// Job name (from the IPP `job-name` attribute).
    pub name: String,
    /// Originating user (from the IPP `requesting-user-name` attribute).
    pub user: String,
    /// Document format (from the IPP `document-format` attribute;
    /// e.g. `application/pdf`, `application/octet-stream`).
    pub format: String,
    /// Spool file path (`<spool_dir>/<id>.bin`).
    pub spool_path: PathBuf,
    /// Job state (3=pending, 4=processing, 5=completed, 6=aborted).
    pub state: u32,
}

/// In-memory print spooler. Tracks jobs and writes document data to a
/// configurable spool directory.
#[derive(Debug)]
pub struct PrintSpooler {
    spool_dir: PathBuf,
    jobs: HashMap<u32, PrintJob>,
    next_job_id: u32,
}

impl PrintSpooler {
    /// Construct a new spooler that writes job files to `spool_dir`.
    /// The directory is created if it doesn't exist.
    pub fn new(spool_dir: PathBuf) -> Result<Self, PrintError> {
        std::fs::create_dir_all(&spool_dir).map_err(PrintError::Io)?;
        Ok(Self {
            spool_dir,
            jobs: HashMap::new(),
            next_job_id: 1,
        })
    }

    /// Allocate a new job ID and create a placeholder job (no data yet).
    /// Used by Create-Job + Send-Document.
    pub fn create_job(
        &mut self,
        name: String,
        user: String,
        format: String,
    ) -> Result<u32, PrintError> {
        let id = self.next_job_id;
        self.next_job_id += 1;
        let spool_path = self.spool_dir.join(format!("{id}.bin"));
        let job = PrintJob {
            id,
            name,
            user,
            format,
            spool_path,
            state: 3, // pending
        };
        self.jobs.insert(id, job);
        Ok(id)
    }

    /// Write document data to the job's spool file. Used by Print-Job
    /// (single-step) and Send-Document (second step after Create-Job).
    pub fn write_document(&mut self, job_id: u32, data: &[u8]) -> Result<(), PrintError> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or_else(|| PrintError::PrinterNotFound(format!("job {job_id} not found")))?;
        std::fs::write(&job.spool_path, data).map_err(PrintError::Io)?;
        job.state = 5; // completed (synchronous for this minimal impl)
        Ok(())
    }

    /// Look up a job by ID.
    #[must_use]
    pub fn get_job(&self, job_id: u32) -> Option<&PrintJob> {
        self.jobs.get(&job_id)
    }

    /// Number of jobs in the spooler.
    #[must_use]
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    /// True if the spooler holds no jobs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// Borrow the spool directory path.
    #[must_use]
    pub fn spool_dir(&self) -> &PathBuf {
        &self.spool_dir
    }
}

// ============================================================================
// PrintService — IPP request router + operation handlers
// ============================================================================

/// IPP Everywhere print service.
pub struct PrintService {
    /// Printer URI (e.g. `ipp://dc01.example.com/ipp/print`).
    pub printer_uri: String,
    /// Printer name (e.g. `dc01-printer`).
    pub printer_name: String,
    /// Spooler (job tracking + disk-backed document storage).
    pub spooler: Arc<Mutex<PrintSpooler>>,
}

impl PrintService {
    /// Construct a new print service with a spool directory under the
    /// system temp dir.
    pub fn new() -> Self {
        let spool_dir = std::env::temp_dir().join("adrian-spool");
        let spooler = PrintSpooler::new(spool_dir).expect("spool dir must be creatable");
        Self {
            printer_uri: "ipp://localhost/ipp/print".to_string(),
            printer_name: "adrian-printer".to_string(),
            spooler: Arc::new(Mutex::new(spooler)),
        }
    }

    /// Construct a new print service with a specific spool directory
    /// (useful for tests).
    pub fn with_spool_dir(spool_dir: PathBuf) -> Result<Self, PrintError> {
        let spooler = PrintSpooler::new(spool_dir)?;
        Ok(Self {
            printer_uri: "ipp://localhost/ipp/print".to_string(),
            printer_name: "adrian-printer".to_string(),
            spooler: Arc::new(Mutex::new(spooler)),
        })
    }

    /// Dispatch an IPP request and return the IPP response. This is
    /// the operation handler called by the axum router.
    pub async fn dispatch(&self, request: IppRequest) -> IppResponse {
        // Version check — accept 1.0, 1.1, 2.0; reject others.
        if !matches!(
            request.version,
            ipp_version::IPP_1_0 | ipp_version::IPP_1_1 | ipp_version::IPP_2_0
        ) {
            return IppResponse::new_error(
                request.version,
                request.request_id,
                ipp_status::SERVER_ERROR_VERSION_NOT_SUPPORTED,
                "unsupported IPP version",
            );
        }
        match request.operation {
            ipp_op::PRINT_JOB => self.handle_print_job(request).await,
            ipp_op::CREATE_JOB => self.handle_create_job(request).await,
            ipp_op::SEND_DOCUMENT => self.handle_send_document(request).await,
            ipp_op::GET_JOB_ATTRIBUTES => self.handle_get_job_attributes(request).await,
            ipp_op::GET_PRINTER_ATTRIBUTES => self.handle_get_printer_attributes(request).await,
            other => IppResponse::new_error(
                request.version,
                request.request_id,
                ipp_status::SERVER_ERROR_OPERATION_NOT_SUPPORTED,
                &format!("operation 0x{other:04x} not supported"),
            ),
        }
    }

    /// Build the IPP axum router (RFC 8011 endpoint at POST /ipp).
    pub fn router(&self) -> axum::Router {
        let spooler = self.spooler.clone();
        let printer_uri = self.printer_uri.clone();
        let printer_name = self.printer_name.clone();
        axum::Router::new()
            .route(
                "/ipp",
                axum::routing::post(move |body: axum::body::Bytes| {
                    let spooler = spooler.clone();
                    let printer_uri = printer_uri.clone();
                    let printer_name = printer_name.clone();
                    async move {
                        let svc = PrintService {
                            printer_uri,
                            printer_name,
                            spooler,
                        };
                        let request = match IppRequest::decode(&body) {
                            Ok(r) => r,
                            Err(e) => {
                                let resp = IppResponse::new_error(
                                    ipp_version::IPP_1_1,
                                    0,
                                    ipp_status::CLIENT_ERROR_BAD_REQUEST,
                                    &format!("malformed IPP request: {e}"),
                                );
                                return axum::response::Response::builder()
                                    .status(axum::http::StatusCode::BAD_REQUEST)
                                    .header(axum::http::header::CONTENT_TYPE, "application/ipp")
                                    .body(axum::body::Body::from(resp.encode()))
                                    .expect("response builder");
                            }
                        };
                        let response = svc.dispatch(request).await;
                        axum::response::Response::builder()
                            .status(axum::http::StatusCode::OK)
                            .header(axum::http::header::CONTENT_TYPE, "application/ipp")
                            .body(axum::body::Body::from(response.encode()))
                            .expect("response builder")
                    }
                }),
            )
            .route(
                "/ipp/print",
                axum::routing::get(|| async { "adrian IPP print service" }),
            )
    }

    // ---- Operation handlers ----

    async fn handle_print_job(&self, request: IppRequest) -> IppResponse {
        let job_name = request
            .attribute("job-name")
            .and_then(|v| match v {
                IppValue::Text(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "unnamed".to_string());
        let user = request
            .attribute("requesting-user-name")
            .and_then(|v| match v {
                IppValue::Text(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "anonymous".to_string());
        let format = request
            .attribute("document-format")
            .and_then(|v| match v {
                IppValue::Text(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let mut spooler = self.spooler.lock().await;
        let job_id = match spooler.create_job(job_name, user, format) {
            Ok(id) => id,
            Err(e) => {
                return IppResponse::new_error(
                    request.version,
                    request.request_id,
                    ipp_status::SERVER_ERROR_INTERNAL_ERROR,
                    &format!("create_job: {e}"),
                );
            }
        };
        if let Err(e) = spooler.write_document(job_id, &request.data) {
            return IppResponse::new_error(
                request.version,
                request.request_id,
                ipp_status::SERVER_ERROR_INTERNAL_ERROR,
                &format!("write_document: {e}"),
            );
        }
        let job_attrs = vec![
            IppAttribute {
                tag: ipp_tag::INTEGER,
                name: "job-id".to_string(),
                values: vec![IppValue::Integer(job_id as i32)],
            },
            IppAttribute {
                tag: ipp_tag::ENUM,
                name: "job-state".to_string(),
                values: vec![IppValue::Enum(5)], // completed
            },
        ];
        IppResponse {
            version: request.version,
            status: ipp_status::SUCCESSFUL_OK,
            request_id: request.request_id,
            attribute_groups: vec![(ipp_tag::JOB, job_attrs)],
            data: Vec::new(),
        }
    }

    async fn handle_create_job(&self, request: IppRequest) -> IppResponse {
        let job_name = request
            .attribute("job-name")
            .and_then(|v| match v {
                IppValue::Text(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "unnamed".to_string());
        let user = request
            .attribute("requesting-user-name")
            .and_then(|v| match v {
                IppValue::Text(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "anonymous".to_string());
        let format = request
            .attribute("document-format")
            .and_then(|v| match v {
                IppValue::Text(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let mut spooler = self.spooler.lock().await;
        let job_id = match spooler.create_job(job_name, user, format) {
            Ok(id) => id,
            Err(e) => {
                return IppResponse::new_error(
                    request.version,
                    request.request_id,
                    ipp_status::SERVER_ERROR_INTERNAL_ERROR,
                    &format!("create_job: {e}"),
                );
            }
        };
        let job_attrs = vec![IppAttribute {
            tag: ipp_tag::INTEGER,
            name: "job-id".to_string(),
            values: vec![IppValue::Integer(job_id as i32)],
        }];
        IppResponse {
            version: request.version,
            status: ipp_status::SUCCESSFUL_OK,
            request_id: request.request_id,
            attribute_groups: vec![(ipp_tag::JOB, job_attrs)],
            data: Vec::new(),
        }
    }

    async fn handle_send_document(&self, request: IppRequest) -> IppResponse {
        let job_id = match request.attribute("job-id").and_then(|v| match v {
            IppValue::Integer(n) => Some(*n as u32),
            _ => None,
        }) {
            Some(id) => id,
            None => {
                return IppResponse::new_error(
                    request.version,
                    request.request_id,
                    ipp_status::CLIENT_ERROR_BAD_REQUEST,
                    "missing required 'job-id' attribute",
                );
            }
        };
        let mut spooler = self.spooler.lock().await;
        if let Err(e) = spooler.write_document(job_id, &request.data) {
            return IppResponse::new_error(
                request.version,
                request.request_id,
                ipp_status::CLIENT_ERROR_NOT_FOUND,
                &format!("write_document: {e}"),
            );
        }
        let job_attrs = vec![
            IppAttribute {
                tag: ipp_tag::INTEGER,
                name: "job-id".to_string(),
                values: vec![IppValue::Integer(job_id as i32)],
            },
            IppAttribute {
                tag: ipp_tag::ENUM,
                name: "job-state".to_string(),
                values: vec![IppValue::Enum(5)], // completed
            },
        ];
        IppResponse {
            version: request.version,
            status: ipp_status::SUCCESSFUL_OK,
            request_id: request.request_id,
            attribute_groups: vec![(ipp_tag::JOB, job_attrs)],
            data: Vec::new(),
        }
    }

    async fn handle_get_job_attributes(&self, request: IppRequest) -> IppResponse {
        let job_id = match request.attribute("job-id").and_then(|v| match v {
            IppValue::Integer(n) => Some(*n as u32),
            _ => None,
        }) {
            Some(id) => id,
            None => {
                return IppResponse::new_error(
                    request.version,
                    request.request_id,
                    ipp_status::CLIENT_ERROR_BAD_REQUEST,
                    "missing required 'job-id' attribute",
                );
            }
        };
        let spooler = self.spooler.lock().await;
        match spooler.get_job(job_id) {
            Some(job) => {
                let job_attrs = vec![
                    IppAttribute {
                        tag: ipp_tag::INTEGER,
                        name: "job-id".to_string(),
                        values: vec![IppValue::Integer(job.id as i32)],
                    },
                    IppAttribute {
                        tag: ipp_tag::NAME_WITHOUT_LANG,
                        name: "job-name".to_string(),
                        values: vec![IppValue::Text(job.name.clone())],
                    },
                    IppAttribute {
                        tag: ipp_tag::NAME_WITHOUT_LANG,
                        name: "requesting-user-name".to_string(),
                        values: vec![IppValue::Text(job.user.clone())],
                    },
                    IppAttribute {
                        tag: ipp_tag::ENUM,
                        name: "job-state".to_string(),
                        values: vec![IppValue::Enum(job.state)],
                    },
                ];
                IppResponse {
                    version: request.version,
                    status: ipp_status::SUCCESSFUL_OK,
                    request_id: request.request_id,
                    attribute_groups: vec![(ipp_tag::JOB, job_attrs)],
                    data: Vec::new(),
                }
            }
            None => IppResponse::new_error(
                request.version,
                request.request_id,
                ipp_status::CLIENT_ERROR_NOT_FOUND,
                &format!("job {job_id} not found"),
            ),
        }
    }

    async fn handle_get_printer_attributes(&self, request: IppRequest) -> IppResponse {
        let printer_attrs = vec![
            IppAttribute {
                tag: ipp_tag::URI,
                name: "printer-uri".to_string(),
                values: vec![IppValue::Text(self.printer_uri.clone())],
            },
            IppAttribute {
                tag: ipp_tag::NAME_WITHOUT_LANG,
                name: "printer-name".to_string(),
                values: vec![IppValue::Text(self.printer_name.clone())],
            },
            IppAttribute {
                tag: ipp_tag::ENUM,
                name: "printer-state".to_string(),
                values: vec![IppValue::Enum(3)], // idle
            },
            IppAttribute {
                tag: ipp_tag::KEYWORD,
                name: "printer-state-reasons".to_string(),
                values: vec![IppValue::Text("none".to_string())],
            },
            IppAttribute {
                tag: ipp_tag::KEYWORD,
                name: "ipp-versions-supported".to_string(),
                values: vec![
                    IppValue::Text("1.0".to_string()),
                    IppValue::Text("1.1".to_string()),
                    IppValue::Text("2.0".to_string()),
                ],
            },
            IppAttribute {
                tag: ipp_tag::ENUM,
                name: "operations-supported".to_string(),
                values: vec![
                    IppValue::Enum(ipp_op::PRINT_JOB as u32),
                    IppValue::Enum(ipp_op::CREATE_JOB as u32),
                    IppValue::Enum(ipp_op::SEND_DOCUMENT as u32),
                    IppValue::Enum(ipp_op::GET_JOB_ATTRIBUTES as u32),
                    IppValue::Enum(ipp_op::GET_PRINTER_ATTRIBUTES as u32),
                ],
            },
        ];
        IppResponse {
            version: request.version,
            status: ipp_status::SUCCESSFUL_OK,
            request_id: request.request_id,
            attribute_groups: vec![(ipp_tag::PRINTER, printer_attrs)],
            data: Vec::new(),
        }
    }
}

impl Default for PrintService {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service() -> PrintService {
        // Use a unique temp dir per test to avoid cross-test interference.
        let dir = std::env::temp_dir().join(format!(
            "adrian-spool-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        PrintService::with_spool_dir(dir).expect("spooler")
    }

    // ---- Public API contracts (kept from the stub) ----

    #[test]
    fn service_new_and_default_construct_without_state() {
        let a = PrintService::new();
        let b = PrintService::default();
        let _ = (a, b);
    }

    #[test]
    fn router_returns_empty_but_not_panic() {
        let svc = PrintService::new();
        let router = svc.router();
        drop(router);
    }

    #[test]
    fn error_variants_render_expected_prefixes() {
        assert_eq!(
            format!("{}", PrintError::Ipp("version-not-supported".into())),
            "ipp: version-not-supported"
        );
        assert_eq!(
            format!("{}", PrintError::PrinterNotFound("HP-LaserJet-4".into())),
            "printer not found: HP-LaserJet-4"
        );
        assert_eq!(
            format!("{}", PrintError::Spooler("queue stalled".into())),
            "spooler: queue stalled"
        );
    }

    #[test]
    fn printer_not_found_variant_is_matchable() {
        let err = PrintError::PrinterNotFound("missing-printer".into());
        match err {
            PrintError::PrinterNotFound(name) => assert_eq!(name, "missing-printer"),
            other => panic!("expected PrinterNotFound, got {:?}", other),
        }
    }

    #[test]
    fn error_variants_are_distinct_debug_representations() {
        let variants = [
            PrintError::Ipp("i".into()),
            PrintError::PrinterNotFound("p".into()),
            PrintError::Spooler("s".into()),
        ];
        let debugs: Vec<String> = variants.iter().map(|e| format!("{:?}", e)).collect();
        let unique: std::collections::HashSet<_> = debugs.iter().collect();
        assert_eq!(
            unique.len(),
            variants.len(),
            "Debug reprs collided: {debugs:?}"
        );
    }

    // ---- Wave 4: IPP operation tests ----

    #[tokio::test]
    async fn wave4_ipp_print_job_writes_document_to_spool_dir() {
        // T-403 / T-405: Print-Job creates a new job, writes the document
        // data to the spool dir, and returns a successful response with
        // the job-id.
        let svc = make_service();
        let document = b"%PDF-1.4 fake pdf body for testing\n";
        let request = IppRequest {
            version: ipp_version::IPP_1_1,
            operation: ipp_op::PRINT_JOB,
            request_id: 0x0000_0001,
            attribute_groups: vec![(
                ipp_tag::OPERATION,
                vec![
                    IppAttribute {
                        tag: ipp_tag::URI,
                        name: "printer-uri".to_string(),
                        values: vec![IppValue::Text("ipp://localhost/ipp/print".to_string())],
                    },
                    IppAttribute {
                        tag: ipp_tag::NAME_WITHOUT_LANG,
                        name: "job-name".to_string(),
                        values: vec![IppValue::Text("test-job".to_string())],
                    },
                    IppAttribute {
                        tag: ipp_tag::NAME_WITHOUT_LANG,
                        name: "requesting-user-name".to_string(),
                        values: vec![IppValue::Text("alice".to_string())],
                    },
                    IppAttribute {
                        tag: ipp_tag::KEYWORD,
                        name: "document-format".to_string(),
                        values: vec![IppValue::Text("application/pdf".to_string())],
                    },
                ],
            )],
            data: document.to_vec(),
        };
        let response = svc.dispatch(request).await;
        assert_eq!(response.status, ipp_status::SUCCESSFUL_OK);
        assert_eq!(response.request_id, 0x0000_0001);
        // The response must include a job-id.
        let job_id = response
            .attribute_groups
            .iter()
            .flat_map(|(_, attrs)| attrs.iter())
            .find(|a| a.name == "job-id")
            .and_then(|a| a.values.first())
            .and_then(|v| match v {
                IppValue::Integer(n) => Some(*n),
                _ => None,
            })
            .expect("response must include job-id");
        assert!(job_id > 0);
        // Verify the spool file was written.
        let spooler = svc.spooler.lock().await;
        let job = spooler.get_job(job_id as u32).expect("job must exist");
        let on_disk = std::fs::read(&job.spool_path).expect("spool file must be readable");
        assert_eq!(on_disk, document);
    }

    #[tokio::test]
    async fn wave4_ipp_get_printer_attributes_returns_expected_attrs() {
        // T-403 / T-405: Get-Printer-Attributes returns the printer-uri,
        // printer-name, printer-state, ipp-versions-supported, and
        // operations-supported attributes.
        let svc = make_service();
        let request = IppRequest {
            version: ipp_version::IPP_1_1,
            operation: ipp_op::GET_PRINTER_ATTRIBUTES,
            request_id: 0x0000_0002,
            attribute_groups: vec![(
                ipp_tag::OPERATION,
                vec![IppAttribute {
                    tag: ipp_tag::URI,
                    name: "printer-uri".to_string(),
                    values: vec![IppValue::Text("ipp://localhost/ipp/print".to_string())],
                }],
            )],
            data: Vec::new(),
        };
        let response = svc.dispatch(request).await;
        assert_eq!(response.status, ipp_status::SUCCESSFUL_OK);
        // The response must include the printer-attributes group.
        let printer_group = response
            .attribute_groups
            .iter()
            .find(|(tag, _)| *tag == ipp_tag::PRINTER)
            .expect("response must include printer-attributes group");
        let attr_names: Vec<&str> = printer_group.1.iter().map(|a| a.name.as_str()).collect();
        assert!(attr_names.contains(&"printer-uri"));
        assert!(attr_names.contains(&"printer-name"));
        assert!(attr_names.contains(&"printer-state"));
        assert!(attr_names.contains(&"ipp-versions-supported"));
        assert!(attr_names.contains(&"operations-supported"));
    }

    #[tokio::test]
    async fn wave4_ipp_create_job_then_send_document_completes_job() {
        // T-403 / T-405: Create-Job returns a job-id; Send-Document
        // uploads the document data and completes the job.
        let svc = make_service();
        // Step 1: Create-Job.
        let create_req = IppRequest {
            version: ipp_version::IPP_1_1,
            operation: ipp_op::CREATE_JOB,
            request_id: 0x0000_0003,
            attribute_groups: vec![(
                ipp_tag::OPERATION,
                vec![
                    IppAttribute {
                        tag: ipp_tag::URI,
                        name: "printer-uri".to_string(),
                        values: vec![IppValue::Text("ipp://localhost/ipp/print".to_string())],
                    },
                    IppAttribute {
                        tag: ipp_tag::NAME_WITHOUT_LANG,
                        name: "job-name".to_string(),
                        values: vec![IppValue::Text("two-step-job".to_string())],
                    },
                    IppAttribute {
                        tag: ipp_tag::NAME_WITHOUT_LANG,
                        name: "requesting-user-name".to_string(),
                        values: vec![IppValue::Text("bob".to_string())],
                    },
                ],
            )],
            data: Vec::new(),
        };
        let create_resp = svc.dispatch(create_req).await;
        assert_eq!(create_resp.status, ipp_status::SUCCESSFUL_OK);
        let job_id = create_resp
            .attribute_groups
            .iter()
            .flat_map(|(_, attrs)| attrs.iter())
            .find(|a| a.name == "job-id")
            .and_then(|a| a.values.first())
            .and_then(|v| match v {
                IppValue::Integer(n) => Some(*n),
                _ => None,
            })
            .expect("Create-Job must return job-id");
        // Step 2: Send-Document.
        let document = b"raw postscript\n%%EOF\n";
        let send_req = IppRequest {
            version: ipp_version::IPP_1_1,
            operation: ipp_op::SEND_DOCUMENT,
            request_id: 0x0000_0004,
            attribute_groups: vec![(
                ipp_tag::OPERATION,
                vec![
                    IppAttribute {
                        tag: ipp_tag::URI,
                        name: "printer-uri".to_string(),
                        values: vec![IppValue::Text("ipp://localhost/ipp/print".to_string())],
                    },
                    IppAttribute {
                        tag: ipp_tag::INTEGER,
                        name: "job-id".to_string(),
                        values: vec![IppValue::Integer(job_id)],
                    },
                    IppAttribute {
                        tag: ipp_tag::KEYWORD,
                        name: "document-format".to_string(),
                        values: vec![IppValue::Text("application/postscript".to_string())],
                    },
                ],
            )],
            data: document.to_vec(),
        };
        let send_resp = svc.dispatch(send_req).await;
        assert_eq!(send_resp.status, ipp_status::SUCCESSFUL_OK);
        // The job-state should be "completed" (5).
        let job_state = send_resp
            .attribute_groups
            .iter()
            .flat_map(|(_, attrs)| attrs.iter())
            .find(|a| a.name == "job-state")
            .and_then(|a| a.values.first())
            .and_then(|v| match v {
                IppValue::Enum(n) => Some(*n),
                _ => None,
            })
            .expect("Send-Document must return job-state");
        assert_eq!(job_state, 5);
        // Verify the spool file was written.
        let spooler = svc.spooler.lock().await;
        let job = spooler.get_job(job_id as u32).expect("job must exist");
        let on_disk = std::fs::read(&job.spool_path).expect("spool file must be readable");
        assert_eq!(on_disk, document);
    }

    #[tokio::test]
    async fn wave4_ipp_error_responses_for_bad_input() {
        // T-405: error responses for unsupported version, unsupported
        // operation, and missing required attributes.
        let svc = make_service();
        // 1) Unsupported IPP version.
        let req = IppRequest {
            version: 0x0999, // unsupported
            operation: ipp_op::GET_PRINTER_ATTRIBUTES,
            request_id: 1,
            attribute_groups: vec![(ipp_tag::OPERATION, vec![])],
            data: Vec::new(),
        };
        let resp = svc.dispatch(req).await;
        assert_eq!(
            resp.status,
            ipp_status::SERVER_ERROR_VERSION_NOT_SUPPORTED,
            "unsupported version must surface version-not-supported"
        );
        // 2) Unsupported operation.
        let req = IppRequest {
            version: ipp_version::IPP_1_1,
            operation: 0x9999, // unsupported
            request_id: 2,
            attribute_groups: vec![(ipp_tag::OPERATION, vec![])],
            data: Vec::new(),
        };
        let resp = svc.dispatch(req).await;
        assert_eq!(
            resp.status,
            ipp_status::SERVER_ERROR_OPERATION_NOT_SUPPORTED,
            "unsupported operation must surface operation-not-supported"
        );
        // 3) Missing required 'job-id' on Send-Document.
        let req = IppRequest {
            version: ipp_version::IPP_1_1,
            operation: ipp_op::SEND_DOCUMENT,
            request_id: 3,
            attribute_groups: vec![(ipp_tag::OPERATION, vec![])],
            data: Vec::new(),
        };
        let resp = svc.dispatch(req).await;
        assert_eq!(
            resp.status,
            ipp_status::CLIENT_ERROR_BAD_REQUEST,
            "missing job-id must surface bad-request"
        );
        // 4) Get-Job-Attributes on a non-existent job.
        let req = IppRequest {
            version: ipp_version::IPP_1_1,
            operation: ipp_op::GET_JOB_ATTRIBUTES,
            request_id: 4,
            attribute_groups: vec![(
                ipp_tag::OPERATION,
                vec![IppAttribute {
                    tag: ipp_tag::INTEGER,
                    name: "job-id".to_string(),
                    values: vec![IppValue::Integer(9999)],
                }],
            )],
            data: Vec::new(),
        };
        let resp = svc.dispatch(req).await;
        assert_eq!(
            resp.status,
            ipp_status::CLIENT_ERROR_NOT_FOUND,
            "missing job must surface not-found"
        );
    }

    // ---- IPP codec round-trip ----

    #[test]
    fn wave4_ipp_request_encode_decode_round_trips() {
        // The IPP request encoder/decoder must round-trip a simple
        // Print-Job request including attribute groups and document data.
        let request = IppRequest {
            version: ipp_version::IPP_1_1,
            operation: ipp_op::PRINT_JOB,
            request_id: 0xCAFE_BABE,
            attribute_groups: vec![(
                ipp_tag::OPERATION,
                vec![IppAttribute {
                    tag: ipp_tag::NAME_WITHOUT_LANG,
                    name: "job-name".to_string(),
                    values: vec![IppValue::Text("round-trip".to_string())],
                }],
            )],
            data: b"document bytes".to_vec(),
        };
        let bytes = request.encode();
        let decoded = IppRequest::decode(&bytes).expect("decode must succeed");
        assert_eq!(decoded.version, request.version);
        assert_eq!(decoded.operation, request.operation);
        assert_eq!(decoded.request_id, request.request_id);
        assert_eq!(decoded.data, request.data);
        // Attribute groups.
        assert_eq!(decoded.attribute_groups.len(), 1);
        let (group_tag, attrs) = &decoded.attribute_groups[0];
        assert_eq!(*group_tag, ipp_tag::OPERATION);
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].name, "job-name");
        assert_eq!(attrs[0].values.len(), 1);
        assert_eq!(attrs[0].values[0], IppValue::Text("round-trip".to_string()));
    }
}
