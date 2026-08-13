//! # adrian-admx-compiler
//!
//! `admx2adrian` — ADMX → declarative canonical JSON compiler.
//!
//! Per ADR-090 §Decision, this crate parses ADMX (Administrative Template
//! XML, per MS-GPREG Appendix A) files into a structured `AdmxPolicy`
//! representation, and then converts that representation into a
//! [`DeclarativePolicy`] that the framework's per-platform executors
//! can compile to platform-native formats.
//!
//! The compiler is **single-pass** (stream-parse ADMX via `quick-xml`,
//! build the output in memory, emit on completion) and **deterministic**
//! (same ADMX input → byte-identical JSON output, per ADR-090 §8 CI
//! regression contract).
//!
//! ## ADRs
//!
//! - ADR-090: ADMX → declarative JSON compiler
//! - ADR-091: GPP preferences cross-platform compilation
//! - ADR-127: GPO translation (admx/preg/gpttmpl → declarative)
//! - ADR-089: Declarative policy ↔ GPC/GPT synthesis

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use adrian_policy_core::{DeclarativePolicy, PolicySetting, PolicyValue};
use thiserror::Error;

/// Error type for ADMX compilation.
#[derive(Debug, Error)]
pub enum AdmxError {
    /// XML parse error from `quick-xml` (malformed ADMX input).
    #[error("admx parse: {0}")]
    Parse(String),
    /// Semantic error (e.g. ADMX policy with no `name` attribute, or
    /// an unsupported `class` value).
    #[error("semantic: {0}")]
    Semantic(String),
}

/// ADMX policy `class` attribute (per MS-GPREG Appendix A — the
/// `<policy class="...">` attribute is one of `Machine`, `User`, or
/// `Both`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmxClass {
    /// Machine policy (applies to HKLM).
    Machine,
    /// User policy (applies to HKCU).
    User,
    /// Both machine and user (rare).
    Both,
}

impl AdmxClass {
    /// Parse an ADMX `class` attribute value (case-insensitive) into an
    /// [`AdmxClass`]. Returns `Err` for unknown values.
    pub fn parse(s: &str) -> Result<Self, AdmxError> {
        match s.to_ascii_lowercase().as_str() {
            "machine" => Ok(Self::Machine),
            "user" => Ok(Self::User),
            "both" => Ok(Self::Both),
            other => Err(AdmxError::Semantic(format!(
                "unknown ADMX class {other:?} (expected Machine/User/Both)"
            ))),
        }
    }

    /// The string form used in ADMX XML attributes (round-trips through
    /// [`AdmxClass::parse`]).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Machine => "Machine",
            Self::User => "User",
            Self::Both => "Both",
        }
    }
}

/// A single ADMX `<elements>` element (per ADR-090 §3 — the ADMX
/// `<elements>` block defines the policy's parameters).
#[derive(Debug, Clone, PartialEq)]
pub enum AdmxElement {
    /// ADMX `<boolean>` element — a REG_DWORD 0/1 toggle.
    Boolean {
        /// The registry value name.
        value_name: String,
    },
    /// ADMX `<text>` element — a REG_SZ single-line string.
    Text {
        /// The registry value name.
        value_name: String,
    },
    /// ADMX `<decimal>` or `<longDecimal>` element — a REG_DWORD
    /// unsigned integer.
    Integer {
        /// The registry value name.
        value_name: String,
        /// Optional minimum value (ADMX `minValue` attribute).
        min: Option<i64>,
        /// Optional maximum value (ADMX `maxValue` attribute).
        max: Option<i64>,
    },
    /// ADMX `<enum>` element — a dropdown list of named values.
    Enum {
        /// The registry value name.
        value_name: String,
        /// The enum items: `(value, display_name)` pairs (one per
        /// `<item>` child).
        items: Vec<(String, String)>,
    },
}

/// ADMX policy definition — one parsed `<policy>` element (per ADR-090
/// §Decision — the parsed in-memory representation that
/// [`admx_to_declarative`] consumes).
#[derive(Debug, Clone, PartialEq)]
pub struct AdmxPolicy {
    /// The policy's unique name (ADMX `name` attribute, e.g.
    /// `Pol_Ciphers_AES128`).
    pub name: String,
    /// The display name (ADMX `displayName` attribute, typically a
    /// `$(string.<id>)` reference into the ADML).
    pub display_name: String,
    /// The explanation / help text (ADMX `explainText` attribute).
    pub explanation: String,
    /// The class (Machine / User / Both).
    pub class: AdmxClass,
    /// The supportedOn reference (ADMX `<supportedOn ref="..."/>` —
    /// e.g. `SUPPORTED_Win10_1809`). `None` if the policy does not
    /// declare a supportedOn.
    pub supported_on: Option<String>,
    /// The registry key path (ADMX `key` attribute, e.g.
    /// `Software\Policies\Contoso\App`).
    pub key: String,
    /// The registry value name (ADMX `valueName` attribute, e.g.
    /// `Enabled`). `None` if the policy uses only `<elements>` for its
    /// values.
    pub value_name: Option<String>,
    /// The elements (ADMX `<elements>` children — see [`AdmxElement`]).
    pub elements: Vec<AdmxElement>,
}

impl AdmxPolicy {
    /// Construct a minimal `AdmxPolicy` with no elements. Convenience
    /// constructor.
    #[must_use]
    pub fn new(name: impl Into<String>, class: AdmxClass, key: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: String::new(),
            explanation: String::new(),
            class,
            supported_on: None,
            key: key.into(),
            value_name: None,
            elements: vec![],
        }
    }
}

// ---- the legacy `compile` entrypoint (kept for backward compat) -----------

/// Compile an ADMX/ADML pair into canonical policy documents (the legacy
/// entrypoint from the previous wave — kept so existing callers don't
/// break). Wave 4a callers should prefer [`parse_admx`] + [`admx_to_declarative`]
/// for the new, richer surface.
///
/// Note: this v1 stub does not yet read ADML files; the
/// display_name / explanation fields are populated with the raw
/// `$(string.<id>)` references from the ADMX. A future wave will
/// substitute the ADML strings.
pub fn compile(
    admx_path: &str,
    adml_path: &str,
) -> Result<Vec<adrian_policy_core::PolicyDoc>, AdmxError> {
    let admx_text = std::fs::read_to_string(admx_path)
        .map_err(|e| AdmxError::Parse(format!("read {admx_path:?}: {e}")))?;
    let _ = std::fs::read_to_string(adml_path)
        .map_err(|e| AdmxError::Parse(format!("read {adml_path:?}: {e}")))?;
    let policies = parse_admx(&admx_text)?;
    let decl = admx_to_declarative(&policies);
    // Wrap the declarative policy as a single PolicyDoc — this is a
    // lossy 1:1 mapping for the v1; the PolicyDoc carries the policy
    // name + version, and the declarative JSON is embedded in the
    // description for now (a future wave will properly translate to
    // the PolicyArea enum).
    let doc = adrian_policy_core::PolicyDoc {
        uuid: uuid::Uuid::nil(),
        name: decl.name,
        version: format!("v{}", decl.version),
        areas: vec![],
        security_descriptor: None,
        scope: adrian_policy_core::PolicyScope {
            principals: vec![],
            ous: vec![],
            hosts: vec![],
        },
    };
    Ok(vec![doc])
}

// ---- the new Wave 4a API: parse_admx + admx_to_declarative ----------------

/// Parse an ADMX XML string into a list of [`AdmxPolicy`] structs (per
/// ADR-090 §Decision — single-pass stream parsing via `quick-xml`).
///
/// Only the `<policies>` subtree is parsed; the `<categories>`,
/// `<supportedOn>`, and `<policyNamespaces>` subtrees are skipped (the
/// framework does not need them for the declarative compilation).
pub fn parse_admx(admx_xml: &str) -> Result<Vec<AdmxPolicy>, AdmxError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(admx_xml);
    reader.config_mut().trim_text(true);

    let mut policies: Vec<AdmxPolicy> = Vec::new();
    let mut current_policy: Option<AdmxPolicy> = None;
    let mut current_element: Option<AdmxElementBuilder> = None;
    let mut current_enum_items: Vec<(String, String)> = Vec::new();
    let mut current_enum_item_display: Option<String> = None;
    let mut current_enum_item_value: Option<String> = None;
    let mut in_enum_item = false;
    let mut in_enum_item_value = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let (ns, local) = split_ns(&name_bytes);
                let _ = ns;
                match local {
                    b"policy" => {
                        let name = attr(&e, b"name")
                            .ok_or_else(|| AdmxError::Semantic("policy missing name".into()))?;
                        let class_str = attr(&e, b"class").unwrap_or_else(|| "Machine".into());
                        let class = AdmxClass::parse(&class_str)?;
                        let key = attr(&e, b"key").unwrap_or_default();
                        let value_name = attr(&e, b"valueName");
                        let display_name = attr(&e, b"displayName").unwrap_or_default();
                        let explanation = attr(&e, b"explainText").unwrap_or_default();
                        current_policy = Some(AdmxPolicy {
                            name,
                            display_name,
                            explanation,
                            class,
                            supported_on: None,
                            key,
                            value_name,
                            elements: vec![],
                        });
                    }
                    b"supportedOn" => {
                        if let Some(p) = current_policy.as_mut() {
                            if let Some(ref_attr) = attr(&e, b"ref") {
                                p.supported_on = Some(ref_attr);
                            }
                        }
                    }
                    b"elements" => { /* enter elements block */ }
                    b"text" => {
                        if let Some(vn) = attr(&e, b"valueName") {
                            current_element = Some(AdmxElementBuilder::Text { value_name: vn });
                        }
                    }
                    b"boolean" => {
                        if let Some(vn) = attr(&e, b"valueName") {
                            current_element = Some(AdmxElementBuilder::Boolean { value_name: vn });
                        }
                    }
                    b"decimal" | b"longDecimal" => {
                        if let Some(vn) = attr(&e, b"valueName") {
                            let min = attr(&e, b"minValue").and_then(|s| s.parse().ok());
                            let max = attr(&e, b"maxValue").and_then(|s| s.parse().ok());
                            current_element = Some(AdmxElementBuilder::Integer {
                                value_name: vn,
                                min,
                                max,
                            });
                        }
                    }
                    b"enum" => {
                        if let Some(vn) = attr(&e, b"valueName") {
                            current_element = Some(AdmxElementBuilder::Enum {
                                value_name: vn,
                                items: Vec::new(),
                            });
                            current_enum_items.clear();
                        }
                    }
                    b"item"
                        if current_element
                            .as_ref()
                            .is_some_and(|b| matches!(b, AdmxElementBuilder::Enum { .. })) =>
                    {
                        in_enum_item = true;
                        current_enum_item_display = None;
                        current_enum_item_value = None;
                    }
                    b"displayName" => {
                        if in_enum_item {
                            current_enum_item_display = Some(String::new());
                        }
                    }
                    b"value" if in_enum_item => {
                        in_enum_item_value = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let (_, local) = split_ns(&name_bytes);
                match local {
                    b"boolean" => {
                        if let Some(vn) = attr(&e, b"valueName") {
                            if let Some(p) = current_policy.as_mut() {
                                p.elements.push(AdmxElement::Boolean { value_name: vn });
                            }
                        }
                    }
                    b"text" => {
                        if let Some(vn) = attr(&e, b"valueName") {
                            if let Some(p) = current_policy.as_mut() {
                                p.elements.push(AdmxElement::Text { value_name: vn });
                            }
                        }
                    }
                    b"decimal" | b"longDecimal" => {
                        // Inside an enum-item value, this is a self-closing
                        // decimal element with `value` attribute.
                        if in_enum_item_value {
                            if let Some(v) = attr(&e, b"value") {
                                current_enum_item_value = Some(v);
                            }
                        } else if let Some(vn) = attr(&e, b"valueName") {
                            let min = attr(&e, b"minValue").and_then(|s| s.parse().ok());
                            let max = attr(&e, b"maxValue").and_then(|s| s.parse().ok());
                            if let Some(p) = current_policy.as_mut() {
                                p.elements.push(AdmxElement::Integer {
                                    value_name: vn,
                                    min,
                                    max,
                                });
                            }
                        }
                    }
                    b"supportedOn" => {
                        if let Some(p) = current_policy.as_mut() {
                            if let Some(ref_attr) = attr(&e, b"ref") {
                                p.supported_on = Some(ref_attr);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name_bytes = e.name().as_ref().to_vec();
                let (_, local) = split_ns(&name_bytes);
                match local {
                    b"policy" => {
                        if let Some(p) = current_policy.take() {
                            policies.push(p);
                        }
                    }
                    b"text" | b"boolean" | b"decimal" | b"longDecimal" => {
                        if let Some(builder) = current_element.take() {
                            if let Some(p) = current_policy.as_mut() {
                                p.elements.push(builder.build());
                            }
                        }
                    }
                    b"enum" => {
                        if let Some(builder) = current_element.take() {
                            if let Some(p) = current_policy.as_mut() {
                                p.elements.push(builder.build());
                            }
                        }
                        current_enum_items.clear();
                    }
                    b"item" => {
                        if in_enum_item {
                            let display = current_enum_item_display.take().unwrap_or_default();
                            let value = current_enum_item_value.take().unwrap_or_default();
                            if let Some(AdmxElementBuilder::Enum { items, .. }) =
                                current_element.as_mut()
                            {
                                items.push((value, display));
                            }
                            in_enum_item = false;
                        }
                    }
                    b"value" => {
                        in_enum_item_value = false;
                    }
                    b"displayName" => {
                        // displayName text was captured by the Text event below.
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(t)) => {
                let text = t
                    .unescape()
                    .map_err(|e| AdmxError::Parse(e.to_string()))?
                    .to_string();
                if in_enum_item && current_enum_item_display.is_some() {
                    if let Some(d) = current_enum_item_display.as_mut() {
                        d.push_str(&text);
                    }
                }
            }
            Ok(Event::CData(c)) => {
                let text = String::from_utf8_lossy(&c).to_string();
                if in_enum_item && current_enum_item_display.is_some() {
                    if let Some(d) = current_enum_item_display.as_mut() {
                        d.push_str(&text);
                    }
                }
            }
            Ok(Event::Eof) => break,
            // Comment / Decl / PI / DocType events are intentionally
            // ignored — they carry no policy-relevant data.
            Ok(_) => {}
            Err(e) => return Err(AdmxError::Parse(e.to_string())),
        }
        buf.clear();
    }

    Ok(policies)
}

/// Builder helper for [`AdmxElement`] — used internally by
/// [`parse_admx`] to accumulate state across `<text>`/`<decimal>`/etc.
/// start/end events.
#[derive(Debug, Clone)]
enum AdmxElementBuilder {
    Boolean {
        value_name: String,
    },
    Text {
        value_name: String,
    },
    Integer {
        value_name: String,
        min: Option<i64>,
        max: Option<i64>,
    },
    Enum {
        value_name: String,
        items: Vec<(String, String)>,
    },
}

impl AdmxElementBuilder {
    fn build(self) -> AdmxElement {
        match self {
            Self::Boolean { value_name } => AdmxElement::Boolean { value_name },
            Self::Text { value_name } => AdmxElement::Text { value_name },
            Self::Integer {
                value_name,
                min,
                max,
            } => AdmxElement::Integer {
                value_name,
                min,
                max,
            },
            Self::Enum { value_name, items } => AdmxElement::Enum { value_name, items },
        }
    }
}

/// Split a qualified XML name (e.g. `ns:local` or just `local`) into
/// `(namespace_prefix, local_name)`. ADMX uses the default namespace
/// (no prefix) for its core elements, so most names have no prefix.
fn split_ns(name: &[u8]) -> (Option<&[u8]>, &[u8]) {
    match name.iter().position(|&b| b == b':') {
        Some(i) => (Some(&name[..i]), &name[i + 1..]),
        None => (None, name),
    }
}

/// Read an attribute from an XML event by local name (ignoring any
/// namespace prefix). Returns `None` if not present.
fn attr<'a>(e: &'a quick_xml::events::BytesStart<'a>, local: &[u8]) -> Option<String> {
    for a in e.attributes().with_checks(false).flatten() {
        let (ns, name) = split_ns(a.key.as_ref());
        let _ = ns;
        if name == local {
            return Some(String::from_utf8_lossy(a.value.as_ref()).to_string());
        }
    }
    None
}

// ---- admx_to_declarative --------------------------------------------------

/// Convert parsed ADMX policies into a [`DeclarativePolicy`] (per ADR-090
/// §Decision — the framework's canonical JSON policy template).
///
/// Each [`AdmxPolicy`] becomes a set of [`PolicySetting`]s:
/// - If the policy has a top-level `value_name`, a setting with the
///   registry key path `<key>\<value_name>` and a default value derived
///   from the policy's `enabledValue` (boolean true if no `enabledValue`
///   is present).
/// - Each ADMX element becomes a setting with key `<key>\<element_value_name>`
///   and a typed default value:
///   - `Boolean` → `PolicyValue::Boolean(false)`
///   - `Text` → `PolicyValue::String(String::new())`
///   - `Integer` → `PolicyValue::Integer(0)` (or the min if set)
///   - `Enum` → `PolicyValue::String("")` with the first item value as
///     the documented default
///
/// The output is suitable for the framework's authoring UI to seed a
/// new policy instance from an ADMX template (per ADR-090 §Operational
/// impact).
pub fn admx_to_declarative(policies: &[AdmxPolicy]) -> DeclarativePolicy {
    let mut settings: Vec<PolicySetting> = Vec::new();
    for p in policies {
        // Top-level value (the policy's own on/off toggle).
        if let Some(vn) = &p.value_name {
            let key = format!("registry.{}\\{}", p.key, vn);
            settings.push(PolicySetting {
                key,
                value: PolicyValue::Boolean(true),
                applies_to: vec![],
            });
        }
        // Each element.
        for elem in &p.elements {
            match elem {
                AdmxElement::Boolean { value_name } => {
                    settings.push(PolicySetting {
                        key: format!("registry.{}\\{}", p.key, value_name),
                        value: PolicyValue::Boolean(false),
                        applies_to: vec![],
                    });
                }
                AdmxElement::Text { value_name } => {
                    settings.push(PolicySetting {
                        key: format!("registry.{}\\{}", p.key, value_name),
                        value: PolicyValue::String(String::new()),
                        applies_to: vec![],
                    });
                }
                AdmxElement::Integer {
                    value_name, min, ..
                } => {
                    let default = min.unwrap_or(0);
                    settings.push(PolicySetting {
                        key: format!("registry.{}\\{}", p.key, value_name),
                        value: PolicyValue::Integer(default),
                        applies_to: vec![],
                    });
                }
                AdmxElement::Enum {
                    value_name, items, ..
                } => {
                    let default = items.first().map(|(v, _)| v.clone()).unwrap_or_default();
                    settings.push(PolicySetting {
                        key: format!("registry.{}\\{}", p.key, value_name),
                        value: PolicyValue::String(default),
                        applies_to: vec![],
                    });
                }
            }
        }
    }
    DeclarativePolicy {
        version: 1,
        name: "admx-imported".into(),
        description: format!("Imported from {} ADMX policies", policies.len()),
        settings,
    }
}

#[cfg(test)]
mod tests {
    //! Behavioral tests for `adrian-admx-compiler`. Per the Wave 4a task
    //! instructions these cover the real ADMX XML parsing and the
    //! `admx_to_declarative` conversion — the loud-stub test from the
    //! prior wave has been replaced by real round-trip tests using a
    //! small synthetic ADMX file modelled on the example in
    //! `docs/04-group-policy/03-admx-templates.md`.

    use super::*;

    /// A small synthetic ADMX file used by the parser tests. Modelled
    /// on the "contoso.admx" example in the docs.
    const SAMPLE_ADMX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions xmlns="http://www.microsoft.com/GroupPolicy/PolicyDefinitions" revision="1.0">
  <policyNamespaces>
    <target prefix="contoso" namespace="Contoso.Policies.App" />
  </policyNamespaces>
  <policies>
    <policy name="POL_EnableFeature" class="Machine"
            displayName="$(string.POL_EnableFeature)"
            explainText="$(string.POL_EnableFeature_Help)"
            key="Software\Policies\Contoso\App"
            valueName="Enabled">
      <supportedOn ref="SUPPORTED_Win10_1809" />
      <enabledValue><decimal value="1" /></enabledValue>
      <disabledValue><decimal value="0" /></disabledValue>
      <elements>
        <text id="PART_Threshold" valueName="Threshold" required="true" />
        <decimal id="PART_MaxConn" valueName="MaxConnections" minValue="1" maxValue="100" />
        <boolean id="PART_Log" valueName="Logging" />
        <enum id="PART_LogLevel" valueName="LogLevel" required="true">
          <item displayName="$(string.LOG_LOW)">
            <value><decimal value="1" /></value>
          </item>
          <item displayName="$(string.LOG_HIGH)">
            <value><decimal value="2" /></value>
          </item>
        </enum>
      </elements>
    </policy>
    <policy name="POL_UserSetting" class="User"
            displayName="$(string.POL_UserSetting)"
            key="Software\Policies\Contoso\User"
            valueName="Mode">
      <supportedOn ref="SUPPORTED_Win11" />
    </policy>
  </policies>
</policyDefinitions>"#;

    #[test]
    fn admx_class_parse_accepts_machine_user_both() {
        assert_eq!(AdmxClass::parse("Machine").unwrap(), AdmxClass::Machine);
        assert_eq!(AdmxClass::parse("User").unwrap(), AdmxClass::User);
        assert_eq!(AdmxClass::parse("Both").unwrap(), AdmxClass::Both);
        // Case-insensitive.
        assert_eq!(AdmxClass::parse("machine").unwrap(), AdmxClass::Machine);
    }

    #[test]
    fn admx_class_parse_rejects_unknown_value() {
        let err = AdmxClass::parse("Server").unwrap_err();
        assert!(matches!(err, AdmxError::Semantic(_)));
        assert!(err.to_string().contains("unknown ADMX class"));
    }

    #[test]
    fn admx_class_as_str_round_trips() {
        for c in [AdmxClass::Machine, AdmxClass::User, AdmxClass::Both] {
            let back = AdmxClass::parse(c.as_str()).expect("round trip");
            assert_eq!(back, c);
        }
    }

    #[test]
    fn admx_error_variants_render_messages() {
        let parse = AdmxError::Parse("xml eof".into());
        let semantic = AdmxError::Semantic("bad class".into());
        assert_eq!(parse.to_string(), "admx parse: xml eof");
        assert_eq!(semantic.to_string(), "semantic: bad class");
    }

    #[test]
    fn parse_admx_extracts_policy_metadata() {
        let policies = parse_admx(SAMPLE_ADMX).expect("parse");
        assert_eq!(policies.len(), 2);
        let first = &policies[0];
        assert_eq!(first.name, "POL_EnableFeature");
        assert_eq!(first.class, AdmxClass::Machine);
        assert_eq!(first.key, "Software\\Policies\\Contoso\\App");
        assert_eq!(first.value_name.as_deref(), Some("Enabled"));
        assert_eq!(first.supported_on.as_deref(), Some("SUPPORTED_Win10_1809"));
        assert_eq!(first.display_name, "$(string.POL_EnableFeature)");
    }

    #[test]
    fn parse_admx_extracts_elements_in_order() {
        let policies = parse_admx(SAMPLE_ADMX).expect("parse");
        let first = &policies[0];
        assert_eq!(first.elements.len(), 4);
        // The elements should be parsed in document order:
        // text, decimal (integer), boolean, enum.
        assert!(matches!(first.elements[0], AdmxElement::Text { .. }));
        assert!(matches!(first.elements[1], AdmxElement::Integer { .. }));
        assert!(matches!(first.elements[2], AdmxElement::Boolean { .. }));
        assert!(matches!(first.elements[3], AdmxElement::Enum { .. }));
    }

    #[test]
    fn parse_admx_decimal_element_captures_min_max() {
        let policies = parse_admx(SAMPLE_ADMX).expect("parse");
        let first = &policies[0];
        if let AdmxElement::Integer {
            value_name,
            min,
            max,
        } = &first.elements[1]
        {
            assert_eq!(value_name, "MaxConnections");
            assert_eq!(*min, Some(1));
            assert_eq!(*max, Some(100));
        } else {
            panic!("expected Integer element");
        }
    }

    #[test]
    fn parse_admx_enum_element_captures_items() {
        let policies = parse_admx(SAMPLE_ADMX).expect("parse");
        let first = &policies[0];
        if let AdmxElement::Enum { value_name, items } = &first.elements[3] {
            assert_eq!(value_name, "LogLevel");
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].0, "1");
            assert_eq!(items[1].0, "2");
        } else {
            panic!("expected Enum element");
        }
    }

    #[test]
    fn parse_admx_returns_empty_for_no_policies() {
        let admx = r#"<?xml version="1.0"?>
<policyDefinitions xmlns="http://www.microsoft.com/GroupPolicy/PolicyDefinitions">
  <policies></policies>
</policyDefinitions>"#;
        let policies = parse_admx(admx).expect("parse");
        assert!(policies.is_empty());
    }

    #[test]
    fn parse_admx_rejects_malformed_xml() {
        let err = parse_admx("not xml <broken").unwrap_err();
        assert!(matches!(err, AdmxError::Parse(_)));
    }

    #[test]
    fn admx_to_declarative_emits_one_setting_per_value_and_element() {
        let policies = parse_admx(SAMPLE_ADMX).expect("parse");
        let decl = admx_to_declarative(&policies);
        // Policy 1: 1 top-level value + 4 elements = 5 settings.
        // Policy 2: 1 top-level value + 0 elements = 1 setting.
        assert_eq!(decl.settings.len(), 6);
        // All settings should have keys starting with "registry.".
        assert!(decl.settings.iter().all(|s| s.key.starts_with("registry.")));
        // The top-level toggle for POL_EnableFeature is boolean true.
        let toggle = decl
            .settings
            .iter()
            .find(|s| s.key.ends_with("Enabled"))
            .expect("Enabled setting");
        assert_eq!(toggle.value, PolicyValue::Boolean(true));
    }

    #[test]
    fn admx_to_declarative_integer_uses_min_as_default() {
        let policies = parse_admx(SAMPLE_ADMX).expect("parse");
        let decl = admx_to_declarative(&policies);
        let setting = decl
            .settings
            .iter()
            .find(|s| s.key.ends_with("MaxConnections"))
            .expect("MaxConnections setting");
        // The min value is 1 — used as the default.
        assert_eq!(setting.value, PolicyValue::Integer(1));
    }

    #[test]
    fn admx_to_declarative_enum_uses_first_item_as_default() {
        let policies = parse_admx(SAMPLE_ADMX).expect("parse");
        let decl = admx_to_declarative(&policies);
        let setting = decl
            .settings
            .iter()
            .find(|s| s.key.ends_with("LogLevel"))
            .expect("LogLevel setting");
        // First item value is "1".
        assert_eq!(setting.value, PolicyValue::String("1".into()));
    }

    #[test]
    fn admx_to_declarative_for_empty_policies_yields_empty_settings() {
        let decl = admx_to_declarative(&[]);
        assert!(decl.settings.is_empty());
        assert_eq!(decl.version, 1);
    }

    #[test]
    fn compile_legacy_entrypoint_returns_one_doc_per_admx_file() {
        // The legacy `compile(admx_path, adml_path)` entrypoint still
        // works (reading from disk). Write the sample to temp files
        // and verify it returns a single PolicyDoc.
        let tmp = std::env::temp_dir();
        let admx_path = tmp.join("w4a_admx_compiler_test.admx");
        let adml_path = tmp.join("w4a_admx_compiler_test.adml");
        std::fs::write(&admx_path, SAMPLE_ADMX).expect("write admx");
        std::fs::write(&adml_path, "<adml/>").expect("write adml");
        let docs =
            compile(admx_path.to_str().unwrap(), adml_path.to_str().unwrap()).expect("compile");
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].name, "admx-imported");
    }
}
