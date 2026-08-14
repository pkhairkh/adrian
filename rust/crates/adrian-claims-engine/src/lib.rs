//! # adrian-claims-engine
//!
//! AD FS claim rule language compatibility layer. Translates legacy AD FS
//! claim rules into CEL selectors for the federation shim, and evaluates
//! them against an input claim set to produce output claims.
//!
//! ## ADRs
//!
//! - ADR-100: Keycloak replaces AD FS farm (WID/SQL/WAP)
//! - ADR-101: AD FS claim rule language compatibility
//! - ADR-102: Rust shim replaces WAP
//! - ADR-104: Keycloak identity brokering + HRD

use adrian_policy_cel::CelSelector;
use std::collections::HashMap;
use thiserror::Error;

/// An error from claim-rule parsing, CEL compilation, or evaluation.
#[derive(Debug, Error)]
pub enum ClaimsError {
    /// Parse error (malformed claim rule text).
    #[error("parse: {0}")]
    Parse(String),
    /// CEL compilation error.
    #[error("compile to CEL: {0}")]
    Compile(String),
    /// Evaluation error.
    #[error("eval: {0}")]
    Eval(String),
}

// =========================================================================
// Claim types
// =========================================================================

/// A single claim — a `(type, value)` pair, optionally with additional
/// properties (e.g. `Issuer`, `OriginalIssuer`, `ValueType`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The claim type URI (e.g. `http://schemas.xmlsoap.org/claims/Group`).
    pub claim_type: String,
    /// The claim value (e.g. `Domain Admins`).
    pub value: String,
    /// Optional properties (e.g. `Issuer`, `OriginalIssuer`, `ValueType`).
    pub properties: HashMap<String, String>,
}

impl Claim {
    /// Construct a minimal claim with just type + value.
    #[must_use]
    pub fn new(claim_type: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            claim_type: claim_type.into(),
            value: value.into(),
            properties: HashMap::new(),
        }
    }

    /// Set a property on the claim (builder pattern).
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

/// The action a claim rule takes when its condition matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    /// `issue(...)` — emit a new claim.
    Issue(Claim),
    /// `add(...)` — add a claim to the input set (does not emit).
    Add(Claim),
    /// `deny(...)` — block the request (per ADR-101 §Deny rules).
    Deny(String),
}

/// A parsed AD FS claim rule (per ADR-101 §Claim Rule Language grammar).
///
/// The grammar is:
/// ```text
/// rule        := [condition] "=>" action ";"
/// condition  := "c:" "[" condition_list "]"
/// condition_list := condition_item ("," condition_item)*
/// condition_item := property "==" string_literal
/// action      := "issue" "(" arg_list ")" | "add" "(" arg_list ")" | "deny" "(" string_literal ")"
/// arg_list    := arg ("," arg)*
/// arg         := identifier "=" (string_literal | identifier)
/// ```
#[derive(Debug, Clone)]
pub struct ClaimRule {
    /// The original source text (for diagnostics).
    pub source: String,
    /// The optional condition (if `None`, the rule is unconditional).
    pub condition: Option<Vec<ConditionItem>>,
    /// The action to take when the condition matches.
    pub action: RuleAction,
}

/// A single condition item — `property == value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionItem {
    /// The claim property to test (e.g. `Type`, `Value`).
    pub property: String,
    /// The expected value (a string literal from the rule text).
    pub expected: String,
}

impl ClaimRule {
    /// Parse one AD FS claim rule per ADR-101 §Claim Rule Language.
    ///
    /// Supported forms:
    /// - `=> issue(Type = "role", Value = "admin");` — unconditional issue
    /// - `c:[Type == "group", Value == "admins"] => issue(Type = "role", Value = "admin");`
    /// - `=> deny("unauthorised");` — unconditional deny
    pub fn parse(source: impl Into<String>) -> Result<Self, ClaimsError> {
        let source = source.into();
        let trimmed = source.trim();
        // Must end with ';'
        let body = trimmed
            .strip_suffix(';')
            .ok_or_else(|| ClaimsError::Parse("rule must end with ';'".into()))?;
        // Split on "=>"
        let arrow_idx = body
            .find("=>")
            .ok_or_else(|| ClaimsError::Parse("rule must contain '=>'".into()))?;
        let cond_str = body[..arrow_idx].trim();
        let action_str = body[arrow_idx + 2..].trim();

        // Parse the condition (if any).
        let condition = if cond_str.is_empty() {
            None
        } else {
            Some(parse_condition(cond_str)?)
        };

        // Parse the action.
        let action = parse_action(action_str)?;

        Ok(Self {
            source,
            condition,
            action,
        })
    }

    /// Compile the rule's condition to a CEL selector. The selector
    /// evaluates to `true` when the input claim set contains a claim
    /// matching the condition.
    ///
    /// The CEL context is a JSON object with a `claims` array:
    /// ```json
    /// { "claims": [ { "type": "group", "value": "admins" }, ... ] }
    /// ```
    pub fn to_cel(&self) -> Result<CelSelector, ClaimsError> {
        let expr = self.to_cel_expr();
        CelSelector::compile(&expr).map_err(|e| ClaimsError::Compile(e.to_string()))
    }

    /// Build the CEL expression string for this rule's condition.
    fn to_cel_expr(&self) -> String {
        match &self.condition {
            None => "true".to_string(),
            Some(items) => {
                // Build a CEL expression that checks if any claim in the
                // input set matches all condition items.
                let mut parts = Vec::new();
                for item in items {
                    let prop_lower = item.property.to_lowercase();
                    let prop = match item.property.as_str() {
                        "Type" => "type",
                        "Value" => "value",
                        _ => &prop_lower,
                    };
                    parts.push(format!(
                        "c.{} == '{}'",
                        prop,
                        item.expected.replace('\'', "\\'")
                    ));
                }
                format!("claims.exists(c, {})", parts.join(" && "))
            }
        }
    }
}

/// Parse the condition part of a claim rule (e.g. `c:[Type == "group", Value == "admins"]`).
fn parse_condition(s: &str) -> Result<Vec<ConditionItem>, ClaimsError> {
    let s = s.trim();
    // Must start with "c:[" and end with "]".
    let inner = s
        .strip_prefix("c:[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| ClaimsError::Parse("condition must be 'c:[...]'".into()))?;
    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    for part in split_top_level(inner, ',') {
        let part = part.trim();
        let eq_idx = part
            .find("==")
            .ok_or_else(|| ClaimsError::Parse(format!("condition item '{part}' missing '=='")))?;
        let property = part[..eq_idx].trim().to_string();
        let value_str = part[eq_idx + 2..].trim();
        let expected = parse_string_literal(value_str)?;
        items.push(ConditionItem { property, expected });
    }
    Ok(items)
}

/// Parse the action part of a claim rule (e.g. `issue(Type = "role", Value = "admin")`).
fn parse_action(s: &str) -> Result<RuleAction, ClaimsError> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("issue(") {
        let args = rest
            .strip_suffix(')')
            .ok_or_else(|| ClaimsError::Parse("issue() missing ')'".into()))?;
        let claim = parse_claim_args(args)?;
        Ok(RuleAction::Issue(claim))
    } else if let Some(rest) = s.strip_prefix("add(") {
        let args = rest
            .strip_suffix(')')
            .ok_or_else(|| ClaimsError::Parse("add() missing ')'".into()))?;
        let claim = parse_claim_args(args)?;
        Ok(RuleAction::Add(claim))
    } else if let Some(rest) = s.strip_prefix("deny(") {
        let reason = rest
            .strip_suffix(')')
            .ok_or_else(|| ClaimsError::Parse("deny() missing ')'".into()))?;
        let reason = parse_string_literal(reason.trim())?;
        Ok(RuleAction::Deny(reason))
    } else {
        Err(ClaimsError::Parse(format!(
            "unknown action: '{s}' (expected issue/add/deny)"
        )))
    }
}

/// Parse the argument list of `issue(...)` / `add(...)` — e.g.
/// `Type = "role", Value = "admin"`.
fn parse_claim_args(args: &str) -> Result<Claim, ClaimsError> {
    let mut claim_type = String::new();
    let mut value = String::new();
    let mut properties = HashMap::new();
    for part in split_top_level(args, ',') {
        let part = part.trim();
        let eq_idx = part
            .find('=')
            .ok_or_else(|| ClaimsError::Parse(format!("arg '{part}' missing '='")))?;
        let key = part[..eq_idx].trim();
        let val_str = part[eq_idx + 1..].trim();
        let val = parse_string_literal(val_str)?;
        match key {
            "Type" => claim_type = val,
            "Value" => value = val,
            other => {
                properties.insert(other.to_string(), val);
            }
        }
    }
    if claim_type.is_empty() {
        return Err(ClaimsError::Parse("issue/add requires Type".into()));
    }
    if value.is_empty() {
        return Err(ClaimsError::Parse("issue/add requires Value".into()));
    }
    Ok(Claim {
        claim_type,
        value,
        properties,
    })
}

/// Parse a string literal — either `"..."` or `'...'`.
fn parse_string_literal(s: &str) -> Result<String, ClaimsError> {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        Ok(s[1..s.len() - 1].to_string())
    } else {
        Err(ClaimsError::Parse(format!(
            "expected string literal, got '{s}'"
        )))
    }
}

/// Split `s` on `sep` at the top level (not inside quotes or parentheses).
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut string_char = '\0';
    let mut paren_depth = 0;
    for c in s.chars() {
        if in_string {
            current.push(c);
            if c == string_char {
                in_string = false;
            }
        } else if c == '"' || c == '\'' {
            in_string = true;
            string_char = c;
            current.push(c);
        } else if c == '(' {
            paren_depth += 1;
            current.push(c);
        } else if c == ')' {
            paren_depth -= 1;
            current.push(c);
        } else if c == sep && paren_depth == 0 {
            parts.push(current.clone());
            current.clear();
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

// =========================================================================
// ClaimsEngine
// =========================================================================

/// The claims engine — evaluates a list of claim rules against an input
/// claim set and produces an output claim set (per ADR-101).
pub struct ClaimsEngine;

impl ClaimsEngine {
    /// Construct a new `ClaimsEngine`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a list of claim rules against the input claims.
    ///
    /// Each rule is evaluated in order. For each rule:
    /// 1. If the rule has no condition, the action is taken unconditionally.
    /// 2. If the rule has a condition, the condition is checked against
    ///    every input claim. If ANY input claim matches, the action is taken.
    /// 3. `Issue` actions add a new claim to the output set.
    /// 4. `Add` actions add a new claim to the input set (visible to
    ///    subsequent rules).
    /// 5. `Deny` actions immediately return an error.
    ///
    /// Returns the output claim set, or an error if a `Deny` rule fires.
    pub fn evaluate(
        &self,
        rules: &[ClaimRule],
        input_claims: &[Claim],
    ) -> Result<Vec<Claim>, ClaimsError> {
        let mut working_claims: Vec<Claim> = input_claims.to_vec();
        let mut output_claims: Vec<Claim> = Vec::new();
        for rule in rules {
            let matches = match &rule.condition {
                None => true,
                Some(items) => working_claims.iter().any(|c| {
                    items.iter().all(|item| {
                        let actual = match item.property.as_str() {
                            "Type" => &c.claim_type,
                            "Value" => &c.value,
                            other => c.properties.get(other).map(|s| s.as_str()).unwrap_or(""),
                        };
                        actual == item.expected
                    })
                }),
            };
            if !matches {
                continue;
            }
            match &rule.action {
                RuleAction::Issue(claim) => {
                    output_claims.push(claim.clone());
                }
                RuleAction::Add(claim) => {
                    working_claims.push(claim.clone());
                }
                RuleAction::Deny(reason) => {
                    return Err(ClaimsError::Eval(format!("denied: {reason}")));
                }
            }
        }
        Ok(output_claims)
    }
}

impl Default for ClaimsEngine {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for `adrian-claims-engine`. These cover the real CRL
    //! parser, the CEL translation, and the claims evaluation engine.

    use super::*;

    // ---- error variants --------------------------------------------------

    #[test]
    fn claims_error_variants_render_messages() {
        assert_eq!(ClaimsError::Parse("eof".into()).to_string(), "parse: eof");
        assert_eq!(
            ClaimsError::Compile("no binding".into()).to_string(),
            "compile to CEL: no binding"
        );
        assert_eq!(
            ClaimsError::Eval("undefined".into()).to_string(),
            "eval: undefined"
        );
    }

    // ---- ClaimRule::parse ------------------------------------------------

    #[test]
    fn parse_unconditional_issue_rule() {
        let rule = ClaimRule::parse(r#"=> issue(Type = "role", Value = "admin");"#).expect("parse");
        assert!(rule.condition.is_none());
        match rule.action {
            RuleAction::Issue(c) => {
                assert_eq!(c.claim_type, "role");
                assert_eq!(c.value, "admin");
            }
            other => panic!("expected Issue, got {other:?}"),
        }
    }

    #[test]
    fn parse_conditional_issue_rule() {
        let rule = ClaimRule::parse(
            r#"c:[Type == "group", Value == "admins"] => issue(Type = "role", Value = "admin");"#,
        )
        .expect("parse");
        let cond = rule.condition.expect("condition");
        assert_eq!(cond.len(), 2);
        assert_eq!(cond[0].property, "Type");
        assert_eq!(cond[0].expected, "group");
        assert_eq!(cond[1].property, "Value");
        assert_eq!(cond[1].expected, "admins");
    }

    #[test]
    fn parse_deny_rule() {
        let rule = ClaimRule::parse(r#"=> deny("unauthorised");"#).expect("parse");
        match rule.action {
            RuleAction::Deny(reason) => assert_eq!(reason, "unauthorised"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_missing_semicolon() {
        let err = ClaimRule::parse(r#"=> issue(Type = "role", Value = "admin")"#).unwrap_err();
        assert!(matches!(err, ClaimsError::Parse(_)));
        assert!(err.to_string().contains("';'"));
    }

    #[test]
    fn parse_rejects_missing_arrow() {
        let err = ClaimRule::parse(r#"issue(Type = "role", Value = "admin");"#).unwrap_err();
        assert!(matches!(err, ClaimsError::Parse(_)));
        assert!(err.to_string().contains("'=>'"));
    }

    // ---- ClaimRule::to_cel -----------------------------------------------

    #[test]
    fn to_cel_unconditional_rule_compiles_to_true() {
        let rule = ClaimRule::parse(r#"=> issue(Type = "role", Value = "admin");"#).unwrap();
        let sel = rule.to_cel().expect("to_cel");
        // Unconditional rule → CEL "true" → evaluates to true.
        let result = sel.eval(&serde_json::Value::Null).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
    }

    #[test]
    fn to_cel_conditional_rule_compiles_to_exists_expression() {
        let rule = ClaimRule::parse(
            r#"c:[Type == "group", Value == "admins"] => issue(Type = "role", Value = "admin");"#,
        )
        .unwrap();
        let sel = rule.to_cel().expect("to_cel");
        // With matching claims → true.
        let facts = serde_json::json!({
            "claims": [
                { "type": "group", "value": "admins" }
            ]
        });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(true));
        // With non-matching claims → false.
        let facts = serde_json::json!({
            "claims": [
                { "type": "group", "value": "users" }
            ]
        });
        let result = sel.eval(&facts).expect("eval");
        assert_eq!(result, serde_json::Value::Bool(false));
    }

    // ---- ClaimsEngine::evaluate ------------------------------------------

    #[test]
    fn evaluate_unconditional_issue_emits_claim() {
        let engine = ClaimsEngine::new();
        let rule = ClaimRule::parse(r#"=> issue(Type = "role", Value = "admin");"#).unwrap();
        let input = vec![Claim::new("group", "users")];
        let output = engine.evaluate(&[rule], &input).expect("eval");
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].claim_type, "role");
        assert_eq!(output[0].value, "admin");
    }

    #[test]
    fn evaluate_conditional_issue_emits_only_on_match() {
        let engine = ClaimsEngine::new();
        let rule = ClaimRule::parse(
            r#"c:[Type == "group", Value == "admins"] => issue(Type = "role", Value = "admin");"#,
        )
        .unwrap();
        // Matching input.
        let input = vec![Claim::new("group", "admins")];
        let output = engine
            .evaluate(std::slice::from_ref(&rule), &input)
            .expect("eval");
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].value, "admin");
        // Non-matching input.
        let input = vec![Claim::new("group", "users")];
        let output = engine.evaluate(&[rule], &input).expect("eval");
        assert!(output.is_empty());
    }

    #[test]
    fn evaluate_deny_rule_returns_error() {
        let engine = ClaimsEngine::new();
        let rule = ClaimRule::parse(r#"=> deny("access blocked");"#).unwrap();
        let input = vec![Claim::new("group", "users")];
        let err = engine.evaluate(&[rule], &input).unwrap_err();
        assert!(matches!(err, ClaimsError::Eval(_)));
        assert!(err.to_string().contains("access blocked"));
    }

    #[test]
    fn evaluate_add_action_adds_to_working_set_for_subsequent_rules() {
        let engine = ClaimsEngine::new();
        let rule1 = ClaimRule::parse(r#"=> add(Type = "group", Value = "added-group");"#).unwrap();
        let rule2 = ClaimRule::parse(
            r#"c:[Type == "group", Value == "added-group"] => issue(Type = "role", Value = "admin");"#,
        )
        .unwrap();
        let input: Vec<Claim> = vec![];
        let output = engine.evaluate(&[rule1, rule2], &input).expect("eval");
        // rule1 adds a claim; rule2 sees it and issues a role claim.
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].value, "admin");
    }

    #[test]
    fn evaluate_multiple_rules_apply_in_order() {
        let engine = ClaimsEngine::new();
        let rules = vec![
            ClaimRule::parse(r#"=> issue(Type = "role", Value = "user");"#).unwrap(),
            ClaimRule::parse(r#"=> issue(Type = "role", Value = "guest");"#).unwrap(),
        ];
        let output = engine.evaluate(&rules, &[]).expect("eval");
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].value, "user");
        assert_eq!(output[1].value, "guest");
    }
}
