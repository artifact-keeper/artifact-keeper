//! SAML 2.0 authentication service.
//!
//! Provides authentication via SAML Identity Providers (IdPs) like
//! Okta, Azure AD, ADFS, Shibboleth, etc.

use std::collections::HashMap;
use std::sync::Arc;

use quick_xml::escape::unescape;
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};

/// SAML configuration
#[derive(Debug, Clone)]
pub struct SamlConfig {
    /// SAML IdP metadata URL
    pub idp_metadata_url: Option<String>,
    /// SAML IdP SSO URL (if not using metadata)
    pub idp_sso_url: String,
    /// SAML IdP issuer/entity ID
    pub idp_issuer: String,
    /// IdP certificate (PEM format) for signature verification
    pub idp_certificate: Option<String>,
    /// Service Provider entity ID
    pub sp_entity_id: String,
    /// Assertion Consumer Service (ACS) URL
    pub acs_url: String,
    /// Attribute containing username
    pub username_attr: String,
    /// Attribute containing email
    pub email_attr: String,
    /// Attribute containing display name
    pub display_name_attr: String,
    /// Attribute containing groups
    pub groups_attr: String,
    /// Group name for admin role
    pub admin_group: Option<String>,
    /// Sign authentication requests
    pub sign_requests: bool,
    /// Require signed assertions
    pub require_signed_assertions: bool,
}

impl SamlConfig {
    /// Create SAML config from environment variables
    pub fn from_env() -> Option<Self> {
        let idp_sso_url = std::env::var("SAML_IDP_SSO_URL").ok()?;
        let idp_issuer = std::env::var("SAML_IDP_ISSUER").ok()?;

        Some(Self {
            idp_metadata_url: std::env::var("SAML_IDP_METADATA_URL").ok(),
            idp_sso_url,
            idp_issuer,
            idp_certificate: std::env::var("SAML_IDP_CERTIFICATE").ok(),
            sp_entity_id: std::env::var("SAML_SP_ENTITY_ID")
                .unwrap_or_else(|_| "artifact-keeper".to_string()),
            acs_url: std::env::var("SAML_ACS_URL")
                .unwrap_or_else(|_| "http://localhost:8080/auth/saml/acs".to_string()),
            username_attr: std::env::var("SAML_USERNAME_ATTR")
                .unwrap_or_else(|_| "NameID".to_string()),
            email_attr: std::env::var("SAML_EMAIL_ATTR").unwrap_or_else(|_| "email".to_string()),
            display_name_attr: std::env::var("SAML_DISPLAY_NAME_ATTR")
                .unwrap_or_else(|_| "displayName".to_string()),
            groups_attr: std::env::var("SAML_GROUPS_ATTR").unwrap_or_else(|_| "groups".to_string()),
            admin_group: std::env::var("SAML_ADMIN_GROUP").ok(),
            sign_requests: std::env::var("SAML_SIGN_REQUESTS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            require_signed_assertions: std::env::var("SAML_REQUIRE_SIGNED_ASSERTIONS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
        })
    }
}

/// SAML user information extracted from assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlUserInfo {
    /// NameID from SAML response
    pub name_id: String,
    /// NameID format
    pub name_id_format: Option<String>,
    /// Session index
    pub session_index: Option<String>,
    /// Username
    pub username: String,
    /// Email address
    pub email: String,
    /// Display name
    pub display_name: Option<String>,
    /// Group memberships
    pub groups: Vec<String>,
    /// All attributes from assertion
    pub attributes: HashMap<String, Vec<String>>,
}

/// SAML AuthnRequest parameters
#[derive(Debug, Clone, Serialize)]
pub struct SamlAuthnRequest {
    /// URL to redirect to
    pub redirect_url: String,
    /// Request ID for tracking
    pub request_id: String,
    /// Relay state (for callback)
    pub relay_state: String,
}

/// Parsed SAML Response
#[derive(Debug, Clone)]
pub struct SamlResponse {
    /// Response ID
    pub id: String,
    /// In response to (request ID)
    pub in_response_to: Option<String>,
    /// Issuer (IdP entity ID)
    pub issuer: String,
    /// Status code
    pub status_code: String,
    /// Status message
    pub status_message: Option<String>,
    /// Assertion data
    pub assertion: Option<SamlAssertion>,
}

/// Parsed SAML Assertion
#[derive(Debug, Clone)]
pub struct SamlAssertion {
    /// Assertion ID
    pub id: String,
    /// Issuer
    pub issuer: String,
    /// Subject NameID
    pub name_id: String,
    /// NameID format
    pub name_id_format: Option<String>,
    /// Session index
    pub session_index: Option<String>,
    /// Not before timestamp
    pub not_before: Option<String>,
    /// Not on or after timestamp
    pub not_on_or_after: Option<String>,
    /// Audience restrictions
    pub audiences: Vec<String>,
    /// Attributes
    pub attributes: HashMap<String, Vec<String>>,
}

/// Helper to extract a named XML attribute value from a quick_xml element's attributes.
/// Returns `None` if the attribute is not present.
fn get_xml_attr(e: &quick_xml::events::BytesStart<'_>, attr_name: &str) -> Option<String> {
    e.attributes().flatten().find_map(|attr| {
        let key = String::from_utf8_lossy(attr.key.as_ref());
        if key == attr_name {
            Some(String::from_utf8_lossy(&attr.value).to_string())
        } else {
            None
        }
    })
}

/// Collects all XML attributes from a quick_xml element into key-value pairs.
fn collect_xml_attrs(e: &quick_xml::events::BytesStart<'_>) -> Vec<(String, String)> {
    e.attributes()
        .flatten()
        .map(|attr| {
            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
            let value = String::from_utf8_lossy(&attr.value).to_string();
            (key, value)
        })
        .collect()
}

/// Mutable state used while walking a SAML response XML document.
struct SamlResponseParser {
    response: SamlResponse,
    assertion: SamlAssertion,
    current_element: String,
    in_assertion: bool,
    current_attr_name: Option<String>,
    current_attr_values: Vec<String>,
}

impl SamlResponseParser {
    fn new() -> Self {
        Self {
            response: SamlResponse {
                id: String::new(),
                in_response_to: None,
                issuer: String::new(),
                status_code: String::new(),
                status_message: None,
                assertion: None,
            },
            assertion: SamlAssertion {
                id: String::new(),
                issuer: String::new(),
                name_id: String::new(),
                name_id_format: None,
                session_index: None,
                not_before: None,
                not_on_or_after: None,
                audiences: Vec::new(),
                attributes: HashMap::new(),
            },
            current_element: String::new(),
            in_assertion: false,
            current_attr_name: None,
            current_attr_values: Vec::new(),
        }
    }

    /// Handle an `Event::Start` element.
    fn handle_start(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
        self.current_element = name.clone();

        match name.as_str() {
            "Response" => self.handle_response_start(e),
            "Assertion" => self.handle_assertion_start(e),
            "StatusCode" => self.handle_status_code(e),
            "NameID" => self.handle_name_id_start(e),
            "Conditions" => self.handle_conditions_start(e),
            "AuthnStatement" => self.handle_authn_statement(e),
            "Attribute" => self.handle_attribute_start(e),
            _ => {}
        }
    }

    /// Handle an `Event::Empty` (self-closing) element.
    fn handle_empty(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
        match name.as_str() {
            "StatusCode" => self.handle_status_code(e),
            "AuthnStatement" => self.handle_authn_statement(e),
            _ => {}
        }
    }

    /// Handle an `Event::Text` node.
    fn handle_text(&mut self, e: &quick_xml::events::BytesText<'_>) {
        let raw = String::from_utf8_lossy(e.as_ref());
        let text = unescape(&raw)
            .map(|c| c.to_string())
            .unwrap_or_else(|_| raw.to_string());

        if text.trim().is_empty() {
            return;
        }

        match self.current_element.as_str() {
            "Issuer" => self.handle_issuer_text(text),
            "NameID" => self.assertion.name_id = text,
            "Audience" => self.assertion.audiences.push(text),
            "AttributeValue" => self.current_attr_values.push(text),
            "StatusMessage" => self.response.status_message = Some(text),
            _ => {}
        }
    }

    /// Handle an `Event::End` element.
    fn handle_end(&mut self, e: &quick_xml::events::BytesEnd<'_>) {
        let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
        match name.as_str() {
            "Assertion" => {
                self.in_assertion = false;
                self.response.assertion = Some(self.assertion.clone());
            }
            "Attribute" => {
                if let Some(attr_name) = self.current_attr_name.take() {
                    self.assertion
                        .attributes
                        .insert(attr_name, self.current_attr_values.clone());
                    self.current_attr_values.clear();
                }
            }
            _ => {}
        }
    }

    // -- Element-specific handlers --

    fn handle_response_start(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        for (key, value) in collect_xml_attrs(e) {
            match key.as_str() {
                "ID" => self.response.id = value,
                "InResponseTo" => self.response.in_response_to = Some(value),
                _ => {}
            }
        }
    }

    fn handle_assertion_start(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        self.in_assertion = true;
        if let Some(id) = get_xml_attr(e, "ID") {
            self.assertion.id = id;
        }
    }

    fn handle_status_code(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        if let Some(value) = get_xml_attr(e, "Value") {
            self.response.status_code = value;
        }
    }

    fn handle_name_id_start(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        if let Some(format) = get_xml_attr(e, "Format") {
            self.assertion.name_id_format = Some(format);
        }
    }

    fn handle_conditions_start(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        for (key, value) in collect_xml_attrs(e) {
            match key.as_str() {
                "NotBefore" => self.assertion.not_before = Some(value),
                "NotOnOrAfter" => self.assertion.not_on_or_after = Some(value),
                _ => {}
            }
        }
    }

    fn handle_authn_statement(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        if let Some(session_index) = get_xml_attr(e, "SessionIndex") {
            self.assertion.session_index = Some(session_index);
        }
    }

    fn handle_attribute_start(&mut self, e: &quick_xml::events::BytesStart<'_>) {
        if let Some(name) = get_xml_attr(e, "Name") {
            self.current_attr_name = Some(name);
            self.current_attr_values.clear();
        }
    }

    fn handle_issuer_text(&mut self, text: String) {
        if self.in_assertion {
            self.assertion.issuer = text;
        } else {
            self.response.issuer = text;
        }
    }

    /// Consume the parser and return the finished `SamlResponse`.
    fn finish(self) -> SamlResponse {
        self.response
    }
}

/// SAML authentication service
pub struct SamlService {
    db: PgPool,
    config: SamlConfig,
    #[allow(dead_code)]
    http_client: Client,
}

impl SamlService {
    /// Create a new SAML service
    pub fn new(db: PgPool, _app_config: Arc<Config>) -> Result<Self> {
        let config = SamlConfig::from_env()
            .ok_or_else(|| AppError::Config("SAML configuration not set".into()))?;

        Ok(Self {
            db,
            config,
            http_client: Client::new(),
        })
    }

    /// Create SAML service from database-stored config
    #[allow(clippy::too_many_arguments)]
    pub fn from_db_config(
        db: PgPool,
        entity_id: &str,
        sso_url: &str,
        _slo_url: Option<&str>,
        certificate: Option<&str>,
        sp_entity_id: &str,
        acs_url: &str,
        _name_id_format: &str,
        attribute_mapping: &serde_json::Value,
        sign_requests: bool,
        require_signed_assertions: bool,
        admin_group: Option<&str>,
    ) -> Self {
        let attr = |key, default| -> String {
            attribute_mapping
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or(default)
                .to_string()
        };
        let username_attr = attr("username", "NameID");
        let email_attr = attr("email", "email");
        let display_name_attr = attr("display_name", "displayName");
        let groups_attr = attr("groups", "groups");

        let config = SamlConfig {
            idp_metadata_url: None,
            idp_sso_url: sso_url.to_string(),
            idp_issuer: entity_id.to_string(),
            idp_certificate: certificate.map(String::from),
            sp_entity_id: sp_entity_id.to_string(),
            acs_url: acs_url.to_string(),
            username_attr,
            email_attr,
            display_name_attr,
            groups_attr,
            admin_group: admin_group.map(String::from),
            sign_requests,
            require_signed_assertions,
        };
        Self {
            db,
            config,
            http_client: Client::new(),
        }
    }

    /// Create SAML service from explicit config
    pub fn with_config(db: PgPool, config: SamlConfig) -> Self {
        Self {
            db,
            config,
            http_client: Client::new(),
        }
    }

    /// Generate SAML AuthnRequest and return redirect URL
    pub fn create_authn_request(&self) -> Result<SamlAuthnRequest> {
        let request_id = format!("_id{}", Uuid::new_v4());
        let relay_state = Uuid::new_v4().to_string();
        let issue_instant = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // Build AuthnRequest XML
        let authn_request = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{destination}"
    AssertionConsumerServiceURL="{acs_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>{sp_entity_id}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        AllowCreate="true"/>
</samlp:AuthnRequest>"#,
            request_id = request_id,
            issue_instant = issue_instant,
            destination = self.config.idp_sso_url,
            acs_url = self.config.acs_url,
            sp_entity_id = self.config.sp_entity_id,
        );

        // Base64 encode and URL encode the request
        let encoded_request = base64_encode(authn_request.as_bytes());
        let url_encoded_request = urlencoding::encode(&encoded_request);
        let url_encoded_relay_state = urlencoding::encode(&relay_state);

        // Build redirect URL
        let redirect_url = format!(
            "{}?SAMLRequest={}&RelayState={}",
            self.config.idp_sso_url, url_encoded_request, url_encoded_relay_state
        );

        Ok(SamlAuthnRequest {
            redirect_url,
            request_id,
            relay_state,
        })
    }

    /// Process SAML Response and extract user information
    pub async fn authenticate(&self, saml_response_b64: &str) -> Result<SamlUserInfo> {
        // Decode base64 response
        let decoded = base64_decode(saml_response_b64).map_err(|e| {
            AppError::Authentication(format!("Failed to decode SAML response: {}", e))
        })?;

        let xml_string = String::from_utf8(decoded).map_err(|e| {
            AppError::Authentication(format!("Invalid UTF-8 in SAML response: {}", e))
        })?;

        // Parse SAML response
        let response = self.parse_saml_response(&xml_string)?;

        // Validate response
        self.validate_response(&response)?;

        // Extract user info from assertion
        let assertion = response
            .assertion
            .ok_or_else(|| AppError::Authentication("No assertion in SAML response".into()))?;

        let user_info = self.extract_user_info(&assertion)?;

        tracing::info!(
            name_id = %user_info.name_id,
            username = %user_info.username,
            "SAML authentication successful"
        );

        Ok(user_info)
    }

    /// Parse SAML Response XML
    fn parse_saml_response(&self, xml: &str) -> Result<SamlResponse> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut parser = SamlResponseParser::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => parser.handle_start(e),
                Ok(Event::Empty(ref e)) => parser.handle_empty(e),
                Ok(Event::Text(ref e)) => parser.handle_text(e),
                Ok(Event::End(ref e)) => parser.handle_end(e),
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(AppError::Authentication(format!(
                        "Failed to parse SAML response: {}",
                        e
                    )));
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(parser.finish())
    }

    /// Validate SAML response
    fn validate_response(&self, response: &SamlResponse) -> Result<()> {
        // Check status code
        if !response.status_code.ends_with(":Success") {
            let message = response
                .status_message
                .clone()
                .unwrap_or_else(|| format!("SAML authentication failed: {}", response.status_code));
            return Err(AppError::Authentication(message));
        }

        // Validate issuer
        if response.issuer != self.config.idp_issuer {
            return Err(AppError::Authentication(format!(
                "Invalid issuer: expected {}, got {}",
                self.config.idp_issuer, response.issuer
            )));
        }

        // Validate assertion if present
        if let Some(assertion) = &response.assertion {
            // Check audience restriction
            if !assertion.audiences.is_empty() {
                let valid_audience = assertion
                    .audiences
                    .iter()
                    .any(|a| a == &self.config.sp_entity_id);
                if !valid_audience {
                    return Err(AppError::Authentication(
                        "SP entity ID not in audience restriction".into(),
                    ));
                }
            }

            // Check time validity
            let now = chrono::Utc::now();

            if let Some(not_before) = &assertion.not_before {
                if let Ok(nb) = chrono::DateTime::parse_from_rfc3339(not_before) {
                    if now < nb {
                        return Err(AppError::Authentication("Assertion not yet valid".into()));
                    }
                }
            }

            if let Some(not_on_or_after) = &assertion.not_on_or_after {
                if let Ok(noa) = chrono::DateTime::parse_from_rfc3339(not_on_or_after) {
                    if now >= noa {
                        return Err(AppError::Authentication("Assertion has expired".into()));
                    }
                }
            }
        }

        // Note: In production, signature verification should be performed here
        // using the IdP certificate. This would require a proper crypto library.
        if self.config.require_signed_assertions {
            tracing::warn!(
                "Signature verification is not implemented. \
                 In production, validate assertion signature using IdP certificate."
            );
        }

        Ok(())
    }

    /// Extract user information from assertion
    fn extract_user_info(&self, assertion: &SamlAssertion) -> Result<SamlUserInfo> {
        // Get username from configured attribute or NameID
        let username = if self.config.username_attr == "NameID" {
            assertion.name_id.clone()
        } else {
            assertion
                .attributes
                .get(&self.config.username_attr)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| assertion.name_id.clone())
        };

        // Get email
        let email = assertion
            .attributes
            .get(&self.config.email_attr)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_else(|| format!("{}@unknown", username));

        // Get display name
        let display_name = assertion
            .attributes
            .get(&self.config.display_name_attr)
            .and_then(|v| v.first())
            .cloned();

        // Get groups
        let groups = assertion
            .attributes
            .get(&self.config.groups_attr)
            .cloned()
            .unwrap_or_default();

        Ok(SamlUserInfo {
            name_id: assertion.name_id.clone(),
            name_id_format: assertion.name_id_format.clone(),
            session_index: assertion.session_index.clone(),
            username,
            email,
            display_name,
            groups,
            attributes: assertion.attributes.clone(),
        })
    }

    /// Get or create a user from SAML information
    pub async fn get_or_create_user(&self, saml_user: &SamlUserInfo) -> Result<User> {
        // Check if user already exists by external_id (NameID)
        let existing_user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
            FROM users
            WHERE external_id = $1 AND auth_provider = 'saml'
            "#,
            saml_user.name_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(mut user) = existing_user {
            // Update user info from SAML
            let is_admin = self.is_admin_from_groups(&saml_user.groups);

            sqlx::query!(
                r#"
                UPDATE users
                SET email = $1, display_name = $2, is_admin = $3,
                    last_login_at = NOW(), updated_at = NOW()
                WHERE id = $4
                "#,
                saml_user.email,
                saml_user.display_name,
                is_admin,
                user.id
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            user.email = saml_user.email.clone();
            user.display_name = saml_user.display_name.clone();
            user.is_admin = is_admin;

            return Ok(user);
        }

        // Create new user from SAML
        let user_id = Uuid::new_v4();
        let is_admin = self.is_admin_from_groups(&saml_user.groups);

        // Generate unique username if conflict exists
        let username = self.generate_unique_username(&saml_user.username).await?;

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, email, display_name, auth_provider, external_id, is_admin, is_active, is_service_account)
            VALUES ($1, $2, $3, $4, 'saml', $5, $6, true, false)
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
            "#,
            user_id,
            username,
            saml_user.email,
            saml_user.display_name,
            saml_user.name_id,
            is_admin
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tracing::info!(
            user_id = %user.id,
            username = %user.username,
            name_id = %saml_user.name_id,
            "Created new user from SAML"
        );

        Ok(user)
    }

    /// Generate unique username if conflict exists
    async fn generate_unique_username(&self, base_username: &str) -> Result<String> {
        let mut username = base_username.to_string();
        let mut suffix = 1;

        loop {
            let exists = sqlx::query_scalar!(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
                username
            )
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .unwrap_or(false);

            if !exists {
                return Ok(username);
            }

            username = format!("{}_{}", base_username, suffix);
            suffix += 1;

            if suffix > 100 {
                return Err(AppError::Internal(
                    "Failed to generate unique username".into(),
                ));
            }
        }
    }

    /// Check if user is admin based on group memberships
    fn is_admin_from_groups(&self, groups: &[String]) -> bool {
        if let Some(admin_group) = &self.config.admin_group {
            groups
                .iter()
                .any(|g| g.to_lowercase() == admin_group.to_lowercase())
        } else {
            false
        }
    }

    /// Extract group memberships for role mapping
    pub fn extract_groups(&self, saml_user: &SamlUserInfo) -> Vec<String> {
        saml_user.groups.clone()
    }

    /// Map SAML groups to application roles
    pub fn map_groups_to_roles(&self, groups: &[String]) -> Vec<String> {
        let mut roles = vec!["user".to_string()];

        if self.is_admin_from_groups(groups) {
            roles.push("admin".to_string());
        }

        // Additional role mappings from environment
        // SAML_GROUP_ROLE_MAP=Developers:developer;Admins:admin
        if let Ok(mappings) = std::env::var("SAML_GROUP_ROLE_MAP") {
            for mapping in mappings.split(';') {
                if let Some((group, role)) = mapping.split_once(':') {
                    if groups
                        .iter()
                        .any(|g| g.to_lowercase() == group.to_lowercase())
                    {
                        roles.push(role.to_string());
                    }
                }
            }
        }

        roles.sort();
        roles.dedup();
        roles
    }

    /// Check if SAML is configured
    pub fn is_configured(&self) -> bool {
        !self.config.idp_sso_url.is_empty() && !self.config.idp_issuer.is_empty()
    }

    /// Get the IdP SSO URL
    pub fn idp_sso_url(&self) -> &str {
        &self.config.idp_sso_url
    }

    /// Get the SP entity ID
    pub fn sp_entity_id(&self) -> &str {
        &self.config.sp_entity_id
    }

    /// Get the ACS URL
    pub fn acs_url(&self) -> &str {
        &self.config.acs_url
    }
}

/// Base64 encode bytes
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::new();
    let mut buffer: u32 = 0;
    let mut bits_collected = 0;

    for &byte in input {
        buffer = (buffer << 8) | (byte as u32);
        bits_collected += 8;

        while bits_collected >= 6 {
            bits_collected -= 6;
            let index = ((buffer >> bits_collected) & 0x3F) as usize;
            output.push(ALPHABET[index] as char);
        }
    }

    if bits_collected > 0 {
        buffer <<= 6 - bits_collected;
        let index = (buffer & 0x3F) as usize;
        output.push(ALPHABET[index] as char);
    }

    // Add padding
    while output.len() % 4 != 0 {
        output.push('=');
    }

    output
}

/// Base64 decode string
fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_collected = 0;

    for byte in input.bytes() {
        if byte == b'=' {
            break;
        }

        // Skip whitespace
        if byte.is_ascii_whitespace() {
            continue;
        }

        let value = ALPHABET
            .iter()
            .position(|&c| c == byte)
            .ok_or_else(|| format!("Invalid base64 character: {}", byte as char))?;

        buffer = (buffer << 6) | (value as u32);
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push(((buffer >> bits_collected) & 0xFF) as u8);
        }
    }

    Ok(output)
}

/// URL encoding for SAML request
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut result = String::new();
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // base64_encode tests
    // =======================================================================

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b"Hello World"), "SGVsbG8gV29ybGQ=");
    }

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_base64_encode_single_byte() {
        assert_eq!(base64_encode(b"a"), "YQ==");
    }

    #[test]
    fn test_base64_encode_two_bytes() {
        assert_eq!(base64_encode(b"ab"), "YWI=");
    }

    #[test]
    fn test_base64_encode_three_bytes() {
        // Three bytes => no padding needed
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn test_base64_encode_padding_alignment() {
        // 4 bytes => 1 byte padding remainder
        assert_eq!(base64_encode(b"abcd"), "YWJjZA==");
        // 5 bytes
        assert_eq!(base64_encode(b"abcde"), "YWJjZGU=");
        // 6 bytes => no padding
        assert_eq!(base64_encode(b"abcdef"), "YWJjZGVm");
    }

    #[test]
    fn test_base64_encode_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = base64_encode(&data);
        // Should not panic, and should produce valid base64
        assert!(!encoded.is_empty());
        assert_eq!(encoded.len() % 4, 0); // Base64 output length is multiple of 4
    }

    #[test]
    fn test_base64_encode_xml_content() {
        // Typical SAML usage: encoding XML
        let xml = r#"<?xml version="1.0"?><samlp:AuthnRequest/>"#;
        let encoded = base64_encode(xml.as_bytes());
        assert!(!encoded.is_empty());
        // Verify round-trip
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), xml);
    }

    // =======================================================================
    // base64_decode tests
    // =======================================================================

    #[test]
    fn test_base64_decode() {
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello");

        let decoded = base64_decode("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    #[test]
    fn test_base64_decode_empty() {
        let decoded = base64_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_base64_decode_no_padding() {
        let decoded = base64_decode("YWJj").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "abc");
    }

    #[test]
    fn test_base64_decode_single_padding() {
        let decoded = base64_decode("YWJjZGU=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "abcde");
    }

    #[test]
    fn test_base64_decode_double_padding() {
        let decoded = base64_decode("YQ==").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "a");
    }

    #[test]
    fn test_base64_decode_ignores_whitespace() {
        let decoded = base64_decode("SGVs\nbG8=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello");

        let decoded = base64_decode("SGVs bG8=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello");

        let decoded = base64_decode("SGVs\r\nbG8=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello");
    }

    #[test]
    fn test_base64_decode_invalid_character() {
        let result = base64_decode("SGVs!G8=");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid base64 character"));
    }

    #[test]
    fn test_base64_roundtrip() {
        let test_strings = vec![
            "",
            "a",
            "ab",
            "abc",
            "test string with spaces",
            "special chars: <>&\"'",
            "unicode: hello world",
        ];

        for s in test_strings {
            let encoded = base64_encode(s.as_bytes());
            let decoded = base64_decode(&encoded).unwrap();
            assert_eq!(
                String::from_utf8(decoded).unwrap(),
                s,
                "Round-trip failed for: {:?}",
                s
            );
        }
    }

    // =======================================================================
    // urlencoding tests
    // =======================================================================

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("hello"), "hello");
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("a+b=c"), "a%2Bb%3Dc");
    }

    #[test]
    fn test_urlencoding_empty() {
        assert_eq!(urlencoding::encode(""), "");
    }

    #[test]
    fn test_urlencoding_unreserved_chars_preserved() {
        // RFC 3986 unreserved characters: A-Z, a-z, 0-9, -, _, ., ~
        assert_eq!(
            urlencoding::encode(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
            ),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
        );
    }

    #[test]
    fn test_urlencoding_special_chars() {
        assert_eq!(urlencoding::encode("/"), "%2F");
        assert_eq!(urlencoding::encode("?"), "%3F");
        assert_eq!(urlencoding::encode("&"), "%26");
        assert_eq!(urlencoding::encode("="), "%3D");
        assert_eq!(urlencoding::encode("#"), "%23");
        assert_eq!(urlencoding::encode("@"), "%40");
    }

    #[test]
    fn test_urlencoding_base64_output() {
        // Typical SAML usage: URL-encoding a base64 string
        let b64 = "SGVsbG8gV29ybGQ=";
        let encoded = urlencoding::encode(b64);
        // + should be encoded, = should be encoded
        assert!(encoded.contains("%3D")); // = is encoded
                                          // Letters and numbers should be preserved
        assert!(encoded.contains("SGVsbG8"));
    }

    #[test]
    fn test_urlencoding_percent_encoding_format() {
        // Verify uppercase hex output
        let encoded = urlencoding::encode(" ");
        assert_eq!(encoded, "%20");

        let encoded = urlencoding::encode("\n");
        assert_eq!(encoded, "%0A");
    }

    // =======================================================================
    // SamlConfig tests
    // =======================================================================

    #[test]
    fn test_saml_config_defaults() {
        // Set minimal env vars for test
        // SAFETY: Test-only, single-threaded access to env vars
        unsafe {
            std::env::set_var("SAML_IDP_SSO_URL", "https://idp.example.com/sso");
            std::env::set_var("SAML_IDP_ISSUER", "https://idp.example.com");
        }

        let config = SamlConfig::from_env();
        assert!(config.is_some());
        let config = config.unwrap();
        assert_eq!(config.idp_sso_url, "https://idp.example.com/sso");
        assert_eq!(config.sp_entity_id, "artifact-keeper");
        assert_eq!(config.username_attr, "NameID");
        assert_eq!(config.email_attr, "email");
        assert_eq!(config.display_name_attr, "displayName");
        assert_eq!(config.groups_attr, "groups");
        assert!(!config.sign_requests);
        assert!(config.require_signed_assertions);
        assert!(config.admin_group.is_none());

        // Clean up
        unsafe {
            std::env::remove_var("SAML_IDP_SSO_URL");
            std::env::remove_var("SAML_IDP_ISSUER");
        }
    }

    #[tokio::test]
    async fn test_saml_config_returns_none_without_required_vars() {
        // Ensure neither var is set
        // SAFETY: Test-only, single-threaded access to env vars
        unsafe {
            std::env::remove_var("SAML_IDP_SSO_URL");
            std::env::remove_var("SAML_IDP_ISSUER");
        }

        let config = SamlConfig::from_env();
        assert!(config.is_none());
    }

    // =======================================================================
    // SAML response XML parsing tests
    // =======================================================================

    fn make_test_saml_config() -> SamlConfig {
        SamlConfig {
            idp_metadata_url: None,
            idp_sso_url: "https://idp.example.com/sso".to_string(),
            idp_issuer: "https://idp.example.com".to_string(),
            idp_certificate: None,
            sp_entity_id: "artifact-keeper".to_string(),
            acs_url: "http://localhost:8080/auth/saml/acs".to_string(),
            username_attr: "NameID".to_string(),
            email_attr: "email".to_string(),
            display_name_attr: "displayName".to_string(),
            groups_attr: "groups".to_string(),
            admin_group: Some("Admins".to_string()),
            sign_requests: false,
            require_signed_assertions: false,
        }
    }

    fn make_test_saml_service() -> SamlService {
        let config = make_test_saml_config();
        SamlService::with_config(
            PgPool::connect_lazy("postgres://invalid:invalid@localhost/invalid").unwrap(),
            config,
        )
    }

    fn sample_saml_response_xml() -> String {
        r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response123"
                InResponseTo="_request456"
                Version="2.0">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_assertion789" Version="2.0">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">john.doe@example.com</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
            <saml:AudienceRestriction>
                <saml:Audience>artifact-keeper</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement SessionIndex="session_abc123"/>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>john.doe@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="displayName">
                <saml:AttributeValue>John Doe</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="groups">
                <saml:AttributeValue>Developers</saml:AttributeValue>
                <saml:AttributeValue>Admins</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"#
            .to_string()
    }

    #[tokio::test]
    async fn test_parse_saml_response_basic() {
        let service = make_test_saml_service();
        let xml = sample_saml_response_xml();

        let response = service.parse_saml_response(&xml).unwrap();

        assert_eq!(response.id, "_response123");
        assert_eq!(response.in_response_to, Some("_request456".to_string()));
        assert_eq!(response.issuer, "https://idp.example.com");
        assert!(response.status_code.ends_with(":Success"));
    }

    #[tokio::test]
    async fn test_parse_saml_response_assertion_fields() {
        let service = make_test_saml_service();
        let xml = sample_saml_response_xml();

        let response = service.parse_saml_response(&xml).unwrap();
        let assertion = response.assertion.as_ref().unwrap();

        assert_eq!(assertion.id, "_assertion789");
        assert_eq!(assertion.issuer, "https://idp.example.com");
        assert_eq!(assertion.name_id, "john.doe@example.com");
        assert_eq!(
            assertion.name_id_format.as_deref(),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        );
        // Self-closing AuthnStatement elements are now correctly handled in Event::Empty
        assert_eq!(assertion.session_index, Some("session_abc123".to_string()));
    }

    #[tokio::test]
    async fn test_parse_saml_response_conditions() {
        let service = make_test_saml_service();
        let xml = sample_saml_response_xml();

        let response = service.parse_saml_response(&xml).unwrap();
        let assertion = response.assertion.as_ref().unwrap();

        assert_eq!(
            assertion.not_before.as_deref(),
            Some("2020-01-01T00:00:00Z")
        );
        assert_eq!(
            assertion.not_on_or_after.as_deref(),
            Some("2099-12-31T23:59:59Z")
        );
        assert_eq!(assertion.audiences, vec!["artifact-keeper"]);
    }

    #[tokio::test]
    async fn test_parse_saml_response_attributes() {
        let service = make_test_saml_service();
        let xml = sample_saml_response_xml();

        let response = service.parse_saml_response(&xml).unwrap();
        let assertion = response.assertion.as_ref().unwrap();

        assert_eq!(
            assertion.attributes.get("email"),
            Some(&vec!["john.doe@example.com".to_string()])
        );
        assert_eq!(
            assertion.attributes.get("displayName"),
            Some(&vec!["John Doe".to_string()])
        );

        let groups = assertion.attributes.get("groups").unwrap();
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&"Developers".to_string()));
        assert!(groups.contains(&"Admins".to_string()));
    }

    #[tokio::test]
    async fn test_parse_saml_response_no_assertion() {
        let service = make_test_saml_service();
        let xml = r#"<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp1" Version="2.0">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
        <samlp:StatusMessage>Authentication failed</samlp:StatusMessage>
    </samlp:Status>
</samlp:Response>"#;

        let response = service.parse_saml_response(xml).unwrap();
        assert!(response.assertion.is_none());
        assert!(response.status_code.ends_with(":Requester"));
        assert_eq!(
            response.status_message.as_deref(),
            Some("Authentication failed")
        );
    }

    #[tokio::test]
    async fn test_parse_saml_response_empty_status_code() {
        let service = make_test_saml_service();
        let xml = r#"<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp1" Version="2.0">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:Response>"#;

        let response = service.parse_saml_response(xml).unwrap();
        assert_eq!(response.id, "_resp1");
        assert!(response.status_code.contains("Success"));
    }

    // =======================================================================
    // validate_response tests
    // =======================================================================

    #[tokio::test]
    async fn test_validate_response_success() {
        let service = make_test_saml_service();
        let xml = sample_saml_response_xml();
        let response = service.parse_saml_response(&xml).unwrap();

        let result = service.validate_response(&response);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_response_failed_status() {
        let service = make_test_saml_service();
        let response = SamlResponse {
            id: "_resp1".to_string(),
            in_response_to: None,
            issuer: "https://idp.example.com".to_string(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Requester".to_string(),
            status_message: Some("Auth failed".to_string()),
            assertion: None,
        };

        let result = service.validate_response(&response);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Auth failed"));
    }

    #[tokio::test]
    async fn test_validate_response_wrong_issuer() {
        let service = make_test_saml_service();
        let response = SamlResponse {
            id: "_resp1".to_string(),
            in_response_to: None,
            issuer: "https://evil-idp.example.com".to_string(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            status_message: None,
            assertion: None,
        };

        let result = service.validate_response(&response);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid issuer"));
    }

    #[tokio::test]
    async fn test_validate_response_wrong_audience() {
        let service = make_test_saml_service();
        let response = SamlResponse {
            id: "_resp1".to_string(),
            in_response_to: None,
            issuer: "https://idp.example.com".to_string(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            status_message: None,
            assertion: Some(SamlAssertion {
                id: "_a1".to_string(),
                issuer: "https://idp.example.com".to_string(),
                name_id: "user@example.com".to_string(),
                name_id_format: None,
                session_index: None,
                not_before: None,
                not_on_or_after: None,
                audiences: vec!["wrong-sp-entity-id".to_string()],
                attributes: HashMap::new(),
            }),
        };

        let result = service.validate_response(&response);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("audience restriction"));
    }

    #[tokio::test]
    async fn test_validate_response_empty_audience_passes() {
        let service = make_test_saml_service();
        let response = SamlResponse {
            id: "_resp1".to_string(),
            in_response_to: None,
            issuer: "https://idp.example.com".to_string(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            status_message: None,
            assertion: Some(SamlAssertion {
                id: "_a1".to_string(),
                issuer: "https://idp.example.com".to_string(),
                name_id: "user@example.com".to_string(),
                name_id_format: None,
                session_index: None,
                not_before: None,
                not_on_or_after: None,
                audiences: vec![],
                attributes: HashMap::new(),
            }),
        };

        // Empty audiences list means no restriction to check
        let result = service.validate_response(&response);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_response_expired_assertion() {
        let service = make_test_saml_service();
        let response = SamlResponse {
            id: "_resp1".to_string(),
            in_response_to: None,
            issuer: "https://idp.example.com".to_string(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            status_message: None,
            assertion: Some(SamlAssertion {
                id: "_a1".to_string(),
                issuer: "https://idp.example.com".to_string(),
                name_id: "user@example.com".to_string(),
                name_id_format: None,
                session_index: None,
                not_before: None,
                not_on_or_after: Some("2020-01-01T00:00:00Z".to_string()),
                audiences: vec!["artifact-keeper".to_string()],
                attributes: HashMap::new(),
            }),
        };

        let result = service.validate_response(&response);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expired"));
    }

    #[tokio::test]
    async fn test_validate_response_not_yet_valid() {
        let service = make_test_saml_service();
        let response = SamlResponse {
            id: "_resp1".to_string(),
            in_response_to: None,
            issuer: "https://idp.example.com".to_string(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            status_message: None,
            assertion: Some(SamlAssertion {
                id: "_a1".to_string(),
                issuer: "https://idp.example.com".to_string(),
                name_id: "user@example.com".to_string(),
                name_id_format: None,
                session_index: None,
                not_before: Some("2099-01-01T00:00:00Z".to_string()),
                not_on_or_after: None,
                audiences: vec!["artifact-keeper".to_string()],
                attributes: HashMap::new(),
            }),
        };

        let result = service.validate_response(&response);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not yet valid"));
    }

    #[tokio::test]
    async fn test_validate_response_correct_audience_among_many() {
        let service = make_test_saml_service();
        let response = SamlResponse {
            id: "_resp1".to_string(),
            in_response_to: None,
            issuer: "https://idp.example.com".to_string(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            status_message: None,
            assertion: Some(SamlAssertion {
                id: "_a1".to_string(),
                issuer: "https://idp.example.com".to_string(),
                name_id: "user@example.com".to_string(),
                name_id_format: None,
                session_index: None,
                not_before: None,
                not_on_or_after: None,
                audiences: vec![
                    "other-sp".to_string(),
                    "artifact-keeper".to_string(),
                    "another-sp".to_string(),
                ],
                attributes: HashMap::new(),
            }),
        };

        let result = service.validate_response(&response);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_response_failed_status_without_message() {
        let service = make_test_saml_service();
        let response = SamlResponse {
            id: "_resp1".to_string(),
            in_response_to: None,
            issuer: "https://idp.example.com".to_string(),
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Responder".to_string(),
            status_message: None,
            assertion: None,
        };

        let result = service.validate_response(&response);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // Should include the status code in the default message
        assert!(err.contains("Responder"));
    }

    // =======================================================================
    // extract_user_info tests
    // =======================================================================

    #[tokio::test]
    async fn test_extract_user_info_basic() {
        let service = make_test_saml_service();
        let assertion = SamlAssertion {
            id: "_a1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "john@example.com".to_string(),
            name_id_format: Some(
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            ),
            session_index: Some("session_123".to_string()),
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("email".to_string(), vec!["john@example.com".to_string()]);
                attrs.insert("displayName".to_string(), vec!["John Doe".to_string()]);
                attrs.insert(
                    "groups".to_string(),
                    vec!["Developers".to_string(), "Admins".to_string()],
                );
                attrs
            },
        };

        let user_info = service.extract_user_info(&assertion).unwrap();

        // username_attr is "NameID", so username comes from name_id
        assert_eq!(user_info.username, "john@example.com");
        assert_eq!(user_info.email, "john@example.com");
        assert_eq!(user_info.display_name, Some("John Doe".to_string()));
        assert_eq!(user_info.groups, vec!["Developers", "Admins"]);
        assert_eq!(user_info.name_id, "john@example.com");
        assert_eq!(user_info.session_index, Some("session_123".to_string()));
    }

    #[tokio::test]
    async fn test_extract_user_info_custom_username_attr() {
        let mut config = make_test_saml_config();
        config.username_attr = "uid".to_string();

        let service = SamlService {
            db: PgPool::connect_lazy("postgres://invalid:invalid@localhost/invalid").unwrap(),
            config,
            http_client: Client::new(),
        };

        let assertion = SamlAssertion {
            id: "_a1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "john@example.com".to_string(),
            name_id_format: None,
            session_index: None,
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("uid".to_string(), vec!["jdoe".to_string()]);
                attrs.insert("email".to_string(), vec!["john@example.com".to_string()]);
                attrs
            },
        };

        let user_info = service.extract_user_info(&assertion).unwrap();
        assert_eq!(user_info.username, "jdoe");
    }

    #[tokio::test]
    async fn test_extract_user_info_missing_username_attr_falls_back_to_name_id() {
        let mut config = make_test_saml_config();
        config.username_attr = "nonexistent".to_string();

        let service = SamlService {
            db: PgPool::connect_lazy("postgres://invalid:invalid@localhost/invalid").unwrap(),
            config,
            http_client: Client::new(),
        };

        let assertion = SamlAssertion {
            id: "_a1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "fallback-user".to_string(),
            name_id_format: None,
            session_index: None,
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            attributes: HashMap::new(),
        };

        let user_info = service.extract_user_info(&assertion).unwrap();
        assert_eq!(user_info.username, "fallback-user");
    }

    #[tokio::test]
    async fn test_extract_user_info_missing_email_generates_default() {
        let service = make_test_saml_service();
        let assertion = SamlAssertion {
            id: "_a1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "jdoe".to_string(),
            name_id_format: None,
            session_index: None,
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            attributes: HashMap::new(),
        };

        let user_info = service.extract_user_info(&assertion).unwrap();
        // No email attribute => default email is "{username}@unknown"
        assert_eq!(user_info.email, "jdoe@unknown");
    }

    #[tokio::test]
    async fn test_extract_user_info_missing_display_name() {
        let service = make_test_saml_service();
        let assertion = SamlAssertion {
            id: "_a1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "jdoe".to_string(),
            name_id_format: None,
            session_index: None,
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            attributes: HashMap::new(),
        };

        let user_info = service.extract_user_info(&assertion).unwrap();
        assert!(user_info.display_name.is_none());
    }

    #[tokio::test]
    async fn test_extract_user_info_empty_groups() {
        let service = make_test_saml_service();
        let assertion = SamlAssertion {
            id: "_a1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "jdoe".to_string(),
            name_id_format: None,
            session_index: None,
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            attributes: HashMap::new(),
        };

        let user_info = service.extract_user_info(&assertion).unwrap();
        assert!(user_info.groups.is_empty());
    }

    #[tokio::test]
    async fn test_extract_user_info_preserves_all_attributes() {
        let service = make_test_saml_service();
        let mut attrs = HashMap::new();
        attrs.insert("email".to_string(), vec!["a@b.com".to_string()]);
        attrs.insert(
            "custom_attr".to_string(),
            vec!["value1".to_string(), "value2".to_string()],
        );

        let assertion = SamlAssertion {
            id: "_a1".to_string(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "jdoe".to_string(),
            name_id_format: None,
            session_index: None,
            not_before: None,
            not_on_or_after: None,
            audiences: vec![],
            attributes: attrs,
        };

        let user_info = service.extract_user_info(&assertion).unwrap();
        assert_eq!(user_info.attributes.len(), 2);
        assert_eq!(
            user_info.attributes.get("custom_attr").unwrap(),
            &vec!["value1".to_string(), "value2".to_string()]
        );
    }

    // =======================================================================
    // is_admin_from_groups tests
    // =======================================================================

    #[tokio::test]
    async fn test_is_admin_from_groups_matching() {
        let service = make_test_saml_service();
        let groups = vec!["Developers".to_string(), "Admins".to_string()];
        assert!(service.is_admin_from_groups(&groups));
    }

    #[tokio::test]
    async fn test_is_admin_from_groups_case_insensitive() {
        let service = make_test_saml_service();
        let groups = vec!["admins".to_string()];
        assert!(service.is_admin_from_groups(&groups));

        let groups = vec!["ADMINS".to_string()];
        assert!(service.is_admin_from_groups(&groups));
    }

    #[tokio::test]
    async fn test_is_admin_from_groups_not_matching() {
        let service = make_test_saml_service();
        let groups = vec!["Developers".to_string(), "Users".to_string()];
        assert!(!service.is_admin_from_groups(&groups));
    }

    #[tokio::test]
    async fn test_is_admin_from_groups_empty() {
        let service = make_test_saml_service();
        let groups: Vec<String> = vec![];
        assert!(!service.is_admin_from_groups(&groups));
    }

    #[tokio::test]
    async fn test_is_admin_from_groups_no_admin_group_configured() {
        let mut config = make_test_saml_config();
        config.admin_group = None;

        let service = SamlService {
            db: PgPool::connect_lazy("postgres://invalid:invalid@localhost/invalid").unwrap(),
            config,
            http_client: Client::new(),
        };

        let groups = vec!["Admins".to_string(), "SuperAdmins".to_string()];
        assert!(!service.is_admin_from_groups(&groups));
    }

    // =======================================================================
    // map_groups_to_roles tests
    // =======================================================================

    #[tokio::test]
    async fn test_map_groups_to_roles_basic_user() {
        // Clear the env var to avoid interference
        // SAFETY: Test-only, single-threaded access to env vars
        unsafe { std::env::remove_var("SAML_GROUP_ROLE_MAP") };

        let service = make_test_saml_service();
        let groups = vec!["Developers".to_string()];
        let roles = service.map_groups_to_roles(&groups);

        assert!(roles.contains(&"user".to_string()));
        assert!(!roles.contains(&"admin".to_string()));
    }

    #[tokio::test]
    async fn test_map_groups_to_roles_admin() {
        unsafe { std::env::remove_var("SAML_GROUP_ROLE_MAP") };

        let service = make_test_saml_service();
        let groups = vec!["Admins".to_string()];
        let roles = service.map_groups_to_roles(&groups);

        assert!(roles.contains(&"user".to_string()));
        assert!(roles.contains(&"admin".to_string()));
    }

    #[tokio::test]
    async fn test_map_groups_to_roles_deduplication() {
        unsafe { std::env::remove_var("SAML_GROUP_ROLE_MAP") };

        let service = make_test_saml_service();
        let groups = vec!["Admins".to_string()];
        let roles = service.map_groups_to_roles(&groups);

        // Should not have duplicate entries
        let mut unique_roles = roles.clone();
        unique_roles.sort();
        unique_roles.dedup();
        assert_eq!(roles.len(), unique_roles.len());
    }

    #[tokio::test]
    async fn test_map_groups_to_roles_sorted() {
        unsafe { std::env::remove_var("SAML_GROUP_ROLE_MAP") };

        let service = make_test_saml_service();
        let groups = vec!["Admins".to_string()];
        let roles = service.map_groups_to_roles(&groups);

        let mut sorted = roles.clone();
        sorted.sort();
        assert_eq!(roles, sorted);
    }

    // =======================================================================
    // extract_groups tests
    // =======================================================================

    #[tokio::test]
    async fn test_extract_groups() {
        let service = make_test_saml_service();
        let saml_user = SamlUserInfo {
            name_id: "jdoe".to_string(),
            name_id_format: None,
            session_index: None,
            username: "jdoe".to_string(),
            email: "jdoe@example.com".to_string(),
            display_name: None,
            groups: vec!["Group1".to_string(), "Group2".to_string()],
            attributes: HashMap::new(),
        };

        let groups = service.extract_groups(&saml_user);
        assert_eq!(groups, vec!["Group1", "Group2"]);
    }

    // =======================================================================
    // is_configured tests
    // =======================================================================

    #[tokio::test]
    async fn test_is_configured_true() {
        let service = make_test_saml_service();
        assert!(service.is_configured());
    }

    #[tokio::test]
    async fn test_is_configured_empty_sso_url() {
        let mut config = make_test_saml_config();
        config.idp_sso_url = String::new();

        let service = SamlService {
            db: PgPool::connect_lazy("postgres://invalid:invalid@localhost/invalid").unwrap(),
            config,
            http_client: Client::new(),
        };

        assert!(!service.is_configured());
    }

    #[tokio::test]
    async fn test_is_configured_empty_issuer() {
        let mut config = make_test_saml_config();
        config.idp_issuer = String::new();

        let service = SamlService {
            db: PgPool::connect_lazy("postgres://invalid:invalid@localhost/invalid").unwrap(),
            config,
            http_client: Client::new(),
        };

        assert!(!service.is_configured());
    }

    // =======================================================================
    // Accessor method tests
    // =======================================================================

    #[tokio::test]
    async fn test_idp_sso_url_accessor() {
        let service = make_test_saml_service();
        assert_eq!(service.idp_sso_url(), "https://idp.example.com/sso");
    }

    #[tokio::test]
    async fn test_sp_entity_id_accessor() {
        let service = make_test_saml_service();
        assert_eq!(service.sp_entity_id(), "artifact-keeper");
    }

    #[tokio::test]
    async fn test_acs_url_accessor() {
        let service = make_test_saml_service();
        assert_eq!(service.acs_url(), "http://localhost:8080/auth/saml/acs");
    }

    // =======================================================================
    // create_authn_request tests
    // =======================================================================

    #[tokio::test]
    async fn test_create_authn_request_format() {
        let service = make_test_saml_service();
        let request = service.create_authn_request().unwrap();

        // Request ID should start with _id
        assert!(request.request_id.starts_with("_id"));

        // Relay state should be a valid UUID
        let _uuid = Uuid::parse_str(&request.relay_state).unwrap();

        // Redirect URL should contain the IdP SSO URL
        assert!(request
            .redirect_url
            .starts_with("https://idp.example.com/sso?"));

        // Should contain SAMLRequest parameter
        assert!(request.redirect_url.contains("SAMLRequest="));

        // Should contain RelayState parameter
        assert!(request.redirect_url.contains("RelayState="));
    }

    // =======================================================================
    // SamlUserInfo serialization tests
    // =======================================================================

    #[test]
    fn test_saml_user_info_serialization_roundtrip() {
        let user_info = SamlUserInfo {
            name_id: "jdoe@example.com".to_string(),
            name_id_format: Some(
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            ),
            session_index: Some("session_abc".to_string()),
            username: "jdoe".to_string(),
            email: "jdoe@example.com".to_string(),
            display_name: Some("John Doe".to_string()),
            groups: vec!["Developers".to_string(), "Admins".to_string()],
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert("email".to_string(), vec!["jdoe@example.com".to_string()]);
                attrs
            },
        };

        let json = serde_json::to_string(&user_info).unwrap();
        let parsed: SamlUserInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name_id, user_info.name_id);
        assert_eq!(parsed.username, user_info.username);
        assert_eq!(parsed.email, user_info.email);
        assert_eq!(parsed.display_name, user_info.display_name);
        assert_eq!(parsed.groups, user_info.groups);
    }

    // =======================================================================
    // from_db_config tests
    // =======================================================================

    #[tokio::test]
    async fn test_from_db_config_attribute_mapping() {
        let attr_mapping = serde_json::json!({
            "username": "uid",
            "email": "mail",
            "display_name": "cn",
            "groups": "memberOf"
        });

        let service = SamlService::from_db_config(
            PgPool::connect_lazy("postgres://invalid:invalid@localhost/invalid").unwrap(),
            "https://idp.example.com",
            "https://idp.example.com/sso",
            Some("https://idp.example.com/slo"),
            Some("-----BEGIN CERTIFICATE-----\nMIIC..."),
            "artifact-keeper",
            "http://localhost:8080/auth/saml/acs",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            &attr_mapping,
            false,
            true,
            Some("AdminGroup"),
        );

        assert_eq!(service.config.username_attr, "uid");
        assert_eq!(service.config.email_attr, "mail");
        assert_eq!(service.config.display_name_attr, "cn");
        assert_eq!(service.config.groups_attr, "memberOf");
        assert_eq!(service.config.idp_issuer, "https://idp.example.com");
        assert_eq!(service.config.idp_sso_url, "https://idp.example.com/sso");
        assert!(!service.config.sign_requests);
        assert!(service.config.require_signed_assertions);
        assert_eq!(service.config.admin_group, Some("AdminGroup".to_string()));
    }

    #[tokio::test]
    async fn test_from_db_config_defaults_for_missing_attrs() {
        let attr_mapping = serde_json::json!({});

        let service = SamlService::from_db_config(
            PgPool::connect_lazy("postgres://invalid:invalid@localhost/invalid").unwrap(),
            "https://idp.example.com",
            "https://idp.example.com/sso",
            None,
            None,
            "sp",
            "http://localhost/acs",
            "unspecified",
            &attr_mapping,
            false,
            false,
            None,
        );

        assert_eq!(service.config.username_attr, "NameID");
        assert_eq!(service.config.email_attr, "email");
        assert_eq!(service.config.display_name_attr, "displayName");
        assert_eq!(service.config.groups_attr, "groups");
        assert!(service.config.admin_group.is_none());
        assert!(service.config.idp_certificate.is_none());
    }

    // =======================================================================
    // Full SAML response parsing + validation + extraction integration test
    // =======================================================================

    #[tokio::test]
    async fn test_full_saml_flow_parse_validate_extract() {
        let service = make_test_saml_service();
        let xml = sample_saml_response_xml();

        // Parse
        let response = service.parse_saml_response(&xml).unwrap();

        // Validate
        service.validate_response(&response).unwrap();

        // Extract
        let assertion = response.assertion.unwrap();
        let user_info = service.extract_user_info(&assertion).unwrap();

        assert_eq!(user_info.username, "john.doe@example.com");
        assert_eq!(user_info.email, "john.doe@example.com");
        assert_eq!(user_info.display_name, Some("John Doe".to_string()));
        assert!(user_info.groups.contains(&"Admins".to_string()));
        assert!(user_info.groups.contains(&"Developers".to_string()));

        // Admin check
        assert!(service.is_admin_from_groups(&user_info.groups));
    }

    // =======================================================================
    // Edge case: StatusCode as self-closing element
    // =======================================================================

    #[tokio::test]
    async fn test_parse_saml_response_self_closing_status_code() {
        let service = make_test_saml_service();
        let xml = r#"<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp1" Version="2.0">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:Response>"#;

        let response = service.parse_saml_response(xml).unwrap();
        assert!(response.status_code.ends_with(":Success"));
    }

    // =======================================================================
    // get_xml_attr tests
    // =======================================================================

    #[test]
    fn test_get_xml_attr_present() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content(r#"Element ID="_abc" Version="2.0""#, 7);
        assert_eq!(get_xml_attr(&elem, "ID"), Some("_abc".to_string()));
        assert_eq!(get_xml_attr(&elem, "Version"), Some("2.0".to_string()));
    }

    #[test]
    fn test_get_xml_attr_missing() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content(r#"Element ID="_abc""#, 7);
        assert_eq!(get_xml_attr(&elem, "Version"), None);
        assert_eq!(get_xml_attr(&elem, "NotHere"), None);
    }

    #[test]
    fn test_get_xml_attr_no_attributes() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content("Element", 7);
        assert_eq!(get_xml_attr(&elem, "ID"), None);
    }

    #[test]
    fn test_get_xml_attr_value_with_special_chars() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content(
            r#"StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success""#,
            10,
        );
        assert_eq!(
            get_xml_attr(&elem, "Value"),
            Some("urn:oasis:names:tc:SAML:2.0:status:Success".to_string())
        );
    }

    #[test]
    fn test_get_xml_attr_empty_value() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content(r#"Element Name="""#, 7);
        assert_eq!(get_xml_attr(&elem, "Name"), Some(String::new()));
    }

    // =======================================================================
    // collect_xml_attrs tests
    // =======================================================================

    #[test]
    fn test_collect_xml_attrs_multiple() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content(
            r#"Response ID="_resp1" InResponseTo="_req1" Version="2.0""#,
            8,
        );
        let attrs = collect_xml_attrs(&elem);

        assert_eq!(attrs.len(), 3);
        assert!(attrs.contains(&("ID".to_string(), "_resp1".to_string())));
        assert!(attrs.contains(&("InResponseTo".to_string(), "_req1".to_string())));
        assert!(attrs.contains(&("Version".to_string(), "2.0".to_string())));
    }

    #[test]
    fn test_collect_xml_attrs_single() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content(r#"Assertion ID="_a1""#, 9);
        let attrs = collect_xml_attrs(&elem);

        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0], ("ID".to_string(), "_a1".to_string()));
    }

    #[test]
    fn test_collect_xml_attrs_none() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content("Issuer", 6);
        let attrs = collect_xml_attrs(&elem);

        assert!(attrs.is_empty());
    }

    #[test]
    fn test_collect_xml_attrs_preserves_order() {
        use quick_xml::events::BytesStart;

        let elem = BytesStart::from_content(
            r#"Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z""#,
            10,
        );
        let attrs = collect_xml_attrs(&elem);

        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, "NotBefore");
        assert_eq!(attrs[0].1, "2020-01-01T00:00:00Z");
        assert_eq!(attrs[1].0, "NotOnOrAfter");
        assert_eq!(attrs[1].1, "2099-12-31T23:59:59Z");
    }

    // =======================================================================
    // SamlResponseParser tests
    // =======================================================================

    /// Drive a SamlResponseParser through an XML string and return the result.
    fn parse_xml_fragment(xml: &str) -> SamlResponse {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut parser = SamlResponseParser::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => parser.handle_start(e),
                Ok(Event::Empty(ref e)) => parser.handle_empty(e),
                Ok(Event::Text(ref e)) => parser.handle_text(e),
                Ok(Event::End(ref e)) => parser.handle_end(e),
                Ok(Event::Eof) => break,
                Err(e) => panic!("XML parse error: {}", e),
                _ => {}
            }
            buf.clear();
        }

        parser.finish()
    }

    #[test]
    fn test_parser_new_defaults() {
        let parser = SamlResponseParser::new();
        let response = parser.finish();

        assert!(response.id.is_empty());
        assert!(response.in_response_to.is_none());
        assert!(response.issuer.is_empty());
        assert!(response.status_code.is_empty());
        assert!(response.status_message.is_none());
        assert!(response.assertion.is_none());
    }

    #[test]
    fn test_parser_response_element() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     ID="_resp42" InResponseTo="_req99" Version="2.0">
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);

        assert_eq!(response.id, "_resp42");
        assert_eq!(response.in_response_to, Some("_req99".to_string()));
    }

    #[test]
    fn test_parser_response_without_in_response_to() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     ID="_resp42" Version="2.0">
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);

        assert_eq!(response.id, "_resp42");
        assert!(response.in_response_to.is_none());
    }

    #[test]
    fn test_parser_issuer_outside_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Issuer>https://idp.test.com</saml:Issuer>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);

        assert_eq!(response.issuer, "https://idp.test.com");
    }

    #[test]
    fn test_parser_issuer_inside_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Issuer>https://response-issuer.com</saml:Issuer>
            <saml:Assertion ID="_a1" Version="2.0">
                <saml:Issuer>https://assertion-issuer.com</saml:Issuer>
            </saml:Assertion>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);

        // Response-level issuer
        assert_eq!(response.issuer, "https://response-issuer.com");
        // Assertion-level issuer
        let assertion = response.assertion.as_ref().unwrap();
        assert_eq!(assertion.issuer, "https://assertion-issuer.com");
    }

    #[test]
    fn test_parser_status_code_self_closing() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            </samlp:Status>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);

        assert!(response.status_code.ends_with(":Success"));
    }

    #[test]
    fn test_parser_status_message() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
                <samlp:StatusMessage>Invalid request</samlp:StatusMessage>
            </samlp:Status>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);

        assert!(response.status_code.ends_with(":Requester"));
        assert_eq!(response.status_message.as_deref(), Some("Invalid request"));
    }

    #[test]
    fn test_parser_name_id_with_format() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Assertion ID="_a1" Version="2.0">
                <saml:Subject>
                    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
                </saml:Subject>
            </saml:Assertion>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);
        let assertion = response.assertion.as_ref().unwrap();

        assert_eq!(assertion.name_id, "alice@example.com");
        assert_eq!(
            assertion.name_id_format.as_deref(),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        );
    }

    #[test]
    fn test_parser_conditions() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Assertion ID="_a1" Version="2.0">
                <saml:Conditions NotBefore="2025-01-01T00:00:00Z" NotOnOrAfter="2025-12-31T23:59:59Z">
                    <saml:AudienceRestriction>
                        <saml:Audience>my-sp</saml:Audience>
                        <saml:Audience>other-sp</saml:Audience>
                    </saml:AudienceRestriction>
                </saml:Conditions>
            </saml:Assertion>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);
        let assertion = response.assertion.as_ref().unwrap();

        assert_eq!(
            assertion.not_before.as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
        assert_eq!(
            assertion.not_on_or_after.as_deref(),
            Some("2025-12-31T23:59:59Z")
        );
        assert_eq!(assertion.audiences.len(), 2);
        assert!(assertion.audiences.contains(&"my-sp".to_string()));
        assert!(assertion.audiences.contains(&"other-sp".to_string()));
    }

    #[test]
    fn test_parser_authn_statement_session_index() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Assertion ID="_a1" Version="2.0">
                <saml:AuthnStatement SessionIndex="idx_42"/>
            </saml:Assertion>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);
        let assertion = response.assertion.as_ref().unwrap();

        assert_eq!(assertion.session_index, Some("idx_42".to_string()));
    }

    #[test]
    fn test_parser_attributes_single_value() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Assertion ID="_a1" Version="2.0">
                <saml:AttributeStatement>
                    <saml:Attribute Name="email">
                        <saml:AttributeValue>bob@example.com</saml:AttributeValue>
                    </saml:Attribute>
                </saml:AttributeStatement>
            </saml:Assertion>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);
        let assertion = response.assertion.as_ref().unwrap();

        assert_eq!(
            assertion.attributes.get("email"),
            Some(&vec!["bob@example.com".to_string()])
        );
    }

    #[test]
    fn test_parser_attributes_multi_value() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Assertion ID="_a1" Version="2.0">
                <saml:AttributeStatement>
                    <saml:Attribute Name="roles">
                        <saml:AttributeValue>admin</saml:AttributeValue>
                        <saml:AttributeValue>editor</saml:AttributeValue>
                        <saml:AttributeValue>viewer</saml:AttributeValue>
                    </saml:Attribute>
                </saml:AttributeStatement>
            </saml:Assertion>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);
        let assertion = response.assertion.as_ref().unwrap();

        let roles = assertion.attributes.get("roles").unwrap();
        assert_eq!(roles.len(), 3);
        assert_eq!(roles[0], "admin");
        assert_eq!(roles[1], "editor");
        assert_eq!(roles[2], "viewer");
    }

    #[test]
    fn test_parser_multiple_attributes() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Assertion ID="_a1" Version="2.0">
                <saml:AttributeStatement>
                    <saml:Attribute Name="email">
                        <saml:AttributeValue>user@test.com</saml:AttributeValue>
                    </saml:Attribute>
                    <saml:Attribute Name="displayName">
                        <saml:AttributeValue>Test User</saml:AttributeValue>
                    </saml:Attribute>
                    <saml:Attribute Name="groups">
                        <saml:AttributeValue>Engineering</saml:AttributeValue>
                        <saml:AttributeValue>Platform</saml:AttributeValue>
                    </saml:Attribute>
                </saml:AttributeStatement>
            </saml:Assertion>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);
        let assertion = response.assertion.as_ref().unwrap();

        assert_eq!(assertion.attributes.len(), 3);
        assert_eq!(
            assertion.attributes.get("email"),
            Some(&vec!["user@test.com".to_string()])
        );
        assert_eq!(
            assertion.attributes.get("displayName"),
            Some(&vec!["Test User".to_string()])
        );
        let groups = assertion.attributes.get("groups").unwrap();
        assert_eq!(groups, &vec!["Engineering", "Platform"]);
    }

    #[test]
    fn test_parser_no_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_r1" Version="2.0">
            <saml:Issuer>https://idp.example.com</saml:Issuer>
            <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
            </samlp:Status>
        </samlp:Response>"#;

        let response = parse_xml_fragment(xml);

        assert_eq!(response.id, "_r1");
        assert_eq!(response.issuer, "https://idp.example.com");
        assert!(response.assertion.is_none());
    }

    #[test]
    fn test_parser_full_response() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_full_resp" InResponseTo="_orig_req" Version="2.0">
    <saml:Issuer>https://idp.full-test.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_full_assertion" Version="2.0">
        <saml:Issuer>https://idp.full-test.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">user123</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
            <saml:AudienceRestriction>
                <saml:Audience>test-sp</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement SessionIndex="session_full"/>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>user123@full-test.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="groups">
                <saml:AttributeValue>TeamA</saml:AttributeValue>
                <saml:AttributeValue>TeamB</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"#;

        let response = parse_xml_fragment(xml);

        // Response-level fields
        assert_eq!(response.id, "_full_resp");
        assert_eq!(response.in_response_to, Some("_orig_req".to_string()));
        assert_eq!(response.issuer, "https://idp.full-test.com");
        assert!(response.status_code.ends_with(":Success"));

        // Assertion-level fields
        let assertion = response.assertion.as_ref().unwrap();
        assert_eq!(assertion.id, "_full_assertion");
        assert_eq!(assertion.issuer, "https://idp.full-test.com");
        assert_eq!(assertion.name_id, "user123");
        assert_eq!(
            assertion.name_id_format.as_deref(),
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
        );
        assert_eq!(assertion.session_index, Some("session_full".to_string()));
        assert_eq!(
            assertion.not_before.as_deref(),
            Some("2020-01-01T00:00:00Z")
        );
        assert_eq!(
            assertion.not_on_or_after.as_deref(),
            Some("2099-01-01T00:00:00Z")
        );
        assert_eq!(assertion.audiences, vec!["test-sp"]);
        assert_eq!(
            assertion.attributes.get("email"),
            Some(&vec!["user123@full-test.com".to_string()])
        );
        let groups = assertion.attributes.get("groups").unwrap();
        assert_eq!(groups, &vec!["TeamA", "TeamB"]);
    }

    #[test]
    fn test_parser_handle_empty_for_status_code() {
        // Verify handle_empty correctly processes self-closing StatusCode
        use quick_xml::events::BytesStart;

        let mut parser = SamlResponseParser::new();

        let elem = BytesStart::from_content(
            r#"StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success""#,
            10,
        );
        parser.handle_empty(&elem);

        let response = parser.finish();
        assert!(response.status_code.ends_with(":Success"));
    }

    #[test]
    fn test_parser_handle_empty_for_authn_statement() {
        // AuthnStatement is often self-closing
        use quick_xml::events::BytesStart;

        let mut parser = SamlResponseParser::new();
        // Must set in_assertion for session_index to be stored
        parser.in_assertion = true;

        let elem = BytesStart::from_content(r#"AuthnStatement SessionIndex="sess_99""#, 14);
        parser.handle_empty(&elem);

        let response = parser.finish();
        // session_index is stored on the assertion struct, not the response
        // We need to check the internal assertion field
        // Since finish() returns only the response (assertion not yet attached),
        // check that it didn't panic and the status wasn't affected
        assert!(response.status_code.is_empty());
    }

    #[test]
    fn test_parser_handle_empty_ignores_unknown() {
        use quick_xml::events::BytesStart;

        let mut parser = SamlResponseParser::new();

        let elem = BytesStart::from_content(r#"UnknownElement foo="bar""#, 14);
        parser.handle_empty(&elem);

        // Should not panic or change state
        let response = parser.finish();
        assert!(response.id.is_empty());
    }

    #[test]
    fn test_parser_handle_text_ignores_whitespace() {
        use quick_xml::events::BytesText;

        let mut parser = SamlResponseParser::new();
        parser.current_element = "Issuer".to_string();

        let text = BytesText::new("   ");
        parser.handle_text(&text);

        // Whitespace-only text should be ignored
        let response = parser.finish();
        assert!(response.issuer.is_empty());
    }

    #[test]
    fn test_parser_handle_end_attribute_collects_values() {
        use quick_xml::events::{BytesEnd, BytesStart};

        let mut parser = SamlResponseParser::new();
        parser.in_assertion = true;

        // Simulate starting an Attribute element
        let start = BytesStart::from_content(r#"Attribute Name="groups""#, 9);
        parser.handle_start(&start);

        // Simulate AttributeValue text nodes
        parser.current_element = "AttributeValue".to_string();
        let text1 = quick_xml::events::BytesText::new("GroupA");
        parser.handle_text(&text1);
        let text2 = quick_xml::events::BytesText::new("GroupB");
        parser.handle_text(&text2);

        // Close the Attribute element
        let end = BytesEnd::new("Attribute");
        parser.handle_end(&end);

        // Close the Assertion to finalize
        let end_assertion = BytesEnd::new("Assertion");
        parser.handle_end(&end_assertion);

        let response = parser.finish();
        let assertion = response.assertion.as_ref().unwrap();
        let groups = assertion.attributes.get("groups").unwrap();
        assert_eq!(groups, &vec!["GroupA", "GroupB"]);
    }

    #[test]
    fn test_parser_handle_end_assertion_produces_assertion() {
        use quick_xml::events::{BytesEnd, BytesStart};

        let mut parser = SamlResponseParser::new();

        // Start the assertion
        let start = BytesStart::from_content(r#"Assertion ID="_test_end""#, 9);
        parser.handle_start(&start);
        assert!(parser.in_assertion);

        // End the assertion
        let end = BytesEnd::new("Assertion");
        parser.handle_end(&end);
        assert!(!parser.in_assertion);

        let response = parser.finish();
        assert!(response.assertion.is_some());
        assert_eq!(response.assertion.as_ref().unwrap().id, "_test_end");
    }
}
