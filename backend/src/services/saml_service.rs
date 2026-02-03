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

        let mut response = SamlResponse {
            id: String::new(),
            in_response_to: None,
            issuer: String::new(),
            status_code: String::new(),
            status_message: None,
            assertion: None,
        };

        let mut current_element = String::new();
        let mut in_assertion = false;
        let mut assertion = SamlAssertion {
            id: String::new(),
            issuer: String::new(),
            name_id: String::new(),
            name_id_format: None,
            session_index: None,
            not_before: None,
            not_on_or_after: None,
            audiences: Vec::new(),
            attributes: HashMap::new(),
        };
        let mut current_attr_name: Option<String> = None;
        let mut current_attr_values: Vec<String> = Vec::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                    current_element = name.clone();

                    match name.as_str() {
                        "Response" => {
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "ID" => response.id = value,
                                    "InResponseTo" => response.in_response_to = Some(value),
                                    _ => {}
                                }
                            }
                        }
                        "Assertion" => {
                            in_assertion = true;
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                if key == "ID" {
                                    assertion.id = value;
                                }
                            }
                        }
                        "StatusCode" => {
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                if key == "Value" {
                                    response.status_code = value;
                                }
                            }
                        }
                        "NameID" => {
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                if key == "Format" {
                                    assertion.name_id_format = Some(value);
                                }
                            }
                        }
                        "Conditions" => {
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                match key.as_str() {
                                    "NotBefore" => assertion.not_before = Some(value),
                                    "NotOnOrAfter" => assertion.not_on_or_after = Some(value),
                                    _ => {}
                                }
                            }
                        }
                        "AuthnStatement" => {
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                if key == "SessionIndex" {
                                    assertion.session_index = Some(value);
                                }
                            }
                        }
                        "Attribute" => {
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let value = String::from_utf8_lossy(&attr.value).to_string();
                                if key == "Name" {
                                    current_attr_name = Some(value);
                                    current_attr_values.clear();
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                    if name == "StatusCode" {
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let value = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "Value" {
                                response.status_code = value;
                            }
                        }
                    }
                }
                Ok(Event::Text(ref e)) => {
                    let raw = String::from_utf8_lossy(e.as_ref());
                    let text = unescape(&raw)
                        .map(|c| c.to_string())
                        .unwrap_or_else(|_| raw.to_string());
                    if !text.trim().is_empty() {
                        match current_element.as_str() {
                            "Issuer" => {
                                if in_assertion {
                                    assertion.issuer = text;
                                } else {
                                    response.issuer = text;
                                }
                            }
                            "NameID" => {
                                assertion.name_id = text;
                            }
                            "Audience" => {
                                assertion.audiences.push(text);
                            }
                            "AttributeValue" => {
                                current_attr_values.push(text);
                            }
                            "StatusMessage" => {
                                response.status_message = Some(text);
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                    match name.as_str() {
                        "Assertion" => {
                            in_assertion = false;
                            response.assertion = Some(assertion.clone());
                        }
                        "Attribute" => {
                            if let Some(attr_name) = current_attr_name.take() {
                                assertion
                                    .attributes
                                    .insert(attr_name, current_attr_values.clone());
                                current_attr_values.clear();
                            }
                        }
                        _ => {}
                    }
                }
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

        Ok(response)
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
                external_id, is_admin, is_active, must_change_password,
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
            INSERT INTO users (id, username, email, display_name, auth_provider, external_id, is_admin, is_active)
            VALUES ($1, $2, $3, $4, 'saml', $5, $6, true)
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, must_change_password,
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

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b"Hello World"), "SGVsbG8gV29ybGQ=");
    }

    #[test]
    fn test_base64_decode() {
        let decoded = base64_decode("SGVsbG8=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello");

        let decoded = base64_decode("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("hello"), "hello");
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
        assert_eq!(urlencoding::encode("a+b=c"), "a%2Bb%3Dc");
    }

    #[test]
    fn test_saml_config_defaults() {
        // Set minimal env vars for test
        std::env::set_var("SAML_IDP_SSO_URL", "https://idp.example.com/sso");
        std::env::set_var("SAML_IDP_ISSUER", "https://idp.example.com");

        let config = SamlConfig::from_env();
        assert!(config.is_some());
        let config = config.unwrap();
        assert_eq!(config.idp_sso_url, "https://idp.example.com/sso");
        assert_eq!(config.sp_entity_id, "artifact-keeper");

        // Clean up
        std::env::remove_var("SAML_IDP_SSO_URL");
        std::env::remove_var("SAML_IDP_ISSUER");
    }
}
