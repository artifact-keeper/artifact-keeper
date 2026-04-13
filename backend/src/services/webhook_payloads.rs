//! Webhook payload renderers for different chat platforms.
//!
//! Each template transforms a generic webhook event into a platform-specific
//! JSON structure that the target service can render natively (rich cards,
//! blocks, embeds, etc.).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Supported webhook payload templates.
///
/// Controls how the outgoing JSON body is structured when delivering a
/// webhook. The `Generic` variant preserves backward compatibility with the
/// original flat JSON format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayloadTemplate {
    #[default]
    Generic,
    Slack,
    MicrosoftTeams,
    Discord,
    Mattermost,
}

impl std::fmt::Display for PayloadTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadTemplate::Generic => write!(f, "generic"),
            PayloadTemplate::Slack => write!(f, "slack"),
            PayloadTemplate::MicrosoftTeams => write!(f, "microsoft_teams"),
            PayloadTemplate::Discord => write!(f, "discord"),
            PayloadTemplate::Mattermost => write!(f, "mattermost"),
        }
    }
}

impl PayloadTemplate {
    /// Parse a stored string value into a `PayloadTemplate`.
    ///
    /// Unrecognized values fall back to `Generic` so that existing rows with
    /// the default value always work.
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "slack" => Self::Slack,
            "microsoft_teams" => Self::MicrosoftTeams,
            "discord" => Self::Discord,
            "mattermost" => Self::Mattermost,
            _ => Self::Generic,
        }
    }
}

/// Build a human-readable title line from the event name and details.
fn event_title(event: &str, details: &serde_json::Value) -> String {
    let name = details
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let repo = details
        .get("repository")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let suffix = if repo.is_empty() {
        name.to_string()
    } else {
        format!("{} in {}", name, repo)
    };

    match event {
        "artifact_uploaded" => format!("Artifact uploaded: {}", suffix),
        "artifact_deleted" => format!("Artifact deleted: {}", suffix),
        "repository_created" => format!("Repository created: {}", name),
        "repository_deleted" => format!("Repository deleted: {}", name),
        "user_created" => format!("User created: {}", name),
        "user_deleted" => format!("User deleted: {}", name),
        "build_started" => format!("Build started: {}", suffix),
        "build_completed" => format!("Build completed: {}", suffix),
        "build_failed" => format!("Build failed: {}", suffix),
        "test" => "Test webhook delivery".to_string(),
        _ => format!("Event: {}", event),
    }
}

/// Collect key/value fact pairs from the details object for use in
/// structured card layouts.
fn detail_facts(details: &serde_json::Value) -> Vec<(String, String)> {
    let mut facts = Vec::new();
    if let Some(obj) = details.as_object() {
        for (key, value) in obj {
            let display = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            facts.push((key.clone(), display));
        }
    }
    facts
}

/// Render a webhook payload using the specified template.
///
/// - `template`: which platform layout to use
/// - `event`: the event type string (e.g. "artifact_uploaded", "test")
/// - `details`: arbitrary JSON data associated with the event
/// - `timestamp`: ISO 8601 timestamp string
pub fn render_payload(
    template: PayloadTemplate,
    event: &str,
    details: &serde_json::Value,
    timestamp: &str,
) -> serde_json::Value {
    match template {
        PayloadTemplate::Generic => render_generic(event, details, timestamp),
        PayloadTemplate::Slack => render_slack(event, details, timestamp),
        PayloadTemplate::MicrosoftTeams => render_teams(event, details, timestamp),
        PayloadTemplate::Discord => render_discord(event, details, timestamp),
        PayloadTemplate::Mattermost => render_mattermost(event, details, timestamp),
    }
}

/// Generic format: the original flat JSON structure for backward compatibility.
fn render_generic(event: &str, details: &serde_json::Value, timestamp: &str) -> serde_json::Value {
    serde_json::json!({
        "event": event,
        "timestamp": timestamp,
        "data": details
    })
}

/// Slack Block Kit format.
fn render_slack(event: &str, details: &serde_json::Value, timestamp: &str) -> serde_json::Value {
    let title = event_title(event, details);
    let facts = detail_facts(details);

    let mut fields: Vec<serde_json::Value> = facts
        .iter()
        .map(|(k, v)| {
            serde_json::json!({
                "type": "mrkdwn",
                "text": format!("*{}:* {}", k, v)
            })
        })
        .collect();

    fields.push(serde_json::json!({
        "type": "mrkdwn",
        "text": format!("*timestamp:* {}", timestamp)
    }));

    serde_json::json!({
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title
                }
            },
            {
                "type": "section",
                "fields": fields
            }
        ]
    })
}

/// Microsoft Teams Adaptive Card format.
fn render_teams(event: &str, details: &serde_json::Value, timestamp: &str) -> serde_json::Value {
    let title = event_title(event, details);
    let facts = detail_facts(details);

    let mut fact_items: Vec<serde_json::Value> = facts
        .iter()
        .map(|(k, v)| serde_json::json!({"title": k, "value": v}))
        .collect();

    fact_items.push(serde_json::json!({"title": "timestamp", "value": timestamp}));

    serde_json::json!({
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Medium",
                            "weight": "Bolder",
                            "text": title
                        },
                        {
                            "type": "FactSet",
                            "facts": fact_items
                        }
                    ]
                }
            }
        ]
    })
}

/// Discord embed format.
fn render_discord(event: &str, details: &serde_json::Value, timestamp: &str) -> serde_json::Value {
    let title = event_title(event, details);
    let facts = detail_facts(details);

    let fields: Vec<serde_json::Value> = facts
        .iter()
        .map(|(k, v)| {
            serde_json::json!({
                "name": k,
                "value": v,
                "inline": true
            })
        })
        .collect();

    serde_json::json!({
        "embeds": [
            {
                "title": title,
                "timestamp": timestamp,
                "fields": fields,
                "footer": {
                    "text": "Artifact Keeper"
                }
            }
        ]
    })
}

/// Mattermost attachment format.
fn render_mattermost(
    event: &str,
    details: &serde_json::Value,
    timestamp: &str,
) -> serde_json::Value {
    let title = event_title(event, details);
    let facts = detail_facts(details);

    let fields: Vec<serde_json::Value> = facts
        .iter()
        .map(|(k, v)| {
            serde_json::json!({
                "title": k,
                "value": v,
                "short": true
            })
        })
        .collect();

    serde_json::json!({
        "text": title,
        "attachments": [
            {
                "fallback": title,
                "title": format!("Event: {}", event),
                "fields": fields,
                "footer": "Artifact Keeper",
                "ts": timestamp
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // PayloadTemplate basics
    // -----------------------------------------------------------------------

    #[test]
    fn test_payload_template_default_is_generic() {
        assert_eq!(PayloadTemplate::default(), PayloadTemplate::Generic);
    }

    #[test]
    fn test_payload_template_display() {
        assert_eq!(PayloadTemplate::Generic.to_string(), "generic");
        assert_eq!(PayloadTemplate::Slack.to_string(), "slack");
        assert_eq!(
            PayloadTemplate::MicrosoftTeams.to_string(),
            "microsoft_teams"
        );
        assert_eq!(PayloadTemplate::Discord.to_string(), "discord");
        assert_eq!(PayloadTemplate::Mattermost.to_string(), "mattermost");
    }

    #[test]
    fn test_payload_template_from_str_lossy() {
        assert_eq!(
            PayloadTemplate::from_str_lossy("slack"),
            PayloadTemplate::Slack
        );
        assert_eq!(
            PayloadTemplate::from_str_lossy("microsoft_teams"),
            PayloadTemplate::MicrosoftTeams
        );
        assert_eq!(
            PayloadTemplate::from_str_lossy("discord"),
            PayloadTemplate::Discord
        );
        assert_eq!(
            PayloadTemplate::from_str_lossy("mattermost"),
            PayloadTemplate::Mattermost
        );
        assert_eq!(
            PayloadTemplate::from_str_lossy("generic"),
            PayloadTemplate::Generic
        );
        assert_eq!(
            PayloadTemplate::from_str_lossy("unknown_value"),
            PayloadTemplate::Generic
        );
    }

    #[test]
    fn test_payload_template_serialization() {
        let json = serde_json::to_string(&PayloadTemplate::Slack).unwrap();
        assert_eq!(json, "\"slack\"");
    }

    #[test]
    fn test_payload_template_deserialization() {
        let t: PayloadTemplate = serde_json::from_str("\"microsoft_teams\"").unwrap();
        assert_eq!(t, PayloadTemplate::MicrosoftTeams);
    }

    #[test]
    fn test_payload_template_roundtrip() {
        for template in [
            PayloadTemplate::Generic,
            PayloadTemplate::Slack,
            PayloadTemplate::MicrosoftTeams,
            PayloadTemplate::Discord,
            PayloadTemplate::Mattermost,
        ] {
            let json = serde_json::to_string(&template).unwrap();
            let parsed: PayloadTemplate = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, template);
        }
    }

    // -----------------------------------------------------------------------
    // Helper functions
    // -----------------------------------------------------------------------

    #[test]
    fn test_event_title_artifact_uploaded() {
        let details = serde_json::json!({"name": "my-lib", "repository": "libs-release"});
        assert_eq!(
            event_title("artifact_uploaded", &details),
            "Artifact uploaded: my-lib in libs-release"
        );
    }

    #[test]
    fn test_event_title_no_repository() {
        let details = serde_json::json!({"name": "admin-user"});
        assert_eq!(
            event_title("user_created", &details),
            "User created: admin-user"
        );
    }

    #[test]
    fn test_event_title_test_event() {
        let details = serde_json::json!({"message": "ping"});
        assert_eq!(event_title("test", &details), "Test webhook delivery");
    }

    #[test]
    fn test_event_title_unknown_event() {
        let details = serde_json::json!({});
        assert_eq!(event_title("custom.thing", &details), "Event: custom.thing");
    }

    #[test]
    fn test_detail_facts_extracts_primitives() {
        let details = serde_json::json!({
            "name": "foo",
            "version": "1.0.0",
            "size": 1024,
            "stable": true,
            "nested": {"skip": true}
        });
        let facts = detail_facts(&details);
        // nested objects are skipped
        assert!(facts.iter().any(|(k, _)| k == "name"));
        assert!(facts.iter().any(|(k, _)| k == "version"));
        assert!(facts.iter().any(|(k, _)| k == "size"));
        assert!(facts.iter().any(|(k, _)| k == "stable"));
        assert!(!facts.iter().any(|(k, _)| k == "nested"));
    }

    // -----------------------------------------------------------------------
    // Generic template
    // -----------------------------------------------------------------------

    #[test]
    fn test_render_generic_structure() {
        let details = serde_json::json!({"name": "pkg", "version": "2.0"});
        let ts = "2026-04-08T12:00:00Z";
        let payload = render_payload(PayloadTemplate::Generic, "artifact_uploaded", &details, ts);

        assert_eq!(payload["event"], "artifact_uploaded");
        assert_eq!(payload["timestamp"], ts);
        assert_eq!(payload["data"]["name"], "pkg");
        assert_eq!(payload["data"]["version"], "2.0");
    }

    #[test]
    fn test_render_generic_test_event() {
        let details = serde_json::json!({"message": "This is a test webhook delivery"});
        let ts = "2026-04-08T00:00:00Z";
        let payload = render_payload(PayloadTemplate::Generic, "test", &details, ts);

        assert_eq!(payload["event"], "test");
        assert_eq!(
            payload["data"]["message"],
            "This is a test webhook delivery"
        );
    }

    // -----------------------------------------------------------------------
    // Slack template
    // -----------------------------------------------------------------------

    #[test]
    fn test_render_slack_has_blocks() {
        let details = serde_json::json!({"name": "my-app", "version": "3.1"});
        let ts = "2026-04-08T12:00:00Z";
        let payload = render_payload(PayloadTemplate::Slack, "artifact_uploaded", &details, ts);

        let blocks = payload["blocks"].as_array().expect("blocks must be array");
        assert_eq!(blocks.len(), 2);

        // Header block
        assert_eq!(blocks[0]["type"], "header");
        let header_text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(header_text.contains("Artifact uploaded"));

        // Section block with fields
        assert_eq!(blocks[1]["type"], "section");
        let fields = blocks[1]["fields"]
            .as_array()
            .expect("fields must be array");
        assert!(!fields.is_empty());

        // All fields use mrkdwn type
        for field in fields {
            assert_eq!(field["type"], "mrkdwn");
        }
    }

    #[test]
    fn test_render_slack_includes_timestamp_field() {
        let details = serde_json::json!({"name": "x"});
        let ts = "2026-04-08T12:00:00Z";
        let payload = render_payload(PayloadTemplate::Slack, "test", &details, ts);

        let fields = payload["blocks"][1]["fields"].as_array().unwrap();
        let has_ts = fields
            .iter()
            .any(|f| f["text"].as_str().unwrap_or("").contains(ts));
        assert!(has_ts, "Slack payload must include the timestamp in fields");
    }

    // -----------------------------------------------------------------------
    // Microsoft Teams template
    // -----------------------------------------------------------------------

    #[test]
    fn test_render_teams_adaptive_card_structure() {
        let details = serde_json::json!({"name": "backend", "version": "1.0.0"});
        let ts = "2026-04-08T12:00:00Z";
        let payload = render_payload(
            PayloadTemplate::MicrosoftTeams,
            "build_completed",
            &details,
            ts,
        );

        assert_eq!(payload["type"], "message");

        let attachments = payload["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(
            attachments[0]["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );

        let content = &attachments[0]["content"];
        assert_eq!(content["type"], "AdaptiveCard");
        assert_eq!(content["version"], "1.4");

        let body = content["body"].as_array().unwrap();
        assert!(body.len() >= 2);

        // Title block
        assert_eq!(body[0]["type"], "TextBlock");
        assert!(body[0]["text"]
            .as_str()
            .unwrap()
            .contains("Build completed"));

        // FactSet
        assert_eq!(body[1]["type"], "FactSet");
        let facts = body[1]["facts"].as_array().unwrap();
        assert!(!facts.is_empty());
        // Each fact has title and value
        for fact in facts {
            assert!(fact.get("title").is_some());
            assert!(fact.get("value").is_some());
        }
    }

    // -----------------------------------------------------------------------
    // Discord template
    // -----------------------------------------------------------------------

    #[test]
    fn test_render_discord_embeds_structure() {
        let details = serde_json::json!({"name": "my-crate", "repository": "cargo-hosted"});
        let ts = "2026-04-08T12:00:00Z";
        let payload = render_payload(PayloadTemplate::Discord, "artifact_uploaded", &details, ts);

        let embeds = payload["embeds"].as_array().expect("embeds must be array");
        assert_eq!(embeds.len(), 1);

        let embed = &embeds[0];
        assert!(embed["title"]
            .as_str()
            .unwrap()
            .contains("Artifact uploaded"));
        assert_eq!(embed["timestamp"], ts);
        assert_eq!(embed["footer"]["text"], "Artifact Keeper");

        let fields = embed["fields"].as_array().unwrap();
        for field in fields {
            assert!(field.get("name").is_some());
            assert!(field.get("value").is_some());
            assert_eq!(field["inline"], true);
        }
    }

    #[test]
    fn test_render_discord_empty_details() {
        let details = serde_json::json!({});
        let ts = "2026-04-08T12:00:00Z";
        let payload = render_payload(PayloadTemplate::Discord, "test", &details, ts);

        let embeds = payload["embeds"].as_array().unwrap();
        assert_eq!(embeds.len(), 1);
        let fields = embeds[0]["fields"].as_array().unwrap();
        assert!(fields.is_empty());
    }

    // -----------------------------------------------------------------------
    // Mattermost template
    // -----------------------------------------------------------------------

    #[test]
    fn test_render_mattermost_structure() {
        let details = serde_json::json!({"name": "web-app", "version": "2.5.0"});
        let ts = "2026-04-08T12:00:00Z";
        let payload = render_payload(PayloadTemplate::Mattermost, "build_failed", &details, ts);

        assert!(payload["text"].as_str().unwrap().contains("Build failed"));

        let attachments = payload["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);

        let att = &attachments[0];
        assert!(att["fallback"].as_str().unwrap().contains("Build failed"));
        assert_eq!(att["title"], "Event: build_failed");
        assert_eq!(att["footer"], "Artifact Keeper");
        assert_eq!(att["ts"], ts);

        let fields = att["fields"].as_array().unwrap();
        for field in fields {
            assert!(field.get("title").is_some());
            assert!(field.get("value").is_some());
            assert_eq!(field["short"], true);
        }
    }

    #[test]
    fn test_render_mattermost_test_event() {
        let details = serde_json::json!({"message": "ping"});
        let ts = "2026-04-08T00:00:00Z";
        let payload = render_payload(PayloadTemplate::Mattermost, "test", &details, ts);

        assert_eq!(payload["text"], "Test webhook delivery");
        let att_fields = payload["attachments"][0]["fields"].as_array().unwrap();
        assert!(att_fields
            .iter()
            .any(|f| f["title"] == "message" && f["value"] == "ping"));
    }

    // -----------------------------------------------------------------------
    // Cross-template consistency
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_templates_produce_valid_json() {
        let details = serde_json::json!({"name": "test-pkg", "version": "1.0"});
        let ts = "2026-04-08T12:00:00Z";
        for template in [
            PayloadTemplate::Generic,
            PayloadTemplate::Slack,
            PayloadTemplate::MicrosoftTeams,
            PayloadTemplate::Discord,
            PayloadTemplate::Mattermost,
        ] {
            let payload = render_payload(template, "artifact_uploaded", &details, ts);
            // Should serialize without error
            let serialized = serde_json::to_string(&payload).unwrap();
            assert!(!serialized.is_empty());
            // Should round-trip
            let _: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        }
    }
}
