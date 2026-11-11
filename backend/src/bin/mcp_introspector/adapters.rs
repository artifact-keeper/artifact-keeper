//! Inventory adapters: turn the tool inventories other MCP runtimes already
//! produce into the body of `POST .../capabilities` (`gateway_reported`), so
//! an operator running a Docker MCP Gateway or ToolHive can feed AK without
//! AK running anything.
//!
//! | `--from` | Input | Produced by |
//! |---|---|---|
//! | `docker-gateway` | a JSON array of MCP `Tool` objects | `docker mcp tools ls --format=json` |
//! | `docker-catalog` | `tools.json`: `[{name, description, arguments: [{name, type, desc}]}]` | the `docker/mcp-registry` catalog override |
//! | `toolhive` | `{"tools": [Tool...], "resources"?, "prompts"?}` or a registry entry's `"tools": ["name", ...]` | `thv mcp list tools --format json`, toolhive-registry `_meta` |
//! | `static` | `{"tools", "resources", "prompts", "instructions"}` | Cisco MCP Scanner `static` JSON, hand-written |

use serde_json::{json, Map, Value};

/// ToolHive's placeholder for "listed at runtime".
pub const TOOLHIVE_RUNTIME_PLACEHOLDER: &str = "set_during_runtime";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inventory {
    DockerGateway,
    DockerCatalog,
    ToolHive,
    Static,
}

impl Inventory {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "docker-gateway" => Some(Self::DockerGateway),
            "docker-catalog" => Some(Self::DockerCatalog),
            "toolhive" => Some(Self::ToolHive),
            "static" => Some(Self::Static),
            _ => None,
        }
    }

    pub fn generated_by(self) -> &'static str {
        match self {
            Self::DockerGateway => "docker-mcp-gateway",
            Self::DockerCatalog => "docker-mcp-catalog",
            Self::ToolHive => "toolhive",
            Self::Static => "static",
        }
    }
}

/// The members of a `Tool` AK keeps.
const TOOL_FIELDS: &[&str] = &[
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
    "_meta",
];

fn keep(v: &Value, fields: &[&str]) -> Option<Value> {
    let o = v.as_object()?;
    o.get("name").and_then(|n| n.as_str())?;
    let mut out = Map::new();
    for f in fields {
        if let Some(x) = o.get(*f) {
            if !x.is_null() {
                out.insert((*f).to_string(), x.clone());
            }
        }
    }
    Some(Value::Object(out))
}

fn tools_of(v: &Value) -> Vec<Value> {
    v.as_array()
        .map(|a| a.iter().filter_map(|t| keep(t, TOOL_FIELDS)).collect())
        .unwrap_or_default()
}

/// `tools.json` arguments to a JSON Schema.
fn catalog_tool(t: &Value) -> Option<Value> {
    let name = t.get("name")?.as_str()?;
    let mut props = Map::new();
    let mut required = Vec::new();
    for a in t
        .get("arguments")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
    {
        let Some(arg) = a.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let mut p = Map::new();
        p.insert(
            "type".into(),
            a.get("type").cloned().unwrap_or(json!("string")),
        );
        if let Some(d) = a.get("desc").or_else(|| a.get("description")) {
            p.insert("description".into(), d.clone());
        }
        if let Some(items) = a.get("items") {
            p.insert("items".into(), items.clone());
        }
        props.insert(arg.to_string(), Value::Object(p));
        if !a.get("optional").and_then(|o| o.as_bool()).unwrap_or(false) {
            required.push(json!(arg));
        }
    }
    let mut tool = json!({
        "name": name,
        "inputSchema": {"type": "object", "properties": props, "required": required},
    });
    if let Some(d) = t.get("description") {
        tool["description"] = d.clone();
    }
    if let Some(a) = t.get("annotations") {
        tool["annotations"] = a.clone();
    }
    Some(tool)
}

/// Convert an inventory into an ingest body.
pub fn convert(kind: Inventory, input: &Value) -> Result<Value, String> {
    let (tools, resources, prompts, instructions) = match kind {
        Inventory::DockerGateway => {
            let arr = input
                .as_array()
                .or_else(|| input.get("tools").and_then(|t| t.as_array()))
                .ok_or("expected the JSON array `docker mcp tools ls --format=json` prints")?;
            (tools_of(&Value::Array(arr.clone())), vec![], vec![], None)
        }
        Inventory::DockerCatalog => {
            let arr = input.as_array().ok_or("expected a tools.json array")?;
            (
                arr.iter().filter_map(catalog_tool).collect(),
                vec![],
                vec![],
                None,
            )
        }
        Inventory::ToolHive => {
            let list = input
                .get("tools")
                .and_then(|t| t.as_array())
                .ok_or("expected an object with a `tools` array")?;
            let tools = list
                .iter()
                .filter_map(|t| match t {
                    Value::String(n) if n != TOOLHIVE_RUNTIME_PLACEHOLDER && !n.is_empty() => {
                        Some(json!({"name": n}))
                    }
                    other => keep(other, TOOL_FIELDS),
                })
                .collect();
            let arr = |k: &str| {
                input
                    .get(k)
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default()
            };
            (tools, arr("resources"), arr("prompts"), None)
        }
        Inventory::Static => {
            let o = input.as_object().ok_or("expected a JSON object")?;
            let arr = |k: &str| {
                o.get(k)
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default()
            };
            (
                tools_of(&Value::Array(arr("tools"))),
                arr("resources"),
                arr("prompts"),
                o.get("instructions").cloned(),
            )
        }
    };
    let mut body = json!({
        "source": "gateway_reported",
        "generatedBy": kind.generated_by(),
        "tools": tools,
        "resources": resources,
        "prompts": prompts,
    });
    if let Some(i) = instructions.filter(|i| i.is_string()) {
        body["instructions"] = i;
    }
    Ok(body)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_gateway_array() {
        let input = json!([
            {"name": "search", "description": "Search", "inputSchema": {"type": "object"},
             "annotations": {"readOnlyHint": true}, "extra": 1},
            {"description": "nameless"},
        ]);
        let b = convert(Inventory::DockerGateway, &input).unwrap();
        assert_eq!(b["source"], "gateway_reported");
        assert_eq!(b["generatedBy"], "docker-mcp-gateway");
        assert_eq!(b["tools"].as_array().unwrap().len(), 1);
        assert!(b["tools"][0].get("extra").is_none());
        assert_eq!(b["tools"][0]["annotations"]["readOnlyHint"], true);
        assert!(convert(Inventory::DockerGateway, &json!("x")).is_err());
        assert!(convert(Inventory::DockerGateway, &json!({"tools": []})).is_ok());
    }

    #[test]
    fn docker_catalog_arguments_become_a_schema() {
        let input = json!([{"name": "fetch", "description": "Fetch a URL", "arguments": [
            {"name": "url", "type": "string", "desc": "The URL"},
            {"name": "max", "type": "integer", "optional": true},
            {"type": "string"},
        ]}, {"nope": 1}]);
        let b = convert(Inventory::DockerCatalog, &input).unwrap();
        let t = &b["tools"][0];
        assert_eq!(
            t["inputSchema"]["properties"]["url"]["description"],
            "The URL"
        );
        assert_eq!(t["inputSchema"]["required"], json!(["url"]));
        assert_eq!(b["tools"].as_array().unwrap().len(), 1);
        assert!(convert(Inventory::DockerCatalog, &json!({})).is_err());
    }

    #[test]
    fn toolhive_both_shapes_and_static() {
        let b = convert(Inventory::ToolHive, &json!({"tools": [
            {"name": "a", "description": "d", "inputSchema": {}}, "b", TOOLHIVE_RUNTIME_PLACEHOLDER, ""
        ], "prompts": [{"name": "p"}]}))
        .unwrap();
        assert_eq!(
            b["tools"],
            json!([{"name": "a", "description": "d", "inputSchema": {}}, {"name": "b"}])
        );
        assert_eq!(b["prompts"][0]["name"], "p");
        assert!(convert(Inventory::ToolHive, &json!([])).is_err());
        let b = convert(
            Inventory::Static,
            &json!({"tools": [{"name": "x"}], "instructions": "i",
            "resources": [{"uri": "file:///a"}]}),
        )
        .unwrap();
        assert_eq!(b["instructions"], "i");
        assert_eq!(b["resources"][0]["uri"], "file:///a");
        assert!(convert(Inventory::Static, &json!([])).is_err());
        for (s, k) in [
            ("docker-gateway", Inventory::DockerGateway),
            ("docker-catalog", Inventory::DockerCatalog),
            ("toolhive", Inventory::ToolHive),
            ("static", Inventory::Static),
        ] {
            assert_eq!(Inventory::parse(s), Some(k));
        }
        assert_eq!(Inventory::parse("x"), None);
    }
}
