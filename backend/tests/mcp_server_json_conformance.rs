//! server.json conformance for the MCP registry format (#5253).
//!
//! The accepted vectors are the examples of the upstream specification
//! `docs/reference/server-json/generic-server-json.md` in
//! `modelcontextprotocol/registry` (MIT licence), reproduced as data so the
//! validator accepts every document the specification itself shows. The
//! refused vectors are one per validation rule of `formats::mcp`, including
//! the OCI identifier table. Pure functions only; no database.

use artifact_keeper_backend::formats::mcp::{
    parse_oci_identifier, parse_server_json, validate_server_json, McpError, OciRefError,
};

fn check(doc: &str) -> Result<(), McpError> {
    let s = parse_server_json(doc.as_bytes())?;
    validate_server_json(&s)
}

/// `(title, document)` for every example in the upstream specification.
const UPSTREAM_EXAMPLES: &[(&str, &str)] = &[
    (
        "Basic Server with NPM Package",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.modelcontextprotocol.anonymous/brave-search",
 "description": "MCP server for Brave Search API integration",
 "title": "Brave Search",
 "websiteUrl": "https://anonymous.modelcontextprotocol.io/examples",
 "repository": {
  "url": "https://github.com/modelcontextprotocol/servers",
  "source": "github"
 },
 "version": "1.0.2",
 "packages": [
  {
   "registryType": "npm",
   "registryBaseUrl": "https://registry.npmjs.org",
   "identifier": "@modelcontextprotocol/server-brave-search",
   "version": "1.0.2",
   "transport": {
    "type": "stdio"
   },
   "environmentVariables": [
    {
     "name": "BRAVE_API_KEY",
     "description": "Brave Search API Key",
     "isRequired": true,
     "isSecret": true
    }
   ]
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "npm-publisher",
   "version": "1.0.1",
   "build_info": {
    "timestamp": "2023-12-01T10:30:00Z"
   }
  }
 }
}"##,
    ),
    (
        "Server in a Monorepo with Subfolder",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.modelcontextprotocol/everything",
 "description": "MCP server that exercises all the features of the MCP protocol",
 "title": "Everything",
 "repository": {
  "url": "https://github.com/modelcontextprotocol/servers",
  "source": "github",
  "subfolder": "src/everything"
 },
 "version": "0.6.2",
 "packages": [
  {
   "registryType": "npm",
   "registryBaseUrl": "https://registry.npmjs.org",
   "identifier": "@modelcontextprotocol/everything",
   "version": "0.6.2",
   "transport": {
    "type": "stdio"
   }
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "npm-publisher",
   "version": "1.0.1",
   "build_info": {
    "timestamp": "2023-12-01T10:30:00Z"
   }
  }
 }
}"##,
    ),
    (
        "Constant (fixed) arguments needed to start the MCP server",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.github.joelverhagen/knapcode-samplemcpserver",
 "description": "Sample NuGet MCP server for a random number and random weather",
 "version": "0.4.0-beta",
 "packages": [
  {
   "registryType": "nuget",
   "registryBaseUrl": "https://api.nuget.org/v3/index.json",
   "identifier": "Knapcode.SampleMcpServer",
   "version": "0.4.0-beta",
   "transport": {
    "type": "stdio"
   },
   "packageArguments": [
    {
     "type": "positional",
     "value": "mcp"
    },
    {
     "type": "positional",
     "value": "start"
    }
   ]
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "nuget-publisher",
   "version": "2.1.0",
   "build_info": {
    "timestamp": "2023-11-15T14:22:00Z",
    "pipeline_id": "nuget-build-456"
   }
  }
 }
}"##,
    ),
    (
        "Filesystem Server with Multiple Packages",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.github.modelcontextprotocol/filesystem",
 "description": "Node.js server implementing Model Context Protocol (MCP) for filesystem operations.",
 "title": "Filesystem",
 "repository": {
  "url": "https://github.com/modelcontextprotocol/servers",
  "source": "github",
  "id": "b94b5f7e-c7c6-d760-2c78-a5e9b8a5b8c9"
 },
 "version": "1.0.2",
 "packages": [
  {
   "registryType": "npm",
   "registryBaseUrl": "https://registry.npmjs.org",
   "identifier": "@modelcontextprotocol/server-filesystem",
   "version": "1.0.2",
   "transport": {
    "type": "stdio"
   },
   "packageArguments": [
    {
     "type": "positional",
     "valueHint": "target_dir",
     "description": "Path to access",
     "default": "/Users/username/Desktop",
     "isRequired": true,
     "isRepeated": true
    }
   ],
   "environmentVariables": [
    {
     "name": "LOG_LEVEL",
     "description": "Logging level (debug, info, warn, error)",
     "default": "info"
    }
   ]
  },
  {
   "registryType": "oci",
   "identifier": "docker.io/mcp/filesystem:1.0.2",
   "transport": {
    "type": "stdio"
   },
   "runtimeArguments": [
    {
     "type": "named",
     "description": "Mount a volume into the container",
     "name": "--mount",
     "value": "type=bind,src={source_path},dst={target_path}",
     "isRequired": true,
     "isRepeated": true,
     "variables": {
      "source_path": {
       "description": "Source path on host",
       "format": "filepath",
       "isRequired": true
      },
      "target_path": {
       "description": "Path to mount in the container. It should be rooted in `/project` directory.",
       "isRequired": true,
       "default": "/project"
      }
     }
    }
   ],
   "packageArguments": [
    {
     "type": "positional",
     "valueHint": "target_dir",
     "value": "/project"
    }
   ],
   "environmentVariables": [
    {
     "name": "LOG_LEVEL",
     "description": "Logging level (debug, info, warn, error)",
     "default": "info"
    }
   ]
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "ci-publisher",
   "version": "3.2.1",
   "build_info": {
    "commit": "a1b2c3d4e5f6789",
    "timestamp": "2023-12-01T10:30:00Z",
    "pipeline_id": "filesystem-build-789",
    "environment": "production"
   }
  }
 }
}"##,
    ),
    (
        "Filesystem Server with Multiple Packages",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.github.example/quay-sample-mcp",
 "description": "Example MCP server distributed as an OCI image on Quay.io",
 "version": "1.0.0",
 "packages": [
  {
   "registryType": "oci",
   "identifier": "quay.io/myorg/my-mcp-server:1.0.0",
   "transport": {
    "type": "stdio"
   }
  }
 ]
}"##,
    ),
    (
        "Remote Server Example",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.modelcontextprotocol.anonymous/mcp-fs",
 "description": "Cloud-hosted MCP filesystem server",
 "repository": {
  "url": "https://github.com/example/remote-fs",
  "source": "github",
  "id": "xyz789ab-cdef-0123-4567-890ghijklmno"
 },
 "version": "2.0.0",
 "remotes": [
  {
   "type": "streamable-http",
   "url": "https://mcp-fs.anonymous.modelcontextprotocol.io/http"
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "cloud-deployer",
   "version": "2.4.0",
   "build_info": {
    "commit": "f7e8d9c2b1a0",
    "timestamp": "2023-12-05T08:45:00Z",
    "deployment_id": "remote-fs-deploy-456",
    "region": "us-west-2"
   }
  }
 }
}"##,
    ),
    (
        "Python Package Example",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.github.example/weather-mcp",
 "description": "Python MCP server for weather data access",
 "title": "Weather",
 "repository": {
  "url": "https://github.com/example/weather-mcp",
  "source": "github",
  "id": "def456gh-ijkl-7890-mnop-qrstuvwxyz12"
 },
 "version": "0.5.0",
 "packages": [
  {
   "registryType": "pypi",
   "registryBaseUrl": "https://pypi.org",
   "identifier": "weather-mcp-server",
   "version": "0.5.0",
   "runtimeHint": "uvx",
   "transport": {
    "type": "stdio"
   },
   "environmentVariables": [
    {
     "name": "WEATHER_API_KEY",
     "description": "API key for weather service",
     "isRequired": true,
     "isSecret": true
    },
    {
     "name": "WEATHER_UNITS",
     "description": "Temperature units (celsius, fahrenheit)",
     "default": "celsius"
    }
   ]
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "poetry-publisher",
   "version": "1.8.3",
   "build_info": {
    "python_version": "3.11.5",
    "timestamp": "2023-11-28T16:20:00Z",
    "build_id": "pypi-weather-123",
    "dependencies_hash": "sha256:a9b8c7d6e5f4"
   }
  }
 }
}"##,
    ),
    (
        "Cargo (Rust) Package Example",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.github.example/widget-mcp",
 "description": "Rust-native MCP server",
 "title": "Widget",
 "repository": {
  "url": "https://github.com/example/widget-mcp",
  "source": "github"
 },
 "version": "0.3.0",
 "packages": [
  {
   "registryType": "cargo",
   "registryBaseUrl": "https://crates.io",
   "identifier": "widget-mcp",
   "version": "0.3.0",
   "transport": {
    "type": "stdio"
   }
  }
 ]
}"##,
    ),
    (
        "NuGet (.NET) Package Example",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.github.joelverhagen/knapcode-samplemcpserver",
 "description": "Sample NuGet MCP server for a random number and random weather",
 "repository": {
  "url": "https://github.com/joelverhagen/Knapcode.SampleMcpServer",
  "source": "github",
  "id": "example-nuget-id-0000-1111-222222222222"
 },
 "version": "0.5.0",
 "packages": [
  {
   "registryType": "nuget",
   "registryBaseUrl": "https://api.nuget.org/v3/index.json",
   "identifier": "Knapcode.SampleMcpServer",
   "version": "0.5.0",
   "runtimeHint": "dnx",
   "transport": {
    "type": "stdio"
   },
   "environmentVariables": [
    {
     "name": "WEATHER_CHOICES",
     "description": "Comma separated list of weather descriptions to randomly select.",
     "isRequired": true,
     "isSecret": false
    }
   ]
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "dotnet-publisher",
   "version": "8.0.100",
   "build_info": {
    "dotnet_version": "8.0.0",
    "timestamp": "2023-12-10T12:15:00Z",
    "configuration": "Release",
    "target_framework": "net8.0",
    "build_number": "20231210.1"
   }
  }
 }
}"##,
    ),
    (
        "Complex Docker Server with Multiple Arguments",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.github.example/database-manager",
 "description": "MCP server for database operations with support for multiple database types",
 "repository": {
  "url": "https://github.com/example/database-manager-mcp",
  "source": "github",
  "id": "ghi789jk-lmno-1234-pqrs-tuvwxyz56789"
 },
 "version": "3.1.0",
 "packages": [
  {
   "registryType": "oci",
   "identifier": "docker.io/example/database-manager-mcp:3.1.0",
   "transport": {
    "type": "stdio"
   },
   "runtimeArguments": [
    {
     "type": "named",
     "name": "--network",
     "value": "host",
     "description": "Use host network mode"
    },
    {
     "type": "named",
     "name": "-e",
     "value": "DB_TYPE={db_type}",
     "description": "Database type to connect to",
     "isRepeated": true,
     "variables": {
      "db_type": {
       "description": "Type of database",
       "choices": [
        "postgres",
        "mysql",
        "mongodb",
        "redis"
       ],
       "isRequired": true
      }
     }
    }
   ],
   "packageArguments": [
    {
     "type": "named",
     "name": "--host",
     "description": "Database host",
     "default": "localhost",
     "isRequired": true
    },
    {
     "type": "named",
     "name": "--port",
     "description": "Database port",
     "format": "number"
    },
    {
     "type": "positional",
     "valueHint": "database_name",
     "description": "Name of the database to connect to",
     "isRequired": true
    }
   ],
   "environmentVariables": [
    {
     "name": "DB_USERNAME",
     "description": "Database username",
     "isRequired": true
    },
    {
     "name": "DB_PASSWORD",
     "description": "Database password",
     "isRequired": true,
     "isSecret": true
    },
    {
     "name": "SSL_MODE",
     "description": "SSL connection mode",
     "default": "prefer",
     "choices": [
      "disable",
      "prefer",
      "require"
     ]
    }
   ]
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "docker-buildx",
   "version": "0.12.1",
   "build_info": {
    "docker_version": "24.0.7",
    "timestamp": "2023-12-08T14:30:00Z",
    "platform": "linux/amd64,linux/arm64",
    "registry": "docker.io",
    "image_digest": "sha256:1a2b3c4d5e6f7890"
   }
  }
 }
}"##,
    ),
    (
        "Server with Remote and Package Options",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.modelcontextprotocol.anonymous/hybrid-mcp",
 "description": "MCP server available as both local package and remote service",
 "title": "Hybrid",
 "repository": {
  "url": "https://github.com/example/hybrid-mcp",
  "source": "github",
  "id": "klm012no-pqrs-3456-tuvw-xyz789abcdef"
 },
 "version": "1.5.0",
 "packages": [
  {
   "registryType": "npm",
   "registryBaseUrl": "https://registry.npmjs.org",
   "identifier": "@example/hybrid-mcp-server",
   "version": "1.5.0",
   "runtimeHint": "npx",
   "transport": {
    "type": "stdio"
   },
   "packageArguments": [
    {
     "type": "named",
     "name": "--mode",
     "description": "Operation mode",
     "default": "local",
     "choices": [
      "local",
      "cached",
      "proxy"
     ]
    }
   ]
  }
 ],
 "remotes": [
  {
   "type": "streamable-http",
   "url": "https://mcp.anonymous.modelcontextprotocol.io/http",
   "headers": [
    {
     "name": "X-API-Key",
     "description": "API key for authentication",
     "isRequired": true,
     "isSecret": true
    },
    {
     "name": "X-Region",
     "description": "Service region",
     "default": "us-east-1",
     "choices": [
      "us-east-1",
      "eu-west-1",
      "ap-southeast-1"
     ]
    }
   ]
  },
  {
   "type": "sse",
   "url": "https://mcp.anonymous.modelcontextprotocol.io/sse"
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "hybrid-deployer",
   "version": "1.7.2",
   "build_info": {
    "timestamp": "2023-12-03T11:00:00Z",
    "deployment_strategy": "blue-green",
    "npm_version": "10.2.4",
    "node_version": "20.10.0",
    "service_endpoints": {
     "sse": "deployed",
     "streamable": "deployed"
    }
   }
  }
 }
}"##,
    ),
    (
        "MCP Bundle (MCPB) Package Example",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.modelcontextprotocol/text-editor",
 "description": "MCP Bundle server for advanced text editing capabilities",
 "title": "Text Editor",
 "repository": {
  "url": "https://github.com/modelcontextprotocol/text-editor-mcpb",
  "source": "github"
 },
 "version": "1.0.2",
 "packages": [
  {
   "registryType": "mcpb",
   "identifier": "https://github.com/modelcontextprotocol/text-editor-mcpb/releases/download/v1.0.2/text-editor.mcpb",
   "fileSha256": "fe333e598595000ae021bd27117db32ec69af6987f507ba7a63c90638ff633ce",
   "transport": {
    "type": "stdio"
   }
  }
 ],
 "_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
   "tool": "mcpb-publisher",
   "version": "1.0.0",
   "build_info": {
    "timestamp": "2023-12-02T09:15:00Z",
    "bundle_format": "mcpb-v1"
   }
  }
 }
}"##,
    ),
    (
        "Embedded MCP inside a CLI tool",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.snyk/cli-mcp",
 "description": "MCP server provided by the Snyk CLI",
 "title": "Snyk",
 "version": "1.1298.0",
 "packages": [
  {
   "registryType": "npm",
   "registryBaseUrl": "https://registry.npmjs.org",
   "identifier": "snyk",
   "version": "1.1298.0",
   "transport": {
    "type": "stdio"
   },
   "packageArguments": [
    {
     "type": "positional",
     "value": "mcp"
    },
    {
     "type": "named",
     "name": "-t",
     "description": "Transport type for MCP server",
     "default": "stdio",
     "choices": [
      "stdio",
      "sse"
     ]
    }
   ]
  }
 ]
}"##,
    ),
    (
        "Server with Custom Installation Path",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.modelcontextprotocol.anonymous/embedded-mcp",
 "description": "MCP server embedded in a Desktop app",
 "websiteUrl": "https://anonymous.modelcontextprotocol.io/embedded-mcp-guide",
 "version": "0.1.0"
}"##,
    ),
    (
        "Remote Server with URL Templating",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.modelcontextprotocol.anonymous/multi-tenant-server",
 "description": "MCP server with configurable remote endpoint",
 "title": "Multi-Tenant Server",
 "version": "1.0.0",
 "remotes": [
  {
   "type": "streamable-http",
   "url": "https://anonymous.modelcontextprotocol.io/mcp/{tenant_id}",
   "variables": {
    "tenant_id": {
     "description": "Tenant identifier (e.g., 'us-cell1', 'emea-cell1')",
     "isRequired": true
    }
   }
  }
 ]
}"##,
    ),
    (
        "Remote Server with URL Templating",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.modelcontextprotocol.anonymous/events-server",
 "description": "MCP server using SSE with tenant-specific endpoints",
 "version": "1.0.0",
 "remotes": [
  {
   "type": "sse",
   "url": "https://events.anonymous.modelcontextprotocol.io/sse/{tenant_id}",
   "variables": {
    "tenant_id": {
     "description": "Tenant identifier",
     "isRequired": true
    }
   }
  }
 ]
}"##,
    ),
    (
        "Local Server with URL Templating",
        r##"{
 "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
 "name": "io.github.example/configurable-server",
 "description": "Local MCP server with configurable port",
 "title": "Configurable Server",
 "version": "1.0.0",
 "packages": [
  {
   "registryType": "npm",
   "registryBaseUrl": "https://registry.npmjs.org",
   "identifier": "@example/mcp-server",
   "version": "1.0.0",
   "transport": {
    "type": "streamable-http",
    "url": "http://localhost:{--port}/mcp"
   },
   "packageArguments": [
    {
     "type": "named",
     "name": "--port",
     "description": "Port for the server to listen on",
     "default": "3000"
    }
   ]
  }
 ]
}"##,
    ),
];

#[test]
fn upstream_specification_examples_validate() {
    assert!(UPSTREAM_EXAMPLES.len() >= 15);
    for (title, doc) in UPSTREAM_EXAMPLES {
        assert_eq!(
            check(doc),
            Ok(()),
            "upstream example `{title}` must validate"
        );
    }
}

/// A minimal valid document with `patch` merged over it.
fn with(patch: &str) -> String {
    let mut base: serde_json::Value = serde_json::from_str(
        r#"{"name":"com.acme/weather","description":"Weather tools","version":"1.0.0",
            "remotes":[{"type":"streamable-http","url":"https://mcp.acme.test/mcp"}]}"#,
    )
    .unwrap();
    let patch: serde_json::Value = serde_json::from_str(patch).unwrap();
    for (k, v) in patch.as_object().unwrap() {
        base[k] = v.clone();
    }
    base.to_string()
}

fn refused_at(doc: &str) -> String {
    match check(doc) {
        Err(McpError::Invalid { path, .. }) => path,
        other => panic!("expected a 400 refusal, got {other:?} for {doc}"),
    }
}

#[test]
fn one_refusal_per_rule() {
    let cases: &[(&str, &str)] = &[
        (r#"{"name":"weather"}"#, "name"),
        (r#"{"name":"com.acme/../etc"}"#, "name"),
        (r#"{"name":"co"}"#, "name"),
        (r#"{"description":""}"#, "description"),
        (
            r#"{"description":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            "description",
        ),
        (r#"{"description":"Weather \u202e tools"}"#, "description"),
        (r#"{"title":"zero\u200bwidth"}"#, "title"),
        (r#"{"version":"latest"}"#, "version"),
        (r#"{"version":"^1.2.0"}"#, "version"),
        (r#"{"version":">=1.0.0 <2"}"#, "version"),
        (r#"{"version":"1.x"}"#, "version"),
        (r#"{"websiteUrl":"javascript:alert(1)"}"#, "websiteUrl"),
        (
            r#"{"repository":{"url":"file:///etc/passwd","source":"github"}}"#,
            "repository.url",
        ),
        (
            r#"{"icons":[{"src":"data:image/png;base64,AAAA"}]}"#,
            "icons[0].src",
        ),
        (r#"{"remotes":[]}"#, ""),
        (r#"{"remotes":[{"type":"stdio"}]}"#, "remotes[0].type"),
        (r#"{"remotes":[{"type":"sse"}]}"#, "remotes[0].url"),
        (
            r#"{"packages":[{"registryType":"maven","identifier":"x","transport":{"type":"stdio"}}]}"#,
            "packages[0].registryType",
        ),
        (
            r#"{"packages":[{"registryType":"npm","identifier":"x","transport":{"type":"stdio","url":"https://x.test"}}]}"#,
            "packages[0].transport",
        ),
        (
            r#"{"packages":[{"registryType":"npm","identifier":"x","transport":{"type":"streamable-http"}}]}"#,
            "packages[0].transport.url",
        ),
        (
            r#"{"packages":[{"registryType":"mcpb","identifier":"https://g.test/x.mcpb","transport":{"type":"stdio"}}]}"#,
            "packages[0].fileSha256",
        ),
        (
            r#"{"packages":[{"registryType":"npm","identifier":"x","fileSha256":"XYZ","transport":{"type":"stdio"}}]}"#,
            "packages[0].fileSha256",
        ),
        (
            r#"{"packages":[{"registryType":"npm","identifier":"x","transport":{"type":"stdio"},"runtimeArguments":[{"type":"named","name":"--a b"}]}]}"#,
            "packages[0].runtimeArguments[0].name",
        ),
        (
            r#"{"packages":[{"registryType":"npm","identifier":"x","transport":{"type":"stdio"},"environmentVariables":[{"name":"K","format":"url"}]}]}"#,
            "packages[0].environmentVariables[0].format",
        ),
        (r#"{"status":"active"}"#, ""),
    ];
    for (patch, path) in cases {
        assert_eq!(&refused_at(&with(patch)), path, "{patch}");
    }
}

#[test]
fn oci_entries_follow_the_identifier_table() {
    let oci = |id: &str, extra: &str| {
        with(&format!(
            r#"{{"remotes":[],"packages":[{{"registryType":"oci","identifier":"{id}","transport":{{"type":"stdio"}}{extra}}}]}}"#
        ))
    };
    let d64 = "a".repeat(64);
    assert_eq!(check(&oci("ghcr.io/acme/mcp:1.2", "")), Ok(()));
    assert_eq!(
        check(&oci(&format!("ghcr.io/acme/mcp:1.2@sha256:{d64}"), "")),
        Ok(())
    );
    assert_eq!(
        check(&oci(&format!("ghcr.io/acme/mcp@sha256:{d64}"), "")),
        Ok(())
    );
    assert_eq!(
        check(&oci(
            &format!("ghcr.io/acme/mcp@sha512:{}", "b".repeat(128)),
            ""
        )),
        Ok(())
    );
    assert_eq!(
        check(&oci(&format!("ghcr.io/acme/mcp:{}", "t".repeat(128)), "")),
        Ok(())
    );
    assert!(matches!(
        check(&oci(&format!("ghcr.io/acme/mcp:{}", "t".repeat(129)), "")),
        Err(McpError::Invalid { .. })
    ));
    assert_eq!(
        check(&oci("ghcr.io/acme/mcp:latest", "")),
        Err(McpError::OciFloatingTag { index: 0 })
    );
    assert_eq!(
        check(&oci("ghcr.io/acme/mcp", "")),
        Err(McpError::OciFloatingTag { index: 0 })
    );
    assert_eq!(
        check(&oci("ghcr.io/acme/mcp:1.2", r#","version":"1.2""#)),
        Err(McpError::OciLegacyFields { index: 0 })
    );
    assert_eq!(
        check(&oci(
            "ghcr.io/acme/mcp:1.2",
            r#","registryBaseUrl":"https://ghcr.io""#
        )),
        Err(McpError::OciLegacyFields { index: 0 })
    );

    let r = parse_oci_identifier("nginx:1.25").unwrap();
    assert_eq!(
        (r.host.as_str(), r.path.as_str()),
        ("docker.io", "library/nginx")
    );
    assert_eq!(
        parse_oci_identifier("ghcr.io/acme/mcp:latest"),
        Err(OciRefError::Floating)
    );
}

#[test]
fn caps_and_depth() {
    let deep = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
    assert!(matches!(
        parse_server_json(deep.as_bytes()),
        Err(McpError::Invalid { .. })
    ));
    let big = " ".repeat(256 * 1024 + 1);
    assert_eq!(parse_server_json(big.as_bytes()), Err(McpError::TooLarge));
    let remotes: Vec<String> = (0..9)
        .map(|i| format!(r#"{{"type":"sse","url":"https://x{i}.test"}}"#))
        .collect();
    assert_eq!(
        refused_at(&with(&format!(r#"{{"remotes":[{}]}}"#, remotes.join(",")))),
        "remotes"
    );
}
