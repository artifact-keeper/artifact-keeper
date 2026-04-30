use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn init_dtrack_creates_key_when_existing_team_key_is_masked() {
    let temp = tempfile::tempdir().unwrap();
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).unwrap();

    let curl_log = temp.path().join("curl.log");
    let api_key_file = temp.path().join("dtrack-api-key");

    let fake_curl = format!(
        r#"#!/bin/sh
printf '%s\n' "$*" >> "{}"

case "$*" in
  *"/api/version"*)
    echo '{{"version":"4.14.1"}}'
    ;;
  *"/api/v1/user/login"*)
    echo "test-token"
    ;;
  *"/api/v1/team/automation-team/key"*)
    echo '{{"key":"odt_full_secret"}}'
    ;;
  *"/api/v1/team"*)
    echo '[{{"name":"Automation","uuid":"automation-team","apiKeys":[{{"maskedKey":"odt_****abcd"}}]}}]'
    ;;
  *"/api/v1/configProperty"*)
    echo "200"
    ;;
  *)
    echo "unexpected curl call: $*" >&2
    exit 1
    ;;
esac
"#,
        curl_log.display()
    );
    write_executable(&bin_dir.join("curl"), &fake_curl);

    let fake_jq = r#"#!/bin/sh
filter="$2"
input="$(cat)"

case "$filter" in
  '.[] | select(.name == "Automation") | .apiKeys[0].key // empty')
    case "$input" in
      *'"key":"'*)
        printf '%s\n' "$input" | sed 's/.*"key":"\([^"]*\)".*/\1/'
        ;;
    esac
    ;;
  '.[] | select(.name == "Automation") | .uuid // empty')
    echo "automation-team"
    ;;
  '.key // empty')
    echo "odt_full_secret"
    ;;
  '.[].name')
    echo "Automation"
    ;;
  *)
    echo "unexpected jq filter: $filter" >&2
    exit 1
    ;;
esac
"#;
    write_executable(&bin_dir.join("jq"), fake_jq);

    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let output = Command::new("/bin/sh")
        .arg(repo_root().join("docker/init-dtrack.sh"))
        .env("PATH", path)
        .env("DEPENDENCY_TRACK_URL", "http://dtrack.test")
        .env("DEPENDENCY_TRACK_ADMIN_PASSWORD", "ArtifactKeeper2026!")
        .env("DTRACK_API_KEY_FILE", &api_key_file)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&api_key_file).unwrap(),
        "odt_full_secret\n"
    );

    let curl_calls = fs::read_to_string(curl_log).unwrap();
    assert!(
        curl_calls.contains("-X PUT http://dtrack.test/api/v1/team/automation-team/key"),
        "expected PUT key creation call, got:\n{curl_calls}"
    );
}
