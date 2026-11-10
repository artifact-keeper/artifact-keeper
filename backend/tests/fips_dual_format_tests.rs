//! Dual-format storage under FIPS mode (#5582, #5587): the upgrade / rollback
//! guarantee at the service layer.
//!
//! Every build reads both the legacy (bcrypt) and the module-backed (PBKDF2,
//! keyed HMAC) stored forms; only `FIPS_MODE=strict` writes the new ones and
//! migrates legacy rows on use. nextest runs each test in its own process,
//! so a test installs the mode it needs once and the whole process sees it.
//!
//! Requires PostgreSQL with all migrations applied:
//!
//! ```sh
//! DATABASE_URL="postgresql://registry:registry@localhost:5432/artifact_registry" \
//!     cargo nextest run --test fips_dual_format_tests --run-ignored ignored-only
//! ```

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::config::Config;
use artifact_keeper_backend::crypto::password;
use artifact_keeper_backend::crypto::token;
use artifact_keeper_backend::fips::{self, FipsMode};
use artifact_keeper_backend::services::auth_service::AuthService;

const PASSWORD: &str = "correct-horse-battery-staple-5582";

fn test_config() -> Arc<Config> {
    if std::env::var("JWT_SECRET").is_err() {
        std::env::set_var(
            "JWT_SECRET",
            "ak-5582-integration-test-jwt-secret-not-for-prod-use",
        );
    }
    Arc::new(Config::from_env().expect("Config::from_env failed"))
}

async fn pool() -> PgPool {
    PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("failed to connect to db")
}

/// Insert an active local user with the given stored password hash.
async fn insert_user(pool: &PgPool, suffix: &str, password_hash: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("ak5582-{suffix}-{}", &id.to_string()[..8]);
    let email = format!("{username}@test.local");
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, is_admin, is_active, auth_provider) \
         VALUES ($1, $2, $3, $4, false, true, 'local')",
    )
    .bind(id)
    .bind(&username)
    .bind(&email)
    .bind(password_hash)
    .execute(pool)
    .await
    .expect("insert user");
    (id, username)
}

async fn stored_hash(pool: &PgPool, user_id: Uuid) -> String {
    sqlx::query_scalar::<_, Option<String>>("SELECT password_hash FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("read hash")
        .expect("hash present")
}

async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

/// The database-backed policy check runs against the real schema: a fresh
/// database has no provider allowing legacy RSA keys, so no violation, and
/// in particular no `policy-check-failed` from a mistyped table name (a
/// strict-mode deployment refused to start on exactly that once).
#[tokio::test]
#[ignore]
async fn db_violations_query_matches_the_schema() {
    let pool = pool().await;
    let violations = fips::db_violations(FipsMode::Strict, &pool).await;
    assert!(
        violations.is_empty(),
        "fresh schema must yield no violations, got {violations:?}"
    );
    assert!(fips::db_violations(FipsMode::Off, &pool).await.is_empty());
}

/// Default mode: bcrypt is still what gets written, and a PBKDF2 hash that a
/// strict-mode deployment wrote earlier still logs in (forward readability
/// across a downgrade).
#[tokio::test]
#[ignore]
async fn off_mode_writes_bcrypt_and_reads_pbkdf2() {
    assert_eq!(fips::mode(), FipsMode::Off);
    let pool = pool().await;
    let auth = AuthService::new(pool.clone(), test_config());

    let written = AuthService::hash_password(PASSWORD).await.expect("hash");
    assert_eq!(
        password::format_of(&written),
        Ok(password::Format::Bcrypt),
        "off mode must keep writing bcrypt: {written}"
    );

    let pbkdf2 = password::hash_pbkdf2_with(PASSWORD, 1_000);
    let (user_id, username) = insert_user(&pool, "pbkdf2-read", &pbkdf2).await;
    let login = auth.authenticate(&username, PASSWORD).await;
    assert!(
        login.is_ok(),
        "PBKDF2 hash must verify in off mode: {login:?}"
    );
    assert!(auth.authenticate(&username, "wrong").await.is_err());
    // Nothing is rewritten outside strict mode.
    assert_eq!(stored_hash(&pool, user_id).await, pbkdf2);

    cleanup_user(&pool, user_id).await;
}

/// Strict mode: a legacy bcrypt user logs in, is migrated to PBKDF2 on that
/// login, keeps logging in, and the old hash would still verify if the
/// deployment rolled back before the migration.
#[tokio::test]
#[ignore]
async fn strict_mode_migrates_legacy_bcrypt_user_on_login() {
    fips::install(FipsMode::Strict, Vec::new()).expect("no violations passed");
    assert!(fips::strict());
    let pool = pool().await;
    let auth = AuthService::new(pool.clone(), test_config());

    let legacy = password::hash_bcrypt(PASSWORD, 4).expect("bcrypt");
    let (user_id, username) = insert_user(&pool, "bcrypt-migrate", &legacy).await;

    auth.authenticate(&username, PASSWORD)
        .await
        .expect("legacy bcrypt user logs in under strict mode");
    let migrated = stored_hash(&pool, user_id).await;
    assert_eq!(
        password::format_of(&migrated),
        Ok(password::Format::Pbkdf2Sha512),
        "strict mode must rehash on login: {migrated}"
    );
    assert_ne!(migrated, legacy);

    auth.authenticate(&username, PASSWORD)
        .await
        .expect("migrated user still logs in");
    assert!(auth.authenticate(&username, "wrong").await.is_err());

    // Rollback safety: the pre-migration hash remains verifiable by any build.
    assert_eq!(password::verify(PASSWORD, &legacy), Ok(true));
    // And a wrong password against the new hash is still a miss, not an error.
    assert_eq!(password::verify("wrong", &migrated), Ok(false));

    cleanup_user(&pool, user_id).await;
}

/// Strict mode: an API token stored as bcrypt by an older build validates,
/// is rewritten as a keyed HMAC on first use, and keeps validating.
#[tokio::test]
#[ignore]
async fn strict_mode_migrates_legacy_api_token_on_use() {
    fips::install(FipsMode::Strict, Vec::new()).expect("no violations passed");
    let pool = pool().await;
    let config = test_config();
    let auth = AuthService::new(pool.clone(), config.clone());

    let (user_id, _username) =
        insert_user(&pool, "token", &password::hash_pbkdf2_with(PASSWORD, 1_000)).await;

    // What an older (non-strict) build would have stored.
    let secret = format!("{}_{}", "ab12cd34", "0123456789abcdef0123456789abcdef");
    let legacy_hash = password::hash_bcrypt(&secret, 4).expect("bcrypt");
    let token_id: Uuid = sqlx::query_scalar(
        "INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at) \
         VALUES ($1, $2, $3, $4, $5, NULL) RETURNING id",
    )
    .bind(user_id)
    .bind("legacy-token")
    .bind(&legacy_hash)
    .bind(&secret[..8])
    .bind(vec!["read:artifacts".to_string()])
    .fetch_one(&pool)
    .await
    .expect("insert legacy token");

    auth.validate_api_token(&secret)
        .await
        .expect("legacy bcrypt token validates in strict mode");

    let stored: String = sqlx::query_scalar("SELECT token_hash FROM api_tokens WHERE id = $1")
        .bind(token_id)
        .fetch_one(&pool)
        .await
        .expect("read token hash");
    assert!(
        token::is_hmac(&stored),
        "token must migrate to the keyed form: {stored}"
    );
    assert!(token::TokenKey::derive(config.jwt_secret.as_bytes())
        .verify(&secret, &stored)
        .expect("hmac form parses"));

    // Second use goes through the HMAC path (the cache is bypassed by a
    // fresh service instance).
    let fresh = AuthService::new(pool.clone(), config.clone());
    fresh
        .validate_api_token(&secret)
        .await
        .expect("migrated token validates");
    assert!(fresh.validate_api_token("ab12cd34_wrong").await.is_err());

    // New tokens minted in strict mode are written in the keyed form directly.
    let (minted, minted_id) = auth
        .generate_api_token(user_id, "fresh", vec!["read:artifacts".to_string()], None)
        .await
        .expect("mint");
    let minted_hash: String = sqlx::query_scalar("SELECT token_hash FROM api_tokens WHERE id = $1")
        .bind(minted_id)
        .fetch_one(&pool)
        .await
        .expect("read minted hash");
    assert!(token::is_hmac(&minted_hash));
    assert_eq!(
        minted.len(),
        8 + 1 + 64,
        "strict-mode tokens carry a 256-bit secret"
    );

    cleanup_user(&pool, user_id).await;
}
