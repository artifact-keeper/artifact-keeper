//! Per-query database `CLIENT` spans built from sqlx's own query events
//! (#3954 §2, #4455).
//!
//! sqlx already reports every statement it runs, as a `tracing` EVENT on the
//! `sqlx::query` target carrying `summary`, `db.statement`, `rows_returned`
//! and `elapsed_secs` (`sqlx_core::logger::QueryLogger`, emitted when the
//! query finishes). `tracing-opentelemetry` exports such an event as a span
//! event on whatever span was current, so the time is visible only by parsing
//! event payloads one trace at a time. [`DbQuerySpanLayer`] turns each of
//! those events into a real OTel `CLIENT` span instead, backdated by
//! `elapsed_secs`, parented to the span the query ran under, and carrying the
//! database semantic conventions:
//!
//! * name `db.query.summary`: `"{operation} {table}"` (e.g. `SELECT
//!   repositories`), or just the operation when no table is recognisable;
//! * `db.system.name = "postgresql"`, `db.operation.name`,
//!   `db.collection.name` (when recognised), `db.response.returned_rows`;
//! * `artifact_keeper.db.slow_statement = true` when sqlx flagged the
//!   statement as slow.
//!
//! The statement text is deliberately NOT copied onto the span: it can carry
//! literal values when a query is built with `format!`, and it is already
//! exported on the parent span's event for anyone who enables it.
//!
//! This costs no call-site changes and no new dependency, and it is bounded:
//!
//! * The layer is installed only on the OTLP path (`init_with_otel`).
//! * It sees only the events the global `EnvFilter` lets through. The default
//!   filter keeps `sqlx::query=info`, so out of the box only statements sqlx
//!   reports as SLOW (WARN, over its 1 s default threshold) become spans. A
//!   span for every statement needs `sqlx::query=debug` in `RUST_LOG`, which
//!   also logs every statement on stdout.
//! * A query with no OTel-backed parent span (startup, a background job outside
//!   any span) produces nothing, so background work does not open one root
//!   trace per statement.
//! * The table name is a best-effort token scan (the first `FROM` / `INTO` /
//!   `UPDATE` target), not a SQL parser; a sub-select's table can win.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use opentelemetry::trace::{Span as _, SpanKind, TraceContextExt, Tracer};
use opentelemetry::KeyValue;
use tracing::dispatcher::WeakDispatch;
use tracing::field::{Field, Visit};
use tracing::{Dispatch, Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// The target sqlx emits its per-statement events on.
const SQLX_QUERY_TARGET: &str = "sqlx::query";

/// Longest identifier accepted as a table name; anything longer is not one.
const MAX_IDENTIFIER_LEN: usize = 63;

/// Converts `sqlx::query` events into backdated OTel `CLIENT` spans.
pub(crate) struct DbQuerySpanLayer<T> {
    tracer: T,
    /// The dispatch this layer is part of, needed to look up the OTel context
    /// of a tracing span (`tracing_opentelemetry::get_otel_context`).
    dispatch: OnceLock<WeakDispatch>,
}

impl<T> DbQuerySpanLayer<T> {
    pub(crate) fn new(tracer: T) -> Self {
        Self {
            tracer,
            dispatch: OnceLock::new(),
        }
    }
}

impl<S, T> Layer<S> for DbQuerySpanLayer<T>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    T: Tracer + Send + Sync + 'static,
    T::Span: Send + Sync + 'static,
{
    fn on_register_dispatch(&self, subscriber: &Dispatch) {
        let _ = self.dispatch.set(subscriber.downgrade());
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != SQLX_QUERY_TARGET {
            return;
        }
        let mut fields = QueryEventFields::default();
        event.record(&mut fields);
        let Some(elapsed) = fields.elapsed() else {
            return;
        };
        let Some(parent_id) = ctx.event_span(event).map(|span| span.id()) else {
            return;
        };
        let Some(dispatch) = self.dispatch.get().and_then(WeakDispatch::upgrade) else {
            return;
        };
        let Some(parent_cx) = tracing_opentelemetry::get_otel_context(&parent_id, &dispatch) else {
            return;
        };
        if !parent_cx.span().span_context().is_valid() {
            return;
        }

        let end = SystemTime::now();
        let start = end.checked_sub(elapsed).unwrap_or(end);
        let summary = QuerySummary::parse(fields.sql());
        let mut span = self
            .tracer
            .span_builder(summary.span_name())
            .with_kind(SpanKind::Client)
            .with_start_time(start)
            .with_attributes(summary.attributes(&fields))
            .start_with_context(&self.tracer, &parent_cx);
        span.end_with_timestamp(end);
    }
}

/// The fields of one sqlx query event this layer uses.
#[derive(Debug, Default)]
struct QueryEventFields {
    summary: String,
    statement: String,
    rows_returned: Option<u64>,
    elapsed_secs: Option<f64>,
    slow: bool,
}

impl QueryEventFields {
    /// The statement duration, if the event carried a usable one.
    fn elapsed(&self) -> Option<Duration> {
        self.elapsed_secs
            .filter(|secs| secs.is_finite() && *secs >= 0.0)
            .map(Duration::from_secs_f64)
    }

    /// The SQL to classify. sqlx puts the full text in `db.statement` only
    /// when it is longer than the four-word `summary` (which then ends in
    /// `" …"`); otherwise `summary` IS the statement.
    fn sql(&self) -> &str {
        let statement = self.statement.trim();
        if statement.is_empty() {
            self.summary.trim_end_matches('…').trim()
        } else {
            statement
        }
    }
}

impl Visit for QueryEventFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "summary" => self.summary = value.to_string(),
            "db.statement" => self.statement = value.to_string(),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "rows_returned" {
            self.rows_returned = Some(value);
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if field.name() == "elapsed_secs" {
            self.elapsed_secs = Some(value);
        }
    }

    fn record_debug(&mut self, field: &Field, _value: &dyn std::fmt::Debug) {
        // Present only on sqlx's slow-statement event.
        if field.name() == "slow_threshold" {
            self.slow = true;
        }
    }
}

/// Operation and table of a statement, for the span name and attributes.
#[derive(Debug, PartialEq, Eq)]
struct QuerySummary {
    operation: Option<String>,
    table: Option<String>,
}

impl QuerySummary {
    fn parse(sql: &str) -> Self {
        let tokens = tokens_outside_literals(sql);
        let operation = tokens
            .first()
            .filter(|t| t.len() <= 16 && t.chars().all(|c| c.is_ascii_alphabetic()))
            .map(|t| t.to_ascii_uppercase());
        let keyword = match operation.as_deref() {
            Some("SELECT") | Some("DELETE") => Some("FROM"),
            Some("INSERT") => Some("INTO"),
            Some("UPDATE") => Some("UPDATE"),
            _ => None,
        };
        let table = keyword.and_then(|keyword| {
            let at = tokens
                .iter()
                .position(|t| t.eq_ignore_ascii_case(keyword))?;
            table_identifier(tokens.get(at + 1)?)
        });
        Self { operation, table }
    }

    /// `db.query.summary`, which is also the span name. Falls back to the
    /// database system when not even the operation is recognisable.
    fn span_name(&self) -> String {
        match (&self.operation, &self.table) {
            (Some(op), Some(table)) => format!("{op} {table}"),
            (Some(op), None) => op.clone(),
            (None, _) => "postgresql".to_string(),
        }
    }

    fn attributes(&self, fields: &QueryEventFields) -> Vec<KeyValue> {
        let mut attrs = vec![
            KeyValue::new("db.system.name", "postgresql"),
            KeyValue::new("db.query.summary", self.span_name()),
        ];
        if let Some(op) = &self.operation {
            attrs.push(KeyValue::new("db.operation.name", op.clone()));
        }
        if let Some(table) = &self.table {
            attrs.push(KeyValue::new("db.collection.name", table.clone()));
        }
        if let Some(rows) = fields.rows_returned {
            attrs.push(KeyValue::new(
                "db.response.returned_rows",
                i64::try_from(rows).unwrap_or(i64::MAX),
            ));
        }
        if fields.slow {
            attrs.push(KeyValue::new("artifact_keeper.db.slow_statement", true));
        }
        attrs
    }
}

/// The whitespace-separated tokens of `sql` that lie outside single-quoted
/// string literals, so a word inside a literal (`'a from secret b'`) can never
/// be taken for the `FROM` keyword or a table. A token containing a quote is
/// dropped too; it is never an identifier. `''` escapes inside a literal
/// toggle twice and so leave the state unchanged.
fn tokens_outside_literals(sql: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut in_literal = false;
    for token in sql.split_whitespace() {
        let quotes = token.matches('\'').count();
        if !in_literal && quotes == 0 {
            tokens.push(token);
        }
        if quotes % 2 == 1 {
            in_literal = !in_literal;
        }
    }
    tokens
}

/// The table name at the start of `token` (`repositories`, `public.users`,
/// `"quoted"`), cut at the first `(`, `,` or `;`. `None` for a sub-select
/// (`(SELECT`) or anything that is not a plain identifier, so a literal can
/// never become an attribute value.
fn table_identifier(token: &str) -> Option<String> {
    let end = token.find(['(', ',', ';', ')']).unwrap_or(token.len());
    let name = token[..end].replace('"', "");
    let valid = !name.is_empty()
        && name.len() <= MAX_IDENTIFIER_LEN
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    valid.then_some(name)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::otel::{attr, otel_subscriber, ExportedSpans};
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn parses_operation_and_table() {
        let cases = [
            (
                "SELECT id, key FROM repositories WHERE key = $1",
                "SELECT repositories",
            ),
            (
                "select * from public.artifacts where id = $1",
                "SELECT public.artifacts",
            ),
            (
                "INSERT INTO audit_log(id, action) VALUES ($1, $2)",
                "INSERT audit_log",
            ),
            ("UPDATE \"users\" SET name = $1", "UPDATE users"),
            ("DELETE FROM sessions; ", "DELETE sessions"),
            ("SELECT 1", "SELECT"),
            ("SELECT x FROM (SELECT 1) s", "SELECT"),
            ("WITH t AS (SELECT 1) SELECT * FROM t", "WITH"),
            ("BEGIN", "BEGIN"),
            ("", "postgresql"),
            ("(SELECT 1)", "postgresql"),
            // A word inside a string literal is never the keyword or table.
            ("SELECT 'a from secretword b' FROM t", "SELECT t"),
            ("SELECT 'it''s from x' FROM t", "SELECT t"),
            ("SELECT 'from' FROM t", "SELECT t"),
        ];
        for (sql, name) in cases {
            assert_eq!(QuerySummary::parse(sql).span_name(), name, "for {sql:?}");
        }
    }

    #[test]
    fn a_literal_or_overlong_token_is_never_a_table() {
        assert_eq!(table_identifier("'secret'"), None);
        assert_eq!(table_identifier("$1"), None);
        assert_eq!(table_identifier("1abc"), None);
        assert_eq!(table_identifier(&"a".repeat(64)), None);
        assert_eq!(table_identifier("ok_table,"), Some("ok_table".into()));
    }

    #[test]
    fn sql_prefers_the_full_statement_over_the_summary() {
        let short = QueryEventFields {
            summary: "SELECT 1".into(),
            ..Default::default()
        };
        assert_eq!(short.sql(), "SELECT 1");
        let long = QueryEventFields {
            summary: "SELECT id, key FROM …".into(),
            statement: "\n\nSELECT id, key FROM repositories WHERE id = $1\n".into(),
            ..Default::default()
        };
        assert_eq!(long.sql(), "SELECT id, key FROM repositories WHERE id = $1");
        let truncated_only = QueryEventFields {
            summary: "SELECT id FROM t …".into(),
            ..Default::default()
        };
        assert_eq!(truncated_only.sql(), "SELECT id FROM t");
    }

    #[test]
    fn elapsed_rejects_unusable_values() {
        let with = |secs| QueryEventFields {
            elapsed_secs: Some(secs),
            ..Default::default()
        };
        assert_eq!(with(0.25).elapsed(), Some(Duration::from_millis(250)));
        assert_eq!(with(-1.0).elapsed(), None);
        assert_eq!(with(f64::NAN).elapsed(), None);
        assert_eq!(QueryEventFields::default().elapsed(), None);
    }

    /// Run `f` under a subscriber with the real `tracing-opentelemetry` layer
    /// and the DB span layer, both exporting to the returned spans.
    fn run_exporting(f: impl FnOnce()) -> ExportedSpans {
        let exported = ExportedSpans::default();
        tracing::subscriber::with_default(subscriber(&exported), f);
        exported
    }

    fn subscriber(exported: &ExportedSpans) -> impl tracing::Subscriber + Send + Sync {
        otel_subscriber(exported).with(DbQuerySpanLayer::new(exported.tracer()))
    }

    /// An event shaped exactly like sqlx's `QueryLogger::finish` output.
    fn emit_sqlx_event(summary: &str, statement: &str, elapsed_secs: f64) {
        tracing::event!(
            target: "sqlx::query",
            tracing::Level::DEBUG,
            summary,
            db.statement = statement,
            rows_affected = 0u64,
            rows_returned = 3u64,
            elapsed = ?Duration::from_secs_f64(elapsed_secs),
            elapsed_secs,
        );
    }

    #[test]
    fn a_query_event_becomes_a_backdated_client_child_span() {
        let exported = run_exporting(|| {
            let request = tracing::info_span!("http_request");
            let _entered = request.enter();
            emit_sqlx_event(
                "SELECT id, key FROM …",
                "\n\nSELECT id, key FROM repositories WHERE key = $1\n",
                0.5,
            );
        });

        let db = exported.named("SELECT repositories");
        assert_eq!(db.len(), 1, "exactly one DB span expected");
        let db = &db[0];
        let parent = &exported.named("http_request")[0];
        assert_eq!(db.span_kind, SpanKind::Client);
        assert_eq!(db.parent_span_id, parent.span_context.span_id());
        assert_eq!(db.span_context.trace_id(), parent.span_context.trace_id());
        let took = db.end_time.duration_since(db.start_time).unwrap();
        assert!(
            (took.as_secs_f64() - 0.5).abs() < 0.05,
            "backdated by elapsed_secs, got {took:?}"
        );
        assert_eq!(
            attr(db, "db.system.name"),
            Some(opentelemetry::Value::from("postgresql"))
        );
        assert_eq!(
            attr(db, "db.operation.name"),
            Some(opentelemetry::Value::from("SELECT"))
        );
        assert_eq!(
            attr(db, "db.collection.name"),
            Some(opentelemetry::Value::from("repositories"))
        );
        assert_eq!(
            attr(db, "db.response.returned_rows"),
            Some(opentelemetry::Value::I64(3))
        );
        assert_eq!(attr(db, "artifact_keeper.db.slow_statement"), None);
        // The statement text stays off the span.
        assert!(db
            .attributes
            .iter()
            .all(|kv| !kv.value.as_str().contains("WHERE key")));
    }

    #[test]
    fn a_slow_statement_is_flagged() {
        let exported = run_exporting(|| {
            let _entered = tracing::info_span!("job").entered();
            tracing::event!(
                target: "sqlx::query",
                tracing::Level::WARN,
                summary = "UPDATE artifacts SET size …",
                db.statement = "\n\nUPDATE artifacts SET size = $1\n",
                rows_affected = 1u64,
                rows_returned = 0u64,
                elapsed_secs = 2.0f64,
                slow_threshold = ?Duration::from_secs(1),
                "slow statement: execution time exceeded alert threshold"
            );
        });
        let db = &exported.named("UPDATE artifacts")[0];
        assert_eq!(
            attr(db, "artifact_keeper.db.slow_statement"),
            Some(opentelemetry::Value::Bool(true))
        );
    }

    #[test]
    fn no_span_without_a_parent_or_for_other_targets() {
        let exported = run_exporting(|| {
            // No current span: background work must not open a root trace
            // per statement.
            emit_sqlx_event("SELECT 1", "", 0.01);
            let _entered = tracing::info_span!("http_request").entered();
            // Another target with the same fields is ignored.
            tracing::event!(
                target: "artifact_keeper_backend::db",
                tracing::Level::INFO,
                summary = "SELECT 1",
                elapsed_secs = 0.01f64,
            );
            // An event without a usable duration is ignored.
            tracing::event!(
                target: "sqlx::query",
                tracing::Level::DEBUG,
                summary = "SELECT 1",
            );
        });
        assert!(exported.named("SELECT").is_empty());
    }

    /// The real thing: a query through sqlx itself, so a change in sqlx's
    /// event shape (field names, emission point) is caught here.
    #[tokio::test(flavor = "current_thread")]
    async fn a_real_sqlx_query_produces_a_db_span() {
        let Some(pool) = crate::testing::try_pool_with(1).await else {
            return;
        };
        let exported = ExportedSpans::default();
        let _guard = tracing::subscriber::set_default(subscriber(&exported));
        {
            use tracing::Instrument;
            sqlx::query("SELECT 1 AS one")
                .fetch_all(&pool)
                .instrument(tracing::info_span!("http_request"))
                .await
                .unwrap();
        }
        let db = exported.named("SELECT");
        assert!(
            db.iter().any(|span| span.span_kind == SpanKind::Client
                && attr(span, "db.response.returned_rows") == Some(opentelemetry::Value::I64(1))),
            "a CLIENT span for `SELECT 1 AS one`, got {db:?}"
        );
    }
}
