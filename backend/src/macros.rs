//! Shared macros for the backend crate.

/// Generate a `fmt::Debug` implementation that redacts sensitive fields.
///
/// Three field kinds are supported, specified as a keyword before the field name:
///
/// - `show field_name` - prints the field value normally
/// - `redact field_name` - prints `"[REDACTED]"` instead of the value
/// - `redact_option field_name` - prints `Some("[REDACTED]")` or `None`
///
/// # Example
///
/// ```ignore
/// redacted_debug!(MyConfig {
///     show url,
///     show username,
///     redact_option password,
///     redact api_key,
/// });
/// ```
macro_rules! redacted_debug {
    ($name:ident { $( $kind:ident $field:ident ),* $(,)? }) => {
        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                let mut s = f.debug_struct(stringify!($name));
                $( redacted_debug!(@add_field s, self, $kind, $field); )*
                s.finish_non_exhaustive()
            }
        }
    };
    (@add_field $s:ident, $self:ident, show, $field:ident) => {
        $s.field(stringify!($field), &$self.$field);
    };
    (@add_field $s:ident, $self:ident, redact, $field:ident) => {
        $s.field(stringify!($field), &"[REDACTED]");
    };
    (@add_field $s:ident, $self:ident, redact_option, $field:ident) => {
        $s.field(stringify!($field), &$self.$field.as_ref().map(|_| "[REDACTED]"));
    };
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    struct TestStruct {
        pub name: String,
        pub secret: String,
        pub optional_secret: Option<String>,
    }

    redacted_debug!(TestStruct {
        show name,
        redact secret,
        redact_option optional_secret,
    });

    #[test]
    fn test_redacted_debug_hides_secret_field() {
        let s = TestStruct {
            name: "visible".to_string(),
            secret: "super-secret-value".to_string(),
            optional_secret: Some("another-secret".to_string()),
        };
        let output = format!("{:?}", s);
        assert!(output.contains("visible"), "should show normal fields");
        assert!(
            !output.contains("super-secret-value"),
            "should not leak secret"
        );
        assert!(
            !output.contains("another-secret"),
            "should not leak optional secret"
        );
        assert!(
            output.contains("[REDACTED]"),
            "should contain redaction marker"
        );
    }

    #[test]
    fn test_redacted_debug_option_none() {
        let s = TestStruct {
            name: "test".to_string(),
            secret: "hidden".to_string(),
            optional_secret: None,
        };
        let output = format!("{:?}", s);
        assert!(
            output.contains("None"),
            "should show None for missing optional"
        );
        assert!(!output.contains("hidden"), "should not leak secret");
    }
}
