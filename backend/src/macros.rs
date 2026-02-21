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
    // Uses is_some() to avoid accessing the inner value, preventing
    // taint-analysis tools from flagging this as cleartext logging.
    (@add_field $s:ident, $self:ident, redact_option, $field:ident) => {
        if $self.$field.is_some() {
            $s.field(stringify!($field), &"[REDACTED]");
        } else {
            $s.field(stringify!($field), &Option::<&str>::None);
        }
    };
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    struct TestStruct {
        pub name: String,
        pub hidden: String,
        pub optional_hidden: Option<String>,
    }

    redacted_debug!(TestStruct {
        show name,
        redact hidden,
        redact_option optional_hidden,
    });

    #[test]
    fn test_redacted_debug_hides_redacted_field() {
        let s = TestStruct {
            name: "visible".to_string(),
            hidden: "do-not-show-this".to_string(),
            optional_hidden: Some("also-do-not-show".to_string()),
        };
        let output = format!("{:?}", s);
        assert!(output.contains("visible"), "should show normal fields");
        assert!(
            !output.contains("do-not-show-this"),
            "should not leak redacted field"
        );
        assert!(
            !output.contains("also-do-not-show"),
            "should not leak optional redacted field"
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
            hidden: "nope".to_string(),
            optional_hidden: None,
        };
        let output = format!("{:?}", s);
        assert!(
            output.contains("None"),
            "should show None for missing optional"
        );
        assert!(!output.contains("nope"), "should not leak redacted field");
    }
}
