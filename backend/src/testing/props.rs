//! Property-test support: generators and law checkers shared by the inline
//! `proptest!` suites.
//!
//! The hand-picked corpora in the unit tests pin the cases someone already
//! thought of. These helpers let a module state a law ("this comparator is a
//! total order") and have `proptest` search for the input that breaks it, then
//! shrink that input to the smallest reproducer.

use std::cmp::Ordering;
use std::fmt::Debug;

use proptest::prelude::*;

/// A version-shaped string built from a deliberately tiny alphabet, so that
/// independent draws collide on prefixes and segments often enough to reach
/// the interesting comparisons (`2` / `10` / `1a`, `1` / `1.0`, `01` / `1`).
pub(crate) fn version_like() -> impl Strategy<Value = String> {
    let token = prop_oneof![
        4 => "[0-9]{1,3}",
        1 => "0[0-9]",
        1 => "[0-9]{19,21}",
        2 => "[a-c]{1,2}",
        2 => "[0-9][a-c]",
        2 => "[a-c][0-9]",
        6 => Just(".".to_string()),
        2 => Just("-".to_string()),
        1 => "[+_:!~]",
    ];
    proptest::collection::vec(token, 0..8).prop_map(|tokens| tokens.concat())
}

/// Three independent [`version_like`] strings.
pub(crate) fn version_triple() -> impl Strategy<Value = (String, String, String)> {
    (version_like(), version_like(), version_like())
}

/// Check the total-order laws for `cmp` on one triple: reflexivity,
/// antisymmetry (`cmp(a, b)` is the reverse of `cmp(b, a)`) and transitivity
/// (`a <= b <= c` implies `a <= c`, over every rotation of the triple).
///
/// `sort_by` may panic on a comparator that breaks these, and a range check
/// built on one can put a version on the wrong side of a bound.
pub(crate) fn check_total_order<T, F>(a: &T, b: &T, c: &T, cmp: F) -> Result<(), TestCaseError>
where
    T: Debug + ?Sized,
    F: Fn(&T, &T) -> Ordering,
{
    for x in [a, b, c] {
        prop_assert_eq!(cmp(x, x), Ordering::Equal, "{:?} must equal itself", x);
    }
    for (x, y) in [(a, b), (b, c), (a, c)] {
        prop_assert_eq!(
            cmp(x, y),
            cmp(y, x).reverse(),
            "{:?} vs {:?} is not antisymmetric",
            x,
            y
        );
    }
    for (x, y, z) in [
        (a, b, c),
        (a, c, b),
        (b, a, c),
        (b, c, a),
        (c, a, b),
        (c, b, a),
    ] {
        if cmp(x, y) != Ordering::Greater && cmp(y, z) != Ordering::Greater {
            prop_assert_ne!(
                cmp(x, z),
                Ordering::Greater,
                "not transitive: {:?} <= {:?} <= {:?}",
                x,
                y,
                z
            );
        }
    }
    Ok(())
}

/// Declare a `#[test]` asserting that `$cmp` (a `Fn(&str, &str) -> Ordering`)
/// is a total order over [`version_triple`].
macro_rules! total_order_proptest {
    ($name:ident, $cmp:expr) => {
        proptest::proptest! {
            #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4000))]
            #[test]
            fn $name((a, b, c) in $crate::testing::props::version_triple()) {
                $crate::testing::props::check_total_order(a.as_str(), b.as_str(), c.as_str(), $cmp)?;
            }
        }
    };
}
pub(crate) use total_order_proptest;
