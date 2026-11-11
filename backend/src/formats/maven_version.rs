//! Maven version comparison implementing the ComparableVersion algorithm.
//!
//! Port of org.apache.maven.artifact.versioning.ComparableVersion from Maven.
//! See: https://maven.apache.org/ref/3.9.6/maven-artifact/
//!
//! The parser, `normalize` and every `compareTo` follow the 3.9.6 source
//! branch for branch, and `maven_reference_vectors` pins the ordering of a
//! corpus that was sorted by the real `ComparableVersion`.

use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct MavenVersion {
    canonical: String,
    items: ListItem,
}

/// One parsed component. Mirrors `ComparableVersion.Item`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    /// A run of ASCII digits with leading zeros stripped (`"0"` for zero).
    /// Kept as text and compared by length then digits, so a number of any
    /// size compares by value: Maven's `IntItem` < `LongItem` <
    /// `BigIntegerItem` ranking is the same ordering.
    Int(String),
    /// A qualifier, already alias-resolved (`ga` / `final` / `release` are
    /// `""`, `cr` is `rc`).
    String(String),
    List(ListItem),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListItem(Vec<Item>);

/// `StringItem.QUALIFIERS`: the index is the rank.
const QUALIFIERS: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

/// `StringItem.comparableQualifier`: a known qualifier is its rank, an unknown
/// one is `7-<qualifier>`, and the results are compared as strings. So known
/// qualifiers order by rank, every unknown one ranks above them, and unknown
/// ones order lexically.
fn comparable_qualifier(qualifier: &str) -> String {
    match QUALIFIERS.iter().position(|q| *q == qualifier) {
        Some(rank) => rank.to_string(),
        None => format!("{}-{qualifier}", QUALIFIERS.len()),
    }
}

/// `comparableQualifier("")`, the release rank everything is measured against.
const RELEASE_QUALIFIER: &str = "5";

/// `new StringItem(value, followedByDigit)`.
fn string_item(value: &str, followed_by_digit: bool) -> Item {
    let value = match value {
        "a" if followed_by_digit => "alpha",
        "b" if followed_by_digit => "beta",
        "m" if followed_by_digit => "milestone",
        other => other,
    };
    let value = match value {
        "ga" | "final" | "release" => "",
        "cr" => "rc",
        other => other,
    };
    Item::String(value.to_string())
}

/// `parseItem(isDigit, buf)`.
fn parse_item(is_digit: bool, buf: &str) -> Item {
    if is_digit {
        let stripped = buf.trim_start_matches('0');
        Item::Int(if stripped.is_empty() { "0" } else { stripped }.to_string())
    } else {
        string_item(buf, false)
    }
}

impl Item {
    /// `Item.isNull()`.
    fn is_null(&self) -> bool {
        match self {
            Item::Int(digits) => digits == "0",
            Item::String(q) => comparable_qualifier(q) == RELEASE_QUALIFIER,
            Item::List(list) => list.0.is_empty(),
        }
    }

    /// `Item.compareTo(item)`, where `None` is Java's `null` (the other side
    /// ran out of items).
    fn compare_to(&self, other: Option<&Item>) -> Ordering {
        match (self, other) {
            (Item::Int(digits), None) => {
                if digits == "0" {
                    Ordering::Equal // 1.0 == 1
                } else {
                    Ordering::Greater // 1.1 > 1
                }
            }
            (Item::Int(a), Some(Item::Int(b))) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (Item::Int(_), Some(Item::String(_))) => Ordering::Greater, // 1.1 > 1-sp
            (Item::Int(_), Some(Item::List(_))) => Ordering::Greater,   // 1.1 > 1-1

            (Item::String(q), None) => comparable_qualifier(q).as_str().cmp(RELEASE_QUALIFIER),
            (Item::String(_), Some(Item::Int(_))) => Ordering::Less, // 1.any < 1.1
            (Item::String(a), Some(Item::String(b))) => {
                comparable_qualifier(a).cmp(&comparable_qualifier(b))
            }
            (Item::String(_), Some(Item::List(_))) => Ordering::Less, // 1.any < 1-1

            // 1-0 == 1; otherwise the first item that differs from nothing decides.
            (Item::List(list), None) => list
                .0
                .iter()
                .map(|item| item.compare_to(None))
                .find(|ord| *ord != Ordering::Equal)
                .unwrap_or(Ordering::Equal),
            (Item::List(_), Some(Item::Int(_))) => Ordering::Less, // 1-1 < 1.0.x
            (Item::List(_), Some(Item::String(_))) => Ordering::Greater, // 1-1 > 1-sp
            (Item::List(a), Some(Item::List(b))) => a.compare_to(b),
        }
    }
}

impl ListItem {
    /// `ListItem.normalize()`: drop null items from the end, looking past
    /// nested lists, so `1.0-snapshot` and `1-snapshot` parse alike.
    fn normalize(&mut self) {
        for i in (0..self.0.len()).rev() {
            if self.0[i].is_null() {
                self.0.remove(i);
            } else if !matches!(self.0[i], Item::List(_)) {
                break;
            }
        }
    }

    /// `ListItem.compareTo(ListItem)`: item by item, a missing item is `null`.
    fn compare_to(&self, other: &ListItem) -> Ordering {
        for i in 0..self.0.len().max(other.0.len()) {
            let ord = match (self.0.get(i), other.0.get(i)) {
                (Some(l), r) => l.compare_to(r),
                (None, Some(r)) => r.compare_to(None).reverse(),
                (None, None) => Ordering::Equal,
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}

impl MavenVersion {
    pub fn parse(version: &str) -> Self {
        let items = Self::parse_items(&version.to_lowercase());
        let canonical = items.to_string();
        MavenVersion { canonical, items }
    }

    /// `ComparableVersion.parseVersion`, branch for branch.
    ///
    /// Java keeps a `list` cursor and a stack of the lists opened so far. A
    /// new list is always appended to the current one and becomes the cursor,
    /// so `open` holds the same lists innermost-last and each is attached to
    /// its parent when the walk ends.
    ///
    /// Only ASCII digits count as digits; Java's `Character.isDigit` also
    /// accepts other Unicode digits, which no published version uses.
    fn parse_items(version: &str) -> ListItem {
        let chars: Vec<char> = version.chars().collect();
        let text = |from: usize, to: usize| chars[from..to].iter().collect::<String>();
        let mut open: Vec<Vec<Item>> = vec![Vec::new()];
        let mut is_digit = false;
        let mut start = 0;

        macro_rules! list {
            () => {
                open.last_mut().expect("the root list is never closed")
            };
        }

        for (i, &c) in chars.iter().enumerate() {
            if c == '.' || c == '-' {
                let item = if i == start {
                    Item::Int("0".to_string())
                } else {
                    parse_item(is_digit, &text(start, i))
                };
                list!().push(item);
                start = i + 1;
                if c == '-' {
                    open.push(Vec::new());
                }
            } else if c.is_ascii_digit() {
                if !is_digit && i > start {
                    if !list!().is_empty() {
                        open.push(Vec::new());
                    }
                    list!().push(string_item(&text(start, i), true));
                    start = i;
                    open.push(Vec::new());
                }
                is_digit = true;
            } else {
                if is_digit && i > start {
                    list!().push(parse_item(true, &text(start, i)));
                    start = i;
                    open.push(Vec::new());
                }
                is_digit = false;
            }
        }

        if chars.len() > start {
            if !is_digit && !list!().is_empty() {
                open.push(Vec::new());
            }
            list!().push(parse_item(is_digit, &text(start, chars.len())));
        }

        // Innermost first, as Java pops its stack: a parent is normalized
        // after the child it ends with.
        let mut closed: Option<ListItem> = None;
        while let Some(items) = open.pop() {
            let mut list = ListItem(items);
            if let Some(child) = closed.take() {
                list.0.push(Item::List(child));
            }
            list.normalize();
            closed = Some(list);
        }
        closed.expect("the root list is always present")
    }
}

impl PartialEq for MavenVersion {
    fn eq(&self, other: &Self) -> bool {
        self.canonical == other.canonical
    }
}
impl Eq for MavenVersion {}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.items.compare_to(&other.items)
    }
}

/// `ListItem.toString()`: `-` before a nested list, `.` before anything else,
/// and no separator while nothing has been written yet.
impl std::fmt::Display for ListItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buffer = String::new();
        for item in &self.0 {
            if !buffer.is_empty() {
                buffer.push(if matches!(item, Item::List(_)) {
                    '-'
                } else {
                    '.'
                });
            }
            match item {
                Item::Int(digits) => buffer.push_str(digits),
                Item::String(q) => buffer.push_str(q),
                Item::List(list) => buffer.push_str(&list.to_string()),
            }
        }
        f.write_str(&buffer)
    }
}

/// Sort versions oldest to newest.
///
/// Maven's ordering is not a total order on every string a client can deploy
/// (`1-999999999 <= 1.0.cr.10 <= 1.RELEASE`, yet `1-999999999 > 1.RELEASE`,
/// in `ComparableVersion` itself), and the standard sort may panic on such a
/// comparator. This is a binary insertion sort: it never panics, and on the
/// conventional versions where the ordering is total it gives the same stable
/// result as `sort_by`.
pub fn sort_maven_versions(versions: &[String]) -> Vec<String> {
    let mut sorted: Vec<(MavenVersion, &String)> = Vec::with_capacity(versions.len());
    for version in versions {
        let parsed = MavenVersion::parse(version);
        let at = sorted.partition_point(|(placed, _)| placed.cmp(&parsed) != Ordering::Greater);
        sorted.insert(at, (parsed, version));
    }
    sorted.into_iter().map(|(_, v)| v.clone()).collect()
}

pub fn latest_version(versions: &[String]) -> Option<&String> {
    versions
        .iter()
        .max_by(|a, b| MavenVersion::parse(a).cmp(&MavenVersion::parse(b)))
}

pub fn latest_release(versions: &[String]) -> Option<&String> {
    versions
        .iter()
        .filter(|v| !v.contains("SNAPSHOT"))
        .max_by(|a, b| MavenVersion::parse(a).cmp(&MavenVersion::parse(b)))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn assert_order(lesser: &str, greater: &str) {
        let a = MavenVersion::parse(lesser);
        let b = MavenVersion::parse(greater);
        assert!(
            a < b,
            "Expected '{}' < '{}', but got {:?}",
            lesser,
            greater,
            a.cmp(&b)
        );
    }

    fn assert_equiv(a_str: &str, b_str: &str) {
        let a = MavenVersion::parse(a_str);
        let b = MavenVersion::parse(b_str);
        assert!(
            a == b,
            "Expected '{}' == '{}', but got {:?}",
            a_str,
            b_str,
            a.cmp(&b)
        );
    }

    #[test]
    fn test_equiv_trailing_zeros() {
        assert_equiv("1", "1.0");
        assert_equiv("1", "1.0.0");
        assert_equiv("1.0", "1.0.0");
    }

    #[test]
    fn test_equiv_release_qualifiers() {
        assert_equiv("1.0", "1.0-ga");
        assert_equiv("1.0", "1.0-final");
        assert_equiv("1.0", "1.0-release");
        assert_equiv("1.0.0", "1.0-ga");
    }

    #[test]
    fn test_equiv_qualifier_aliases() {
        assert_equiv("1.0-alpha1", "1.0-a1");
        assert_equiv("1.0-beta1", "1.0-b1");
        assert_equiv("1.0-rc1", "1.0-cr1");
    }

    #[test]
    fn test_qualifier_ordering() {
        assert_order("1.0-alpha", "1.0-beta");
        assert_order("1.0-beta", "1.0-milestone");
        assert_order("1.0-milestone", "1.0-rc");
        assert_order("1.0-rc", "1.0-snapshot");
        assert_order("1.0-snapshot", "1.0");
        assert_order("1.0", "1.0-sp");
    }

    #[test]
    fn test_numeric_ordering() {
        assert_order("1.0-alpha1", "1.0-alpha2");
        assert_order("1.0-alpha1", "1.0-alpha10");
        assert_order("1.0-beta1", "1.0-beta2");
        assert_order("1.0-rc1", "1.0-rc2");
    }

    #[test]
    fn test_version_ordering() {
        assert_order("1.0", "1.1");
        assert_order("1.0", "2.0");
        assert_order("1.0.0", "1.0.1");
        assert_order("1.0.1", "1.1.0");
    }

    #[test]
    fn test_numeric_vs_lexicographic() {
        assert_order("1.0.2", "1.0.10");
        assert_order("1.2", "1.10");
        assert_order("2.0", "10.0");
    }

    #[test]
    fn test_snapshot_ordering() {
        assert_order("1.0-SNAPSHOT", "1.0");
        assert_order("1.0-alpha-SNAPSHOT", "1.0-alpha");
        assert_order("1.0-rc1-SNAPSHOT", "1.0-rc1");
    }

    #[test]
    fn test_hyphen_vs_dot() {
        assert_order("1-1", "1.1");
    }

    #[test]
    fn test_digit_letter_transition() {
        assert_order("1.0alpha1", "1.0beta1");
        assert_order("1.0alpha1", "1.0.1");
    }

    #[test]
    fn test_sort_maven_versions() {
        let versions = vec![
            "1.0.10".to_string(),
            "1.0.2".to_string(),
            "1.0.1".to_string(),
            "2.0.0".to_string(),
            "1.0.0".to_string(),
        ];
        let sorted = sort_maven_versions(&versions);
        assert_eq!(sorted, vec!["1.0.0", "1.0.1", "1.0.2", "1.0.10", "2.0.0"]);
    }

    #[test]
    fn test_latest_version() {
        let versions = vec![
            "1.0.0".to_string(),
            "2.0.0-SNAPSHOT".to_string(),
            "1.5.0".to_string(),
        ];
        assert_eq!(latest_version(&versions).unwrap(), "2.0.0-SNAPSHOT");
    }

    #[test]
    fn test_latest_release() {
        let versions = vec![
            "1.0.0".to_string(),
            "2.0.0-SNAPSHOT".to_string(),
            "1.5.0".to_string(),
        ];
        assert_eq!(latest_release(&versions).unwrap(), "1.5.0");
    }

    #[test]
    fn test_latest_release_all_snapshots() {
        let versions = vec!["1.0.0-SNAPSHOT".to_string(), "2.0.0-SNAPSHOT".to_string()];
        assert!(latest_release(&versions).is_none());
    }

    // -- agreement with Maven's own ComparableVersion ---------------------------

    // Produced by running maven-artifact's `ComparableVersion` (3.9.x) over
    // REFERENCE_VERSIONS: `getCanonical()` for each, and `compareTo` for
    // every pair. The same check over 1,799 generated versions (3.2 million
    // pairs) found no disagreement.
    const REFERENCE_VERSIONS: [&str; 55] = [
        "1",
        "1.0",
        "1.0.0",
        "1-0",
        "1.1",
        "1.10",
        "1.9",
        "01.02",
        "1.0-SNAPSHOT",
        "1-SNAPSHOT",
        "1.0.0-SNAPSHOT",
        "1.0-alpha",
        "1.0-alpha1",
        "1.0-alpha-1",
        "1.0-a1",
        "1.0a1",
        "1.0-a",
        "1.0-beta",
        "1.0-b2",
        "1.0-milestone1",
        "1.0-m3",
        "1.0-rc1",
        "1.0-cr1",
        "1.0-RC",
        "1.0-ga",
        "1.0-final",
        "1.0.Final",
        "1.0-RELEASE",
        "1.0-sp",
        "1.0-sp1",
        "1.0-1",
        "1.0-0-1",
        "1.0.1",
        "1.0-xyz",
        "1.0-jre",
        "1.0.jre",
        "2.0",
        "2.0.0.RELEASE",
        "2.0-android",
        "10.0",
        "0",
        "0-0-1",
        "0.0-alpha",
        "1-999999999",
        "1.0.cr.10",
        "1.RELEASE",
        "1.999999999",
        "1.1000000000",
        "1.999999999999999999",
        "1.1000000000000000000",
        "1.20000000000000000000",
        "1..2",
        "1-",
        "a1",
        "1a1",
    ];

    const REFERENCE_CANONICAL: [&str; 55] = [
        "1",
        "1",
        "1",
        "1",
        "1.1",
        "1.10",
        "1.9",
        "1.2",
        "1-snapshot",
        "1-snapshot",
        "1-snapshot",
        "1-alpha",
        "1-alpha-1",
        "1-alpha-1",
        "1-alpha-1",
        "1-alpha-1",
        "1-a",
        "1-beta",
        "1-beta-2",
        "1-milestone-1",
        "1-milestone-3",
        "1-rc-1",
        "1-rc-1",
        "1-rc",
        "1",
        "1",
        "1",
        "1",
        "1-sp",
        "1-sp-1",
        "1-1",
        "1-1",
        "1.0.1",
        "1-xyz",
        "1-jre",
        "1-jre",
        "2",
        "2",
        "2-android",
        "10",
        "",
        "1",
        "alpha",
        "1-999999999",
        "1.0.rc.10",
        "1",
        "1.999999999",
        "1.1000000000",
        "1.999999999999999999",
        "1.1000000000000000000",
        "1.20000000000000000000",
        "1.0.2",
        "1",
        "alpha-1",
        "1-alpha-1",
    ];

    /// Row `i`, column `j`: how `REFERENCE_VERSIONS[i]` compares with `[j]`.
    const REFERENCE_ORDER: [&str; 55] = [
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        ">>>>=<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>><<<<<>>>>",
        ">>>>>=>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>><<<<<>>>>",
        ">>>>><=>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>><<<<<>>>>",
        ">>>>><<=>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>><<<<<>>>>",
        "<<<<<<<<===>>>>><>>>>>>><<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<===>>>>><>>>>>>><<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<===>>>>><>>>>>>><<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<<<<=<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<><",
        "<<<<<<<<<<<>====<<<<<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>=",
        "<<<<<<<<<<<>====<<<<<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>=",
        "<<<<<<<<<<<>====<<<<<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>=",
        "<<<<<<<<<<<>====<<<<<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>=",
        ">>>><<<<>>>>>>>>=>>>>>>>>>>>>><<<<<<<<<<>>><<><<<<<<>>>",
        "<<<<<<<<<<<>>>>><=<<<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<<<<>>>>><>=<<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<<<<>>>>><>>=<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<<<<>>>>><>>>=<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<<<<>>>>><>>>>==><<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<<<<>>>>><>>>>==><<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "<<<<<<<<<<<>>>>><>>>><<=<<<<<<<<<<<<<<<<>>><<<<<<<<<<>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        ">>>><<<<>>>>>>>><>>>>>>>>>>>=<<<<<<<<<<<>>><<><<<<<<>>>",
        ">>>><<<<>>>>>>>><>>>>>>>>>>>>=<<<<<<<<<<>>><<><<<<<<>>>",
        ">>>><<<<>>>>>>>>>>>>>>>>>>>>>>=><>>><<<<>>><<><<<<<<>>>",
        ">>>><<<<>>>>>>>>>>>>>>>>>>>>>><=<>>><<<<>>><<><<<<<<>>>",
        ">>>><<<<>>>>>>>>>>>>>>>>>>>>>>>>=>>><<<<>>>>>><<<<<<>>>",
        ">>>><<<<>>>>>>>>>>>>>>>>>>>>>><<<=>><<<<>>><<><<<<<<>>>",
        ">>>><<<<>>>>>>>>>>>>>>>>>>>>>><<<<==<<<<>>><<><<<<<<>>>",
        ">>>><<<<>>>>>>>>>>>>>>>>>>>>>><<<<==<<<<>>><<><<<<<<>>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>==<<>>>>>>>>>>>>>>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>==<<>>>>>>>>>>>>>>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>=<>>>>>>>>>>>>>>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>=>>>>>>>>>>>>>>>",
        "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<=<><<<<<<<<<<><",
        "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>=><<<<<<<<<<><",
        "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<=<<<<<<<<<<><",
        ">>>><<<<>>>>>>>>>>>>>>>>>>>>>>>><>>><<<<>>>=<><<<<<<>>>",
        "<<<<<<<<>>>>>>>>>>>>>>>><<<<>>>><>>><<<<>>>>=<<<<<<<<>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>>=<<<<>>>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>>>=<<<>>>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>>>>=<<>>>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>>>>>=<>>>>",
        ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>>>>>>=>>>>",
        ">>>><<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<>>>>>><<<<<=>>>",
        "====<<<<>>>>>>>><>>>>>>>====<<<<<<<<<<<<>>><>=<<<<<<=>>",
        "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<=<",
        "<<<<<<<<<<<>====<<<<<<<<<<<<<<<<<<<<<<<<>>><<<<<<<<<<>=",
    ];

    #[test]
    fn maven_reference_vectors() {
        let parsed: Vec<MavenVersion> = REFERENCE_VERSIONS
            .iter()
            .map(|v| MavenVersion::parse(v))
            .collect();
        for (i, a) in parsed.iter().enumerate() {
            assert_eq!(
                a.canonical, REFERENCE_CANONICAL[i],
                "canonical form of {:?}",
                REFERENCE_VERSIONS[i]
            );
            for (j, b) in parsed.iter().enumerate() {
                let expected = match REFERENCE_ORDER[i].as_bytes()[j] {
                    b'<' => Ordering::Less,
                    b'=' => Ordering::Equal,
                    _ => Ordering::Greater,
                };
                assert_eq!(
                    a.cmp(b),
                    expected,
                    "{:?} vs {:?}",
                    REFERENCE_VERSIONS[i],
                    REFERENCE_VERSIONS[j]
                );
            }
        }
    }

    // -- the ordering is total on conventional versions ----------------------------

    /// `N(.N){0,3}` with an optional `-qualifier`, `-qualifierN` or
    /// `-qualifier-N` tail: the shape Maven releases actually use.
    fn conventional_version() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        let number = prop_oneof![
            4 => "[0-9]{1,2}",
            1 => "0[0-9]",
            1 => "[0-9]{19,21}",
        ];
        let qualifier = prop_oneof![
            Just(""),
            Just("alpha"),
            Just("a"),
            Just("beta"),
            Just("m"),
            Just("rc"),
            Just("cr"),
            Just("SNAPSHOT"),
            Just("ga"),
            Just("final"),
            Just("sp"),
            Just("jre"),
            Just("x"),
        ];
        (
            proptest::collection::vec(number, 1..5),
            qualifier,
            prop_oneof![Just(""), Just("-")],
            proptest::option::of("[0-9]{1,2}"),
        )
            .prop_map(|(core, qualifier, sep, n)| {
                let core = core.join(".");
                match (qualifier, n) {
                    ("", _) => core,
                    (q, None) => format!("{core}-{q}"),
                    (q, Some(n)) => format!("{core}-{q}{sep}{n}"),
                }
            })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4000))]

        #[test]
        fn ordering_is_a_total_order_on_conventional_versions(
            a in conventional_version(),
            b in conventional_version(),
            c in conventional_version(),
        ) {
            let cmp = |x: &str, y: &str| MavenVersion::parse(x).cmp(&MavenVersion::parse(y));
            crate::testing::props::check_total_order(a.as_str(), b.as_str(), c.as_str(), cmp)?;
        }

        /// Whatever a client deploys, sorting neither panics nor loses a version.
        #[test]
        fn sorting_never_panics_and_keeps_every_version(
            versions in proptest::collection::vec(crate::testing::props::version_like(), 0..40),
        ) {
            let sorted = sort_maven_versions(&versions);
            let mut expected = versions.clone();
            expected.sort();
            let mut got = sorted;
            got.sort();
            proptest::prop_assert_eq!(got, expected);
        }
    }

    #[test]
    fn sorting_conventional_versions_matches_the_standard_sort() {
        let versions: Vec<String> = [
            "2.0",
            "1.0-SNAPSHOT",
            "1.0",
            "1.0-rc1",
            "1.10",
            "1.9",
            "1.0-alpha",
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(
            sort_maven_versions(&versions),
            vec![
                "1.0-alpha",
                "1.0-rc1",
                "1.0-SNAPSHOT",
                "1.0",
                "1.9",
                "1.10",
                "2.0"
            ]
        );
    }
}
