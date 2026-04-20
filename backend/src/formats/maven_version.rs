//! Maven version comparison implementing the ComparableVersion algorithm.
//!
//! Port of org.apache.maven.artifact.versioning.ComparableVersion from Maven.
//! See: https://maven.apache.org/ref/3.9.6/maven-artifact/

use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub struct MavenVersion {
    canonical: String,
    items: ListItem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Int(u64),
    String(StringItem),
    List(ListItem),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StringItem(String);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListItem(Vec<Item>);

impl StringItem {
    fn qualifier_rank(s: &str) -> Option<i32> {
        match s {
            "alpha" | "a" => Some(0),
            "beta" | "b" => Some(1),
            "milestone" | "m" => Some(2),
            "rc" | "cr" => Some(3),
            "snapshot" => Some(4),
            "" | "ga" | "final" | "release" => Some(5),
            "sp" => Some(6),
            _ => None,
        }
    }
}

impl MavenVersion {
    pub fn parse(version: &str) -> Self {
        let lower = version.to_lowercase();
        let items = Self::parse_items(&lower);
        let canonical = format!("{}", items);
        MavenVersion { canonical, items }
    }

    fn parse_items(version: &str) -> ListItem {
        let mut stack: Vec<ListItem> = vec![ListItem(Vec::new())];
        let mut current = String::new();
        let mut is_digit = false;

        for ch in version.chars() {
            if ch == '.' {
                if !current.is_empty() {
                    let item = Self::make_item(is_digit, &current);
                    stack.last_mut().unwrap().0.push(item);
                    current.clear();
                } else {
                    stack.last_mut().unwrap().0.push(Item::Int(0));
                }
            } else if ch == '-' {
                if !current.is_empty() {
                    let item = Self::make_item(is_digit, &current);
                    stack.last_mut().unwrap().0.push(item);
                    current.clear();
                }
                let new_list = ListItem(Vec::new());
                stack.push(new_list);
            } else {
                let ch_is_digit = ch.is_ascii_digit();
                if !current.is_empty() && ch_is_digit != is_digit {
                    let item = Self::make_item(is_digit, &current);
                    stack.last_mut().unwrap().0.push(item);
                    current.clear();
                    if !ch_is_digit {
                        let new_list = ListItem(Vec::new());
                        stack.push(new_list);
                    }
                }
                is_digit = ch_is_digit;
                current.push(ch);
            }
        }

        if !current.is_empty() {
            let item = Self::make_item(is_digit, &current);
            stack.last_mut().unwrap().0.push(item);
        }

        while stack.len() > 1 {
            let mut child = stack.pop().unwrap();
            Self::trim_trailing_nulls(&mut child);
            stack.last_mut().unwrap().0.push(Item::List(child));
        }

        let mut root = stack.pop().unwrap();
        Self::trim_trailing_nulls(&mut root);
        root
    }

    fn make_item(is_digit: bool, token: &str) -> Item {
        if is_digit {
            Item::Int(token.parse::<u64>().unwrap_or(0))
        } else {
            let normalized = match token {
                "a" => "alpha",
                "b" => "beta",
                "m" => "milestone",
                "cr" => "rc",
                "ga" | "final" | "release" => "",
                other => other,
            };
            Item::String(StringItem(normalized.to_string()))
        }
    }

    fn trim_trailing_nulls(list: &mut ListItem) {
        while let Some(last) = list.0.last() {
            match last {
                Item::Int(0) => {
                    list.0.pop();
                }
                Item::String(s) if s.0.is_empty() => {
                    list.0.pop();
                }
                Item::List(l) if l.0.is_empty() => {
                    list.0.pop();
                }
                _ => break,
            }
        }
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
        cmp_list(&self.items, &other.items)
    }
}

fn cmp_list(a: &ListItem, b: &ListItem) -> Ordering {
    let max_len = a.0.len().max(b.0.len());
    for i in 0..max_len {
        let ai = a.0.get(i);
        let bi = b.0.get(i);
        let ord = match (ai, bi) {
            (Some(a_item), Some(b_item)) => cmp_item(a_item, b_item),
            (Some(a_item), None) => cmp_item_with_null(a_item),
            (None, Some(b_item)) => cmp_item_with_null(b_item).reverse(),
            (None, None) => Ordering::Equal,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

fn cmp_item(a: &Item, b: &Item) -> Ordering {
    match (a, b) {
        (Item::Int(a), Item::Int(b)) => a.cmp(b),
        (Item::String(a), Item::String(b)) => cmp_string(a, b),
        (Item::List(a), Item::List(b)) => cmp_list(a, b),
        (Item::Int(_), Item::String(_)) => Ordering::Greater,
        (Item::String(_), Item::Int(_)) => Ordering::Less,
        // In Maven's ComparableVersion, List is always less than Int
        (Item::Int(_), Item::List(_)) => Ordering::Greater,
        (Item::List(_), Item::Int(_)) => Ordering::Less,
        // In Maven's ComparableVersion, List is always greater than String
        (Item::String(_), Item::List(_)) => Ordering::Less,
        (Item::List(_), Item::String(_)) => Ordering::Greater,
    }
}

fn cmp_string(a: &StringItem, b: &StringItem) -> Ordering {
    let a_rank = StringItem::qualifier_rank(&a.0);
    let b_rank = StringItem::qualifier_rank(&b.0);
    match (a_rank, b_rank) {
        (Some(ar), Some(br)) => ar.cmp(&br),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.0.cmp(&b.0),
    }
}

fn cmp_item_with_null(item: &Item) -> Ordering {
    match item {
        Item::Int(n) => n.cmp(&0),
        Item::String(s) => {
            let rank = StringItem::qualifier_rank(&s.0);
            match rank {
                Some(r) => r.cmp(&5),
                None => Ordering::Greater,
            }
        }
        Item::List(l) => {
            if l.0.is_empty() {
                Ordering::Equal
            } else {
                cmp_item_with_null(l.0.first().unwrap())
            }
        }
    }
}

impl std::fmt::Display for ListItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, item) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            match item {
                Item::Int(n) => write!(f, "{}", n)?,
                Item::String(s) => write!(f, "{}", s.0)?,
                Item::List(l) => write!(f, "({})", l)?,
            }
        }
        Ok(())
    }
}

pub fn sort_maven_versions(versions: &[String]) -> Vec<String> {
    let mut versioned: Vec<_> = versions
        .iter()
        .map(|v| (MavenVersion::parse(v), v.clone()))
        .collect();
    versioned.sort_by_key(|v| v.0.clone());
    versioned.into_iter().map(|(_, v)| v).collect()
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
}
