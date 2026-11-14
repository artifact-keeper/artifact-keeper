//! Partition of the IP space into disjoint regions of identical rule
//! applicability.
//!
//! Legacy rules apply by client IP. To translate narrowing into conditional
//! denies the combined effect of all applicable rules must be known per IP, so
//! the space (IPv4 and IPv6 separately) is cut at every CIDR boundary. Each
//! piece is a range with one fixed set of applicable rules; pieces with the same
//! set form one region, expressed as a positive list of CIDRs (there is no
//! negation operator in the target model).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::intent::Cidr;

/// The region limit was exceeded; nothing was truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionOverflow {
    pub regions: usize,
    pub limit: usize,
}

/// Disjoint set of addresses over which the same rules apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// Indexes into the rule list given to [`partition`].
    pub applicable: BTreeSet<usize>,
    pub cidrs: BTreeSet<Cidr>,
}

#[derive(Clone, Copy)]
struct Family {
    bits: u32,
    v6: bool,
}

const V4: Family = Family {
    bits: 32,
    v6: false,
};
const V6: Family = Family {
    bits: 128,
    v6: true,
};

impl Family {
    fn max(self) -> u128 {
        if self.bits == 128 {
            u128::MAX
        } else {
            (1u128 << self.bits) - 1
        }
    }

    fn matches(self, addr: IpAddr) -> bool {
        addr.is_ipv6() == self.v6
    }

    fn value(self, addr: IpAddr) -> u128 {
        match addr {
            IpAddr::V4(a) => u128::from(u32::from(a)),
            IpAddr::V6(a) => u128::from(a),
        }
    }

    fn addr(self, v: u128) -> IpAddr {
        if self.v6 {
            IpAddr::V6(Ipv6Addr::from(v))
        } else {
            IpAddr::V4(Ipv4Addr::from(v as u32))
        }
    }
}

fn interval(family: Family, cidr: &Cidr) -> (u128, u128) {
    let start = family.value(cidr.addr());
    let host_bits = family.bits - u32::from(cidr.prefix_len());
    let end = if host_bits == 128 {
        u128::MAX
    } else {
        start | ((1u128 << host_bits) - 1)
    };
    (start, end)
}

/// The minimal list of CIDRs covering `[start, end]` exactly.
fn range_to_cidrs(family: Family, mut start: u128, end: u128) -> Vec<Cidr> {
    let mut out = Vec::new();
    loop {
        // Largest block aligned at `start` that does not pass `end`.
        let align = if start == 0 {
            family.bits
        } else {
            start.trailing_zeros().min(family.bits)
        };
        let mut host_bits = align;
        while host_bits > 0 {
            let last = if host_bits == 128 {
                u128::MAX
            } else {
                start.saturating_add((1u128 << host_bits) - 1)
            };
            if last <= end && (host_bits < 128 || start == 0) {
                break;
            }
            host_bits -= 1;
        }
        let prefix = (family.bits - host_bits) as u8;
        out.push(Cidr::from_parts(family.addr(start), prefix));
        let last = if host_bits == 128 {
            u128::MAX
        } else {
            start + ((1u128 << host_bits) - 1)
        };
        if last >= end {
            break;
        }
        start = last + 1;
    }
    out
}

/// Partition both address families by the boundaries of every conditioned rule.
///
/// `rules[i]` is `None` for a rule without a CIDR condition (applies to every
/// address) or the rule's ranges. Rules with an empty range set never apply and
/// are simply never members. At most `limit` elementary pieces are produced.
pub fn partition(
    rules: &[Option<&BTreeSet<Cidr>>],
    limit: usize,
) -> Result<Vec<Region>, RegionOverflow> {
    let mut by_signature: BTreeMap<BTreeSet<usize>, BTreeSet<Cidr>> = BTreeMap::new();
    let mut pieces = 0usize;

    for family in [V4, V6] {
        let ranges: Vec<Vec<(u128, u128)>> = rules
            .iter()
            .map(|r| {
                r.map(|set| {
                    set.iter()
                        .filter(|c| family.matches(c.addr()))
                        .map(|c| interval(family, c))
                        .collect()
                })
                .unwrap_or_default()
            })
            .collect();

        let mut cuts: BTreeSet<u128> = BTreeSet::from([0]);
        for (start, end) in ranges.iter().flatten() {
            cuts.insert(*start);
            if let Some(next) = end.checked_add(1) {
                if next <= family.max() {
                    cuts.insert(next);
                }
            }
        }
        pieces += cuts.len();
        if pieces > limit {
            return Err(RegionOverflow {
                regions: pieces,
                limit,
            });
        }

        let cuts: Vec<u128> = cuts.into_iter().collect();
        for (i, &start) in cuts.iter().enumerate() {
            let end = cuts
                .get(i + 1)
                .map(|n| n - 1)
                .unwrap_or_else(|| family.max());
            let signature: BTreeSet<usize> = rules
                .iter()
                .enumerate()
                .filter(|(idx, r)| {
                    r.is_none() || ranges[*idx].iter().any(|(s, e)| *s <= start && start <= *e)
                })
                .map(|(idx, _)| idx)
                .collect();
            by_signature
                .entry(signature)
                .or_default()
                .extend(range_to_cidrs(family, start, end));
        }
    }

    Ok(by_signature
        .into_iter()
        .map(|(applicable, cidrs)| Region { applicable, cidrs })
        .collect())
}

/// Whether `addr` lies in any of `cidrs`.
pub fn contains(cidrs: &BTreeSet<Cidr>, addr: IpAddr) -> bool {
    cidrs.iter().any(|c| {
        let family = if c.addr().is_ipv6() { V6 } else { V4 };
        family.matches(addr) && {
            let (s, e) = interval(family, c);
            let v = family.value(addr);
            s <= v && v <= e
        }
    })
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn cidrs(list: &[&str]) -> BTreeSet<Cidr> {
        list.iter().map(|c| Cidr::parse(c).unwrap()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn region_of(regions: &[Region], addr: IpAddr) -> &Region {
        let hits: Vec<&Region> = regions
            .iter()
            .filter(|r| contains(&r.cidrs, addr))
            .collect();
        assert_eq!(hits.len(), 1, "{addr} must be in exactly one region");
        hits[0]
    }

    #[test]
    fn range_to_cidrs_is_exact_and_minimal() {
        let all = range_to_cidrs(V4, 0, V4.max());
        assert_eq!(all, vec![Cidr::parse("0.0.0.0/0").unwrap()]);
        let all6 = range_to_cidrs(V6, 0, u128::MAX);
        assert_eq!(all6, vec![Cidr::parse("::/0").unwrap()]);
        // 10.0.0.1 - 10.0.0.6 -> /32, /31, /31... verified by round trip.
        let start = V4.value(ip("10.0.0.1"));
        let end = V4.value(ip("10.0.0.6"));
        let parts = range_to_cidrs(V4, start, end);
        let covered: u128 = parts
            .iter()
            .map(|c| {
                let (s, e) = interval(V4, c);
                e - s + 1
            })
            .sum();
        assert_eq!(covered, end - start + 1);
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn no_conditioned_rule_gives_one_region_per_family_signature() {
        let regions = partition(&[None, None], 16).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].applicable, BTreeSet::from([0, 1]));
        assert!(contains(&regions[0].cidrs, ip("1.2.3.4")));
        assert!(contains(&regions[0].cidrs, ip("2001:db8::1")));
    }

    #[test]
    fn nested_and_overlapping_ranges_are_cut_at_every_boundary() {
        let a = cidrs(&["10.0.0.0/8"]);
        let b = cidrs(&["10.1.0.0/16"]);
        let c = cidrs(&["10.0.0.0/9", "192.168.0.0/16"]);
        let regions = partition(&[Some(&a), Some(&b), Some(&c)], 64).unwrap();

        // Disjoint and complete: sampled addresses at boundaries and inside.
        for (addr, expect) in [
            ("9.255.255.255", vec![]),
            ("10.0.0.0", vec![0, 2]),
            ("10.0.255.255", vec![0, 2]),
            ("10.1.0.0", vec![0, 1, 2]),
            ("10.1.255.255", vec![0, 1, 2]),
            ("10.2.0.0", vec![0, 2]),
            ("10.127.255.255", vec![0, 2]),
            ("10.128.0.0", vec![0]),
            ("10.255.255.255", vec![0]),
            ("11.0.0.0", vec![]),
            ("192.168.0.0", vec![2]),
            ("192.168.255.255", vec![2]),
            ("192.169.0.0", vec![]),
            ("2001:db8::1", vec![]),
        ] {
            let r = region_of(&regions, ip(addr));
            let expect: BTreeSet<usize> = expect.into_iter().collect();
            assert_eq!(r.applicable, expect, "{addr}");
        }
    }

    #[test]
    fn unconditional_rules_apply_in_every_region() {
        let a = cidrs(&["10.0.0.0/8"]);
        let regions = partition(&[None, Some(&a)], 16).unwrap();
        assert_eq!(
            region_of(&regions, ip("10.5.5.5")).applicable,
            BTreeSet::from([0, 1])
        );
        assert_eq!(
            region_of(&regions, ip("8.8.8.8")).applicable,
            BTreeSet::from([0])
        );
        assert_eq!(
            region_of(&regions, ip("::1")).applicable,
            BTreeSet::from([0])
        );
    }

    #[test]
    fn ipv6_ranges_and_the_top_of_the_space_are_handled() {
        let a = cidrs(&[
            "2001:db8::/32",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0/124",
        ]);
        let regions = partition(&[Some(&a)], 16).unwrap();
        assert_eq!(
            region_of(&regions, ip("2001:db8::")).applicable,
            BTreeSet::from([0])
        );
        assert_eq!(
            region_of(&regions, ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")).applicable,
            BTreeSet::from([0])
        );
        assert_eq!(
            region_of(&regions, ip("2001:db9::")).applicable,
            BTreeSet::new()
        );
        // IPv4 stays independent of IPv6 boundaries.
        assert_eq!(
            region_of(&regions, ip("1.1.1.1")).applicable,
            BTreeSet::new()
        );
    }

    #[test]
    fn a_host_route_is_an_exact_boundary() {
        let a = cidrs(&["10.0.0.7/32"]);
        let regions = partition(&[Some(&a)], 16).unwrap();
        assert_eq!(
            region_of(&regions, ip("10.0.0.7")).applicable,
            BTreeSet::from([0])
        );
        assert_eq!(
            region_of(&regions, ip("10.0.0.6")).applicable,
            BTreeSet::new()
        );
        assert_eq!(
            region_of(&regions, ip("10.0.0.8")).applicable,
            BTreeSet::new()
        );
    }

    #[test]
    fn exceeding_the_limit_reports_overflow_instead_of_truncating() {
        let many: BTreeSet<Cidr> = (0..40u32)
            .map(|i| Cidr::parse(&format!("10.{i}.0.0/16")).unwrap())
            .collect();
        let err = partition(&[Some(&many)], 8).unwrap_err();
        assert_eq!(err.limit, 8);
        assert!(err.regions > 8);
        assert!(partition(&[Some(&many)], 1000).is_ok());
    }

    #[test]
    fn partitions_cover_the_space_for_pseudorandom_rule_sets() {
        // Deterministic pseudo-random rule sets: every sampled address is in
        // exactly one region and the region's rules are exactly the rules whose
        // ranges contain it.
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..40 {
            let rule_count = 1 + (next() % 4) as usize;
            let sets: Vec<Option<BTreeSet<Cidr>>> = (0..rule_count)
                .map(|_| {
                    if next() % 5 == 0 {
                        None
                    } else {
                        Some(
                            (0..1 + next() % 3)
                                .map(|_| {
                                    let a = (next() % 4) as u8;
                                    let b = (next() % 4) as u8;
                                    let prefix = 8 + (next() % 3) as u8 * 8;
                                    Cidr::from_parts(
                                        IpAddr::V4(Ipv4Addr::new(10 + a, b, 0, 0)),
                                        prefix,
                                    )
                                })
                                .collect(),
                        )
                    }
                })
                .collect();
            let refs: Vec<Option<&BTreeSet<Cidr>>> = sets.iter().map(|s| s.as_ref()).collect();
            let regions = partition(&refs, 1024).unwrap();
            for _ in 0..200 {
                let addr = IpAddr::V4(Ipv4Addr::new(
                    9 + (next() % 6) as u8,
                    (next() % 5) as u8,
                    (next() % 256) as u8,
                    (next() % 256) as u8,
                ));
                let region = region_of(&regions, addr);
                let expect: BTreeSet<usize> = sets
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.as_ref().map(|c| contains(c, addr)).unwrap_or(true))
                    .map(|(i, _)| i)
                    .collect();
                assert_eq!(region.applicable, expect, "{addr}");
            }
        }
    }
}
