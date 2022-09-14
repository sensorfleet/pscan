use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;

/// Continuous port range.
#[derive(Clone, PartialEq)]
enum Prange {
    Range((u16, u16)), // range of continous ports from min to max, inclusive
    Atom(u16),         // signle port
}

impl Prange {
    fn create(min: u16, max: u16) -> Prange {
        if min == max {
            Prange::Atom(min)
        } else {
            Prange::Range((min, max))
        }
    }

    /// Get the smallest port number
    fn min(&self) -> u16 {
        match self {
            Prange::Range((min, _max)) => *min,
            Prange::Atom(val) => *val,
        }
    }

    /// Get the largest port number
    fn max(&self) -> u16 {
        match self {
            Prange::Range((_min, max)) => *max,
            Prange::Atom(val) => *val,
        }
    }

    /// Get the number of ports on this range
    fn count(&self) -> u16 {
        match self {
            Prange::Range((min, max)) => max - min + 1,
            Prange::Atom(_) => 1,
        }
    }

    // Merge this range to other, if possible. Returns merged range or None
    // if ranges could not be merged.
    fn merge(&self, other: &Self) -> Option<Self> {
        let (min, max, omin, omax) = (self.min(), self.max(), other.min(), other.max());

        if max >= omin && max <= omax
            || omax >= min && omax <= max
            || min + 1 == omin
            || omin + 1 == min
            || max + 1 == omax
            || omax + 1 == max
            || max + 1 == omin
            || omax + 1 == min
        {
            Some(Prange::create(min.min(omin), max.max(omax)))
        } else {
            None
        }
    }
}

impl fmt::Debug for Prange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Range(arg0) => write!(f, "[{}-{}]", arg0.0, arg0.1),
            Self::Atom(arg0) => write!(f, "[{}]", arg0),
        }
    }
}

/// A range of ports.
/// Implements Iterartor which returns `PortIterator` instances which can then
/// be used to iterare the actual ports. The `PortIterator`s returned will
/// return at maximum `step` number of ports. This allows to partition a port
/// range into stripes of ports which can then be iterated.
#[derive(Clone)]
pub struct PortRange {
    ranges: Vec<Prange>, // continuous port ranges making this range
}

/// Error returned if port range can not be parsed.
#[derive(Debug)]
pub struct Error {
    msg: String,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl From<&str> for Error {
    fn from(val: &str) -> Self {
        Error { msg: val.into() }
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Self {
        Error {
            msg: format!("Invalid number in port range: {}", err),
        }
    }
}

impl PortRange {
    /// Get number of ports in the range
    pub fn port_count(&self) -> u16 {
        let mut count = 0;
        for r in &self.ranges {
            count += r.count();
        }
        count
    }

    /// Get port at given index in port range.
    /// Panics if given index is out-of-range
    pub fn get(&self, index: usize) -> u16 {
        if index >= self.port_count() as usize {
            panic!("requested index out of bounds")
        }
        let mut curr = 0;
        for r in &self.ranges {
            if curr == index {
                return r.min();
            } else if curr + (r.count() as usize) <= index {
                curr += r.count() as usize;
                continue;
            } else {
                return r.min() + (index - curr) as u16;
            }
        }
        panic!("requested index out of bounds")
    }

    pub fn port_iter(&self) -> impl Iterator<Item = u16> + '_ {
        (0..self.port_count() as usize).map(|i| self.get(i))
    }
}

/// Parse a single port range, min-max (inclusive).
fn parse_single_range(val: &str) -> Result<Prange, Error> {
    let parts: Vec<&str> = val.split('-').collect();
    if parts.len() > 2 {
        return Err("Invalid format for port range".into());
    }
    let min: u16 = parts[0].trim().parse()?;
    let max: u16 = parts[1].trim().parse()?;
    if min > max {
        return Err("First range value needs to be smaller than the last".into());
    }
    Ok(Prange::create(min, max))
}

impl TryFrom<&str> for PortRange {
    type Error = Error;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        let inputs = if val.contains(',') {
            val.split(',').collect()
        } else {
            vec![val]
        };
        let mut parsed_ranges = Vec::with_capacity(inputs.len());
        for s in inputs {
            if !s.contains('-') {
                parsed_ranges.push(Prange::Atom(s.trim().parse()?));
            } else {
                parsed_ranges.push(parse_single_range(s.trim())?);
            }
        }
        let mut ranges = Vec::with_capacity(parsed_ranges.len());
        // sort and merge ranges, removes duplicates
        parsed_ranges.sort_unstable_by_key(|k| k.min());
        let mut curr = parsed_ranges.remove(0);
        for r in parsed_ranges.drain(0..) {
            if let Some(merged) = curr.merge(&r) {
                curr = merged;
            } else {
                // could not merge current anymore, append it to final set of
                // ports
                ranges.push(curr);
                curr = r;
            }
        }
        ranges.push(curr);

        Ok(PortRange { ranges })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn check_elems(r: impl Iterator<Item = u16>, expected: &[u16]) {
        let values: Vec<u16> = r.collect();
        assert_eq!(expected, values)
    }

    fn test_simple_range(input: &str, expected: &[u16]) {
        let r = PortRange::try_from(input).unwrap();
        assert_eq!(r.port_count() as usize, expected.len());
        check_elems(
            (0..r.port_count() as usize).into_iter().map(|i| r.get(i)),
            expected,
        );
    }

    #[test]
    fn simple_ranges() {
        test_simple_range("1- 3", &[1, 2, 3]);
        test_simple_range("1-2", &[1, 2]);
        test_simple_range("1", &[1]);
        test_simple_range("1-3, 6-7", &[1, 2, 3, 6, 7]);
    }

    #[test]
    fn test_full_range() {
        let r = PortRange::try_from("1-65535").unwrap();
        assert_eq!(r.port_count(), 65535);
        check_elems(
            (0..r.port_count() as usize).map(|i| r.get(i)),
            &(1..=65535).collect::<Vec<u16>>(),
        );
    }

    #[test]
    fn complex_steps() {
        let r = PortRange::try_from("1-10,20-30,41-42").unwrap();
        assert_eq!(r.port_count(), 23);
        let mut expected = Vec::new();
        expected.append(&mut (1..11).collect::<Vec<u16>>());
        expected.append(&mut (20..31).collect::<Vec<u16>>());
        expected.append(&mut (41..43).collect::<Vec<u16>>());
        check_elems((0..r.port_count() as usize).map(|i| r.get(i)), &expected);
    }

    #[test]
    fn ranges_and_atoms() {
        let r = PortRange::try_from("22,80,8000-8090,4000-4025").unwrap();
        let mut expected1 = vec![22, 80];
        expected1.append(&mut (4000..=4025).collect());
        expected1.append(&mut (8000..=8090).collect());
        check_elems((0..r.port_count() as usize).map(|i| r.get(i)), &expected1);
    }

    #[test]
    fn test_merge() {
        struct Case {
            name: &'static str,
            input: (Prange, Prange),
            expected: Option<Prange>,
        }
        let cases: [Case; 22] = [
            Case {
                name: "same-atom",
                input: (Prange::Atom(2), Prange::Atom(2)),
                expected: Some(Prange::Atom(2)),
            },
            Case {
                name: "adjacent-atom",
                input: (Prange::Atom(1), Prange::Atom(2)),
                expected: Some(Prange::create(1, 2)),
            },
            Case {
                name: "adjacent-atom2",
                input: (Prange::Atom(2), Prange::Atom(1)),
                expected: Some(Prange::create(1, 2)),
            },
            Case {
                name: "distinct-atom",
                input: (Prange::Atom(2), Prange::Atom(4)),
                expected: None,
            },
            Case {
                name: "adjacent-range",
                input: (Prange::Atom(2), Prange::create(3, 6)),
                expected: Some(Prange::create(2, 6)),
            },
            Case {
                name: "adjacent-range2",
                input: (Prange::Atom(7), Prange::create(3, 6)),
                expected: Some(Prange::create(3, 7)),
            },
            Case {
                name: "adjacent-range3",
                input: (Prange::create(3, 6), Prange::Atom(2)),
                expected: Some(Prange::create(2, 6)),
            },
            Case {
                name: "adjacent-range4",
                input: (Prange::create(3, 6), Prange::Atom(7)),
                expected: Some(Prange::create(3, 7)),
            },
            Case {
                name: "atom-in-range",
                input: (Prange::create(3, 6), Prange::Atom(5)),
                expected: Some(Prange::create(3, 6)),
            },
            Case {
                name: "atom-in-range2",
                input: (Prange::Atom(5), Prange::create(3, 6)),
                expected: Some(Prange::create(3, 6)),
            },
            Case {
                name: "adjacent-range",
                input: (Prange::create(1, 5), Prange::create(6, 10)),
                expected: Some(Prange::create(1, 10)),
            },
            Case {
                name: "adjacent-range2",
                input: (Prange::create(6, 10), Prange::create(1, 5)),
                expected: Some(Prange::create(1, 10)),
            },
            Case {
                name: "adjacent-range3",
                input: (Prange::create(11, 15), Prange::create(6, 10)),
                expected: Some(Prange::create(6, 15)),
            },
            Case {
                name: "adjacent-range4",
                input: (Prange::create(6, 10), Prange::create(11, 15)),
                expected: Some(Prange::create(6, 15)),
            },
            Case {
                name: "overlapping-range",
                input: (Prange::create(3, 6), Prange::create(4, 8)),
                expected: Some(Prange::create(3, 8)),
            },
            Case {
                name: "overlapping-range2",
                input: (Prange::create(5, 10), Prange::create(4, 8)),
                expected: Some(Prange::create(4, 10)),
            },
            Case {
                name: "overlapping-range3",
                input: (Prange::create(4, 8), Prange::create(3, 6)),
                expected: Some(Prange::create(3, 8)),
            },
            Case {
                name: "overlapping-range4",
                input: (Prange::create(4, 8), Prange::create(5, 10)),
                expected: Some(Prange::create(4, 10)),
            },
            Case {
                name: "distinct range",
                input: (Prange::create(4, 8), Prange::create(10, 15)),
                expected: None,
            },
            Case {
                name: "contained-range",
                input: (Prange::create(3, 10), Prange::create(4, 8)),
                expected: Some(Prange::create(3, 10)),
            },
            Case {
                name: "contained-range2",
                input: (Prange::create(4, 8), Prange::create(3, 10)),
                expected: Some(Prange::create(3, 10)),
            },
            Case {
                name: "same-range",
                input: (Prange::create(4, 8), Prange::create(4, 8)),
                expected: Some(Prange::create(4, 8)),
            },
        ];

        for c in cases {
            let result = c.input.0.merge(&c.input.1);
            if result != c.expected {
                panic!("{} : expected {:?}, got {:?}", c.name, c.expected, result)
            }
        }
    }

    #[test]
    fn test_merged_ranges() {
        struct Case<'a> {
            name: &'static str,
            input: &'static str,
            expected: &'a [Prange],
        }
        let cases: &[Case] = &[
            Case {
                name: "simple",
                input: "1-22",
                expected: &[Prange::create(1, 22)],
            },
            Case {
                name: "dual ports",
                input: "22,80,22",
                expected: &[Prange::create(22, 22), Prange::create(80, 80)],
            },
            Case {
                name: "only dual ports",
                input: "22, 22",
                expected: &[Prange::create(22, 22)],
            },
            Case {
                name: "merge to range",
                input: "1-100, 22, 80",
                expected: &[Prange::create(1, 100)],
            },
            Case {
                name: "merge ranges",
                input: "1-100, 8080, 80-120",
                expected: &[Prange::create(1, 120), Prange::create(8080, 8080)],
            },
            Case {
                name: "multiple to merge",
                input: "1-100, 22, 80, 90, 99, 120-140, 130, 135-138, 8080",
                expected: &[
                    Prange::create(1, 100),
                    Prange::create(120, 140),
                    Prange::create(8080, 8080),
                ],
            },
        ];

        for c in cases {
            let result = PortRange::try_from(c.input).unwrap();
            assert_eq!(
                result.ranges.len(),
                c.expected.len(),
                "test {}: expected {} elements, got {}",
                c.name,
                result.ranges.len(),
                c.expected.len()
            );
            for (i, r) in result.ranges.iter().enumerate() {
                assert_eq!(
                    *r, c.expected[i],
                    "test {}: result[{}] expected {:?}, got {:?}",
                    c.name, i, c.expected[i], *r
                );
            }
        }
    }
}
