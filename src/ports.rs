use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;
use std::ops::RangeInclusive;

/// Continuous port range.
#[derive(Clone)]
enum Prange {
    Range((u16, u16)), // range of continous ports from min to max, inclusive
    Atom(u16),         // signle port
}

impl Prange {
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
    step: u16,           // number of ports to return for a step
    curr: (u16, u16),    // current status of iterator, (index in ranges, current port)
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

    /// Adjust the step, that is, maximum number of ports contained in each
    /// returned PortIterator.
    pub fn adjust_step(&mut self, step: u16) {
        self.step = step;
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
    Ok(Prange::Range((min, max)))
}

impl TryFrom<&str> for PortRange {
    type Error = Error;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        let inputs = if val.contains(',') {
            val.split(',').collect()
        } else {
            vec![val]
        };
        let mut ranges = Vec::with_capacity(inputs.len());
        for s in inputs {
            if !s.contains('-') {
                ranges.push(Prange::Atom(s.trim().parse()?));
            } else {
                ranges.push(parse_single_range(s.trim())?);
            }
        }
        let initial_index = ranges[0].min();

        Ok(PortRange {
            ranges,
            step: 100,
            curr: (0, initial_index),
        })
    }
}

/// select next range to scan.
fn select_range(range: &Prange, start: u16, step: u16) -> (u16, u16) {
    let end = {
        if start as u32 + (step - 1) as u32 >= range.max() as u32 {
            range.max()
        } else {
            start + step - 1
        }
    };
    (start, end)
}

impl Iterator for PortRange {
    type Item = PortIterator;

    fn next(&mut self) -> Option<Self::Item> {
        let mut count = 0;
        let mut ranges = Vec::new();
        loop {
            if self.curr.0 >= self.ranges.len() as u16 {
                break;
            }
            let current_range = &self.ranges[self.curr.0 as usize];
            let start = if self.curr.1 == 0 {
                // start from the start of the range
                // if we changed to new range on last iteration, we have reset
                // the curr.1 to 0 without knowing where to actually start
                current_range.min()
            } else {
                self.curr.1
            };

            let (min, max) = select_range(current_range, start, self.step - count);
            if max == current_range.max() {
                self.curr = (self.curr.0 + 1, 0);
            } else {
                self.curr.1 = max + 1;
            }
            ranges.push(min..=max);
            count += max - min + 1;
            if count >= self.step {
                break;
            }
        }
        if !ranges.is_empty() {
            Some(PortIterator::new(ranges))
        } else {
            None
        }
    }
}

/// Iterator returned by `PortRange` which can be used to iterate single port
/// values.
#[derive(Clone)]
pub struct PortIterator {
    ranges: Vec<RangeInclusive<u16>>,
    idx: usize,
}

impl PortIterator {
    /// Create new iterator which is used to iterator given ranges
    fn new(ranges: Vec<RangeInclusive<u16>>) -> Self {
        PortIterator { ranges, idx: 0 }
    }
}

impl Iterator for PortIterator {
    type Item = u16;
    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.ranges.len() {
            let next = self.ranges[self.idx].next();
            if next.is_none() {
                // This range is done, move to next
                self.idx += 1;
                continue;
            }
            return next;
        }
        None
    }
}

impl fmt::Debug for PortIterator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.ranges.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_elems(r: &mut PortIterator, expected: &[u16]) {
        let values: Vec<u16> = r.collect();
        assert_eq!(expected, values)
    }

    fn check_elems_range(r: &mut PortIterator, expected: RangeInclusive<u16>) {
        let expected_data = expected.collect::<Vec<u16>>();
        let values: Vec<u16> = r.collect();
        assert_eq!(expected_data, values)
    }

    fn test_simple_range(input: &str, expected: &[u16]) {
        let r = PortRange::try_from(input).unwrap();
        assert_eq!(r.port_count() as usize, expected.len());
        check_elems(
            r.collect::<Vec<PortIterator>>().get_mut(0).unwrap(),
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
    fn multiple_steps() {
        let r = PortRange::try_from("1-250").unwrap();
        assert_eq!(r.port_count(), 250);
        let mut ranges = r.collect::<Vec<PortIterator>>();
        assert_eq!(ranges.len(), 3);
        check_elems(ranges.get_mut(0).unwrap(), &(1..101).collect::<Vec<u16>>());
        check_elems(
            ranges.get_mut(1).unwrap(),
            &(101..201).collect::<Vec<u16>>(),
        );
        check_elems(
            ranges.get_mut(2).unwrap(),
            &(201..251).collect::<Vec<u16>>(),
        )
    }

    #[test]
    fn test_full_range() {
        let r = PortRange::try_from("1-65535").unwrap();
        assert_eq!(r.port_count(), 65535);
        let mut ranges = r.collect::<Vec<PortIterator>>();
        assert_eq!(ranges.len(), 656);
        for (idx, i) in (1..65535).step_by(100).enumerate() {
            let end = if idx < 655 { i + 99 } else { 65535 };
            check_elems_range(ranges.get_mut(idx).unwrap(), i..=end);
        }
    }

    #[test]
    fn complex_steps() {
        let mut r = PortRange::try_from("1-10,20-30,41-42").unwrap();
        assert_eq!(r.port_count(), 23);
        r.adjust_step(5);
        let mut ranges = r.collect::<Vec<PortIterator>>();
        assert_eq!(ranges.len(), 5);
        check_elems_range(ranges.get_mut(0).unwrap(), 1..=5);
        check_elems_range(ranges.get_mut(1).unwrap(), 6..=10);
        check_elems_range(ranges.get_mut(2).unwrap(), 20..=24);
        check_elems_range(ranges.get_mut(3).unwrap(), 25..=29);
        check_elems(ranges.get_mut(4).unwrap(), &[30, 41, 42]);
    }

    #[test]
    fn ranges_and_atoms() {
        let r = PortRange::try_from("22,80,8000-8090,4000-4025").unwrap();
        assert_eq!(r.port_count(), 119);
        let mut ranges = r.collect::<Vec<PortIterator>>();
        let mut expected1 = vec![22, 80];
        expected1.append(&mut (8000..=8090).collect());
        expected1.append(&mut (4000..=4006).collect());
        check_elems(ranges.get_mut(0).unwrap(), &expected1);
        check_elems_range(ranges.get_mut(1).unwrap(), 4007..=4025);
    }
}
