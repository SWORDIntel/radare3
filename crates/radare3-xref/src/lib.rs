#![forbid(unsafe_code)]

use radare3_types::{Address, XrefId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XrefKind {
    Call,
    Code,
    Data,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Xref {
    pub id: XrefId,
    pub from: Address,
    pub to: Address,
    pub kind: XrefKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct XrefSpan {
    address: Address,
    start: usize,
    len: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FlatXrefDirection {
    spans: Vec<XrefSpan>,
    positions: Vec<usize>,
    prefix_counts: Vec<usize>,
}

impl FlatXrefDirection {
    fn build(xrefs: &[Xref], key: impl Fn(&Xref) -> Address) -> Self {
        let mut keyed = xrefs
            .iter()
            .enumerate()
            .map(|(position, xref)| (key(xref), position))
            .collect::<Vec<_>>();
        keyed.sort_unstable_by_key(|(address, position)| (*address, *position));

        let mut spans = Vec::new();
        let mut positions = Vec::with_capacity(keyed.len());
        let mut prefix_counts = vec![0];
        let mut cursor = 0;

        while cursor < keyed.len() {
            let address = keyed[cursor].0;
            let start = positions.len();

            while cursor < keyed.len() && keyed[cursor].0 == address {
                positions.push(keyed[cursor].1);
                cursor += 1;
            }

            let len = positions.len() - start;
            spans.push(XrefSpan {
                address,
                start,
                len,
            });
            prefix_counts.push(positions.len());
        }

        Self {
            spans,
            positions,
            prefix_counts,
        }
    }

    fn positions(&self, address: Address) -> &[usize] {
        let Ok(span_index) = self
            .spans
            .binary_search_by_key(&address, |span| span.address)
        else {
            return &[];
        };
        let Some(span) = self.spans.get(span_index) else {
            return &[];
        };
        let Some(end) = span.start.checked_add(span.len) else {
            return &[];
        };

        self.positions.get(span.start..end).unwrap_or_default()
    }

    fn count(&self, address: Address) -> usize {
        self.positions(address).len()
    }

    fn count_in_range(&self, start: Address, end: Address) -> usize {
        if start >= end {
            return 0;
        }

        let first = self.spans.partition_point(|span| span.address < start);
        let after_last = self.spans.partition_point(|span| span.address < end);
        let Some(before) = self.prefix_counts.get(first) else {
            return 0;
        };
        let Some(after) = self.prefix_counts.get(after_last) else {
            return 0;
        };

        after.saturating_sub(*before)
    }

    fn key_count(&self) -> usize {
        self.spans.len()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct XrefIndex {
    by_from: FlatXrefDirection,
    by_to: FlatXrefDirection,
}

impl XrefIndex {
    pub fn build(xrefs: &[Xref]) -> Self {
        Self {
            by_from: FlatXrefDirection::build(xrefs, |xref| xref.from),
            by_to: FlatXrefDirection::build(xrefs, |xref| xref.to),
        }
    }

    pub fn outgoing<'a>(
        &'a self,
        xrefs: &'a [Xref],
        address: Address,
    ) -> impl Iterator<Item = &'a Xref> + 'a {
        self.by_from
            .positions(address)
            .iter()
            .filter_map(move |position| xrefs.get(*position))
    }

    pub fn incoming<'a>(
        &'a self,
        xrefs: &'a [Xref],
        address: Address,
    ) -> impl Iterator<Item = &'a Xref> + 'a {
        self.by_to
            .positions(address)
            .iter()
            .filter_map(move |position| xrefs.get(*position))
    }

    pub fn outgoing_count(&self, address: Address) -> usize {
        self.by_from.count(address)
    }

    pub fn incoming_count(&self, address: Address) -> usize {
        self.by_to.count(address)
    }

    pub fn outgoing_count_in_range(&self, start: Address, end: Address) -> usize {
        self.by_from.count_in_range(start, end)
    }

    pub fn source_address_count(&self) -> usize {
        self.by_from.key_count()
    }

    pub fn target_address_count(&self) -> usize {
        self.by_to.key_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_xrefs() -> Vec<Xref> {
        vec![
            Xref {
                id: XrefId(0),
                from: Address(0x1000),
                to: Address(0x2000),
                kind: XrefKind::Call,
            },
            Xref {
                id: XrefId(1),
                from: Address(0x1000),
                to: Address(0x3000),
                kind: XrefKind::Data,
            },
            Xref {
                id: XrefId(2),
                from: Address(0x1100),
                to: Address(0x2000),
                kind: XrefKind::Code,
            },
            Xref {
                id: XrefId(3),
                from: Address(0x1200),
                to: Address(0x2000),
                kind: XrefKind::Data,
            },
        ]
    }

    #[test]
    fn indexes_incoming_and_outgoing_without_reordering() {
        let xrefs = sample_xrefs();
        let index = XrefIndex::build(&xrefs);

        let outgoing = index
            .outgoing(&xrefs, Address(0x1000))
            .map(|xref| xref.id)
            .collect::<Vec<_>>();
        let incoming = index
            .incoming(&xrefs, Address(0x2000))
            .map(|xref| xref.id)
            .collect::<Vec<_>>();

        assert_eq!(outgoing, vec![XrefId(0), XrefId(1)]);
        assert_eq!(incoming, vec![XrefId(0), XrefId(2), XrefId(3)]);
        assert_eq!(index.outgoing_count(Address(0x1000)), 2);
        assert_eq!(index.incoming_count(Address(0x2000)), 3);
        assert_eq!(
            index.outgoing_count_in_range(Address(0x1000), Address(0x1200)),
            3
        );
        assert_eq!(
            index.outgoing_count_in_range(Address(0x1200), Address(0x1201)),
            1
        );
        assert_eq!(
            index.outgoing_count_in_range(Address(0x1200), Address(0x1200)),
            0
        );
        assert_eq!(
            index.outgoing_count_in_range(Address(0x1300), Address(0x1200)),
            0
        );
        assert_eq!(index.source_address_count(), 3);
        assert_eq!(index.target_address_count(), 2);
    }

    #[test]
    fn flat_postings_preserve_original_order_for_unsorted_keys() {
        let xrefs = vec![
            Xref {
                id: XrefId(0),
                from: Address(0x2000),
                to: Address(0x4000),
                kind: XrefKind::Data,
            },
            Xref {
                id: XrefId(1),
                from: Address(0x1000),
                to: Address(0x4000),
                kind: XrefKind::Call,
            },
            Xref {
                id: XrefId(2),
                from: Address(0x2000),
                to: Address(0x3000),
                kind: XrefKind::Code,
            },
            Xref {
                id: XrefId(3),
                from: Address(0x1000),
                to: Address(0x3000),
                kind: XrefKind::Data,
            },
        ];
        let index = XrefIndex::build(&xrefs);

        assert_eq!(
            index
                .outgoing(&xrefs, Address(0x1000))
                .map(|xref| xref.id)
                .collect::<Vec<_>>(),
            vec![XrefId(1), XrefId(3)]
        );
        assert_eq!(
            index
                .incoming(&xrefs, Address(0x4000))
                .map(|xref| xref.id)
                .collect::<Vec<_>>(),
            vec![XrefId(0), XrefId(1)]
        );
    }

    #[test]
    fn missing_addresses_return_empty_iterators() {
        let xrefs = sample_xrefs();
        let index = XrefIndex::build(&xrefs);

        assert_eq!(index.outgoing(&xrefs, Address(0xdead)).count(), 0);
        assert_eq!(index.incoming(&xrefs, Address(0xbeef)).count(), 0);
        assert_eq!(index.outgoing_count(Address(0xdead)), 0);
        assert_eq!(index.incoming_count(Address(0xbeef)), 0);
    }
}
