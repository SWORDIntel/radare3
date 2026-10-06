#![forbid(unsafe_code)]

use std::collections::BTreeMap;

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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct XrefIndex {
    by_from: BTreeMap<Address, Vec<usize>>,
    by_to: BTreeMap<Address, Vec<usize>>,
}

impl XrefIndex {
    pub fn build(xrefs: &[Xref]) -> Self {
        let mut index = Self::default();

        for (position, xref) in xrefs.iter().enumerate() {
            index.by_from.entry(xref.from).or_default().push(position);
            index.by_to.entry(xref.to).or_default().push(position);
        }

        index
    }

    pub fn outgoing<'a>(
        &'a self,
        xrefs: &'a [Xref],
        address: Address,
    ) -> impl Iterator<Item = &'a Xref> + 'a {
        self.by_from
            .get(&address)
            .into_iter()
            .flatten()
            .filter_map(move |position| xrefs.get(*position))
    }

    pub fn incoming<'a>(
        &'a self,
        xrefs: &'a [Xref],
        address: Address,
    ) -> impl Iterator<Item = &'a Xref> + 'a {
        self.by_to
            .get(&address)
            .into_iter()
            .flatten()
            .filter_map(move |position| xrefs.get(*position))
    }

    pub fn outgoing_count(&self, address: Address) -> usize {
        self.by_from.get(&address).map_or(0, Vec::len)
    }

    pub fn incoming_count(&self, address: Address) -> usize {
        self.by_to.get(&address).map_or(0, Vec::len)
    }

    pub fn source_address_count(&self) -> usize {
        self.by_from.len()
    }

    pub fn target_address_count(&self) -> usize {
        self.by_to.len()
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
        assert_eq!(index.source_address_count(), 3);
        assert_eq!(index.target_address_count(), 2);
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
