use std::collections::BTreeMap;

static MARKER_A: &[u8] = b"RADARE3_SEARCH_MARKER_ALPHA";
static MARKER_B: &[u8] = b"RADARE3_SEARCH_MARKER_BETA";
static WIDE_MARKER: [u16; 19] = [
    b'R' as u16,
    b'A' as u16,
    b'D' as u16,
    b'A' as u16,
    b'R' as u16,
    b'E' as u16,
    b'3' as u16,
    b'_' as u16,
    b'W' as u16,
    b'I' as u16,
    b'D' as u16,
    b'E' as u16,
    b'_' as u16,
    b'M' as u16,
    b'A' as u16,
    b'R' as u16,
    b'K' as u16,
    b'E' as u16,
    b'R' as u16,
];

#[inline(never)]
fn mix(mut value: u64) -> u64 {
    for i in 0..40u64 {
        if (value ^ i) & 1 == 1 {
            value = value.wrapping_mul(0x9e37_79b1_85eb_ca87) ^ (value >> 7);
        } else {
            value = value.wrapping_add(0x517c_c1b7_2722_0a95) ^ (value << 11);
        }
    }
    value
}

#[inline(never)]
fn fold_digits(input: &str) -> u64 {
    input
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(u64::from)
        .fold(0u64, |acc, b| mix(acc ^ b))
}

enum Lane {
    Even(u64),
    Odd(u64),
    Carry(u64, u64),
}

#[inline(never)]
fn drive(lanes: &[Lane]) -> u64 {
    let mut acc = 0u64;
    for lane in lanes {
        acc = match lane {
            Lane::Even(v) => mix(acc ^ v),
            Lane::Odd(v) => mix(acc.wrapping_add(*v)),
            Lane::Carry(a, b) => mix(acc ^ a.wrapping_mul(*b)),
        };
    }
    acc
}

fn main() {
    let seed = std::env::args().count() as u64;
    let mut table = BTreeMap::new();
    let mut lanes = Vec::with_capacity(384);

    for i in 0..384u64 {
        let v = i.wrapping_mul(2_654_435_761).wrapping_add(seed);
        match v % 3 {
            0 => lanes.push(Lane::Even(v)),
            1 => lanes.push(Lane::Odd(v)),
            _ => lanes.push(Lane::Carry(v, i | 1)),
        }
        table.insert(v & 0x1ff, v.rotate_left((i & 31) as u32));
    }

    let mut acc = drive(&lanes);
    for value in table.values() {
        acc ^= mix(*value);
    }
    acc ^= fold_digits("r3bench-rust-dispatch-2026");
    acc = acc
        .wrapping_add(u64::from(MARKER_A[0]) + u64::from(MARKER_B[1]) + u64::from(WIDE_MARKER[2]));

    if std::env::args_os().next().is_none() {
        use std::io::Write;
        let _ = std::io::stdout().write_all(MARKER_A);
        let _ = std::io::stdout().write_all(MARKER_B);
    }

    println!("{acc}");
}
