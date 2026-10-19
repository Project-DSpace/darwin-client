//! Postcard's encodings of the few shapes the hashes cover, written out so
//! that hashing a value's wire bytes can't fail. Each matches what postcard
//! writes for the same value; the tests check them against it.

/// A `u64` as postcard writes it: seven bits a byte, lowest first, with the
/// top bit set on every byte but the last.
pub(crate) fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value.to_le_bytes()[0] | 0x80);
        value >>= 7;
    }
    out.push(value.to_le_bytes()[0]);
}

/// An `Option<u64>`: `00`, or `01` and the value.
pub(crate) fn put_option_varint(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            put_varint(out, value);
        }
        None => out.push(0),
    }
}

/// An `Option` of a byte string (`Vec<u8>` or `String`): `00`, or `01`, its
/// length and its bytes.
pub(crate) fn put_option_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            out.push(1);
            put_varint(out, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            out.extend_from_slice(bytes);
        }
        None => out.push(0),
    }
}

/// An `Option<[u8; 32]>`: `00`, or `01` and the 32 bytes.
pub(crate) fn put_option_array(out: &mut Vec<u8>, value: Option<&[u8; 32]>) {
    match value {
        Some(bytes) => {
            out.push(1);
            out.extend_from_slice(bytes);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_are_postcards() {
        let edges = [
            0,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            1_790_000_000,
            u64::from(u32::MAX),
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ];
        for value in edges.into_iter().chain((0..64).map(|shift| 1u64 << shift)) {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(out, postcard::to_stdvec(&value).unwrap(), "{value}");
            for option in [Some(value), None] {
                let mut out = Vec::new();
                put_option_varint(&mut out, option);
                assert_eq!(out, postcard::to_stdvec(&option).unwrap(), "{option:?}");
            }
        }
        let mut out = Vec::new();
        put_varint(&mut out, u64::MAX);
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn byte_strings_and_arrays_are_postcards() {
        for len in [0, 1, 127, 128, 255, 300, 5_261] {
            let bytes: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
            for option in [Some(bytes.clone()), None] {
                let mut out = Vec::new();
                put_option_bytes(&mut out, option.as_deref());
                assert_eq!(out, postcard::to_stdvec(&option).unwrap(), "{len}");
            }
            let text: Option<String> = Some("é".repeat(len / 2));
            let mut out = Vec::new();
            put_option_bytes(&mut out, text.as_deref().map(str::as_bytes));
            assert_eq!(out, postcard::to_stdvec(&text).unwrap(), "{len}");
        }
        for option in [Some([0xa5; 32]), None] {
            let mut out = Vec::new();
            put_option_array(&mut out, option.as_ref());
            assert_eq!(out, postcard::to_stdvec(&option).unwrap());
        }
    }
}
