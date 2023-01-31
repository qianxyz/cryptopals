pub mod hex {
    /// Encode bytes into a hex string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Decode bytes from a hex string.
    pub fn decode(s: impl AsRef<str>) -> Option<Vec<u8>> {
        if s.as_ref().len() % 2 != 0 {
            return None;
        }

        let mut v = Vec::with_capacity(s.as_ref().len() / 2);

        for pair in s.as_ref().as_bytes().chunks_exact(2) {
            let s2 = std::str::from_utf8(pair).ok()?;
            let b = u8::from_str_radix(s2, 16).ok()?;
            v.push(b);
        }

        Some(v)
    }
}

pub mod base64 {
    /// Encode bytes into Base64.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let capacity = (bytes.as_ref().len() + 2) / 3 * 4;
        let mut s = String::with_capacity(capacity);

        // convert a byte into Base64 char
        fn b2c(b: u8) -> char {
            match b {
                0..=25 => (b + b'A') as char,
                26..=51 => (b - 26 + b'a') as char,
                52..=61 => (b - 52 + b'0') as char,
                62 => '+',
                63 => '/',
                _ => unreachable!(),
            }
        }

        let mut iter = bytes.as_ref().chunks_exact(3);
        for ck in iter.by_ref() {
            s.push(b2c(ck[0] >> 2));
            s.push(b2c((ck[0] & 0b11) << 4 | ck[1] >> 4));
            s.push(b2c((ck[1] & 0b1111) << 2 | ck[2] >> 6));
            s.push(b2c(ck[2] & 0b111111));
        }

        let r = iter.remainder();
        match r.len() {
            0 => (),
            1 => {
                s.push(b2c(r[0] >> 2));
                s.push(b2c((r[0] & 0b11) << 4));
                s.push_str("==");
            }
            2 => {
                s.push(b2c(r[0] >> 2));
                s.push(b2c((r[0] & 0b11) << 4 | r[1] >> 4));
                s.push(b2c((r[1] & 0b1111) << 2));
                s.push('=');
            }
            _ => unreachable!(),
        }

        s
    }

    /// Decode bytes from Base64.
    /// Does not check if the input has valid padding.
    pub fn decode(s: impl AsRef<str>) -> Option<Vec<u8>> {
        let capacity = s.as_ref().len() / 4 * 3;
        let mut v = Vec::with_capacity(capacity);

        let mut bit_buf = 0u32;
        let mut char_count = 0;
        for (i, c) in s.as_ref().chars().enumerate() {
            if c == '=' {
                break;
            }

            let b = match c {
                'A'..='Z' => c as u8 - b'A',
                'a'..='z' => c as u8 - b'a' + 26,
                '0'..='9' => c as u8 - b'0' + 52,
                '+' => 62,
                '/' => 63,
                _ => return None,
            };
            bit_buf |= (b as u32) << (6 * (3 - i % 4));

            // flush out the buffer every 4 chars
            if i % 4 == 3 {
                v.push((bit_buf >> 16) as u8);
                v.push((bit_buf >> 8) as u8);
                v.push(bit_buf as u8);
                bit_buf = 0; // clear buffer
            }

            char_count += 1;
        }

        // flush the remaining in the buffer
        match char_count % 4 {
            0 => (),
            2 => v.push((bit_buf >> 16) as u8),
            3 => {
                v.push((bit_buf >> 16) as u8);
                v.push((bit_buf >> 8) as u8);
            }
            _ => unreachable!(),
        }

        Some(v)
    }
}

/// Byte-by-byte xor.
fn xor(base: impl AsRef<[u8]>, key: impl AsRef<[u8]>) -> Vec<u8> {
    base.as_ref()
        .into_iter()
        .zip(key.as_ref().into_iter().cycle())
        .map(|(b, k)| b ^ k)
        .collect()
}

/// The score of a string, based on character frequency.
/// A lower score means it's more likely to be real English text.
fn char_freq_score(s: impl AsRef<str>) -> f32 {
    const EXPECTED_FREQ: [(char, f32); 27] = [
        (' ', 0.18032), // This is essential
        ('a', 0.08167),
        ('b', 0.01492),
        ('c', 0.02782),
        ('d', 0.04253),
        ('e', 0.12702),
        ('f', 0.02228),
        ('g', 0.02015),
        ('h', 0.06094),
        ('i', 0.06966),
        ('j', 0.00153),
        ('k', 0.00772),
        ('l', 0.04025),
        ('m', 0.02406),
        ('n', 0.06749),
        ('o', 0.07507),
        ('p', 0.01929),
        ('q', 0.00095),
        ('r', 0.05987),
        ('s', 0.06327),
        ('t', 0.09056),
        ('u', 0.02758),
        ('v', 0.00978),
        ('w', 0.02360),
        ('x', 0.00150),
        ('y', 0.01974),
        ('z', 0.00074),
    ];

    let mut count = std::collections::HashMap::new();
    let mut total_chars = 0;
    for c in s.as_ref().chars() {
        *count.entry(c.to_ascii_lowercase()).or_insert(0) += 1;
        total_chars += 1;
    }

    let mut score = 0.0;
    for (c, expect) in EXPECTED_FREQ.iter() {
        let actual = *count.get(c).unwrap_or(&0) as f32 / total_chars as f32;
        score += (expect - actual).abs();
    }

    score
}

// TODO: build a struct for plaintext, key and its score.

/// Crack single character XOR encryption.
/// Returns the plaintext with its score (lower is better),
/// or None if every possible XOR is not valid UTF-8.
pub fn single_char_xor_decrypt(cipher: impl AsRef<[u8]>) -> Option<(f32, String)> {
    (0..128u8)
        .filter_map(|k| {
            String::from_utf8(xor(&cipher, [k]))
                .map(|s| (char_freq_score(&s), s))
                .ok()
        })
        .min_by(|x, y| x.0.total_cmp(&y.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_decode() {
        let tests = [
            ("light work.", "bGlnaHQgd29yay4="),
            ("light work", "bGlnaHQgd29yaw=="),
            ("light wor", "bGlnaHQgd29y"),
            ("light wo", "bGlnaHQgd28="),
            ("light w", "bGlnaHQgdw=="),
        ];

        for (plain, b64) in tests {
            assert_eq!(base64::encode(plain.as_bytes()), b64);
            assert_eq!(base64::decode(b64).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn hex_to_base64() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes: Vec<u8> = hex::decode(hex).unwrap();

        assert_eq!(base64::encode(bytes), base64);
    }

    #[test]
    fn equal_length_xor() {
        let s1 = "1c0111001f010100061a024b53535009181c";
        let s2 = "686974207468652062756c6c277320657965";
        let s3 = "746865206b696420646f6e277420706c6179";

        let b1: Vec<u8> = hex::decode(s1).unwrap();
        let b2: Vec<u8> = hex::decode(s2).unwrap();
        let b3 = xor(b1, b2);

        assert_eq!(hex::encode(b3), s3);
    }

    #[test]
    fn repeating_key_xor() {
        let plain = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
        let key = "ICE";
        let out = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

        let hex = hex::encode(xor(plain.as_bytes(), key.as_bytes()));

        assert_eq!(hex, out);
    }
}
