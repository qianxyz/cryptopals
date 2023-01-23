/// A string that is valid hex.
struct Hex(String);

/// A string that is valid base64.
struct Base64(String);

#[derive(Debug)]
struct BadHex; // TODO: add information

impl std::str::FromStr for Hex {
    type Err = BadHex;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // a valid hex string must have even length
        if s.len() % 2 != 0 {
            return Err(BadHex);
        }

        // and only contains 0-9, a-f, A-F
        for c in s.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(BadHex);
            }
        }

        Ok(Hex(s.to_owned()))
    }
}

impl std::fmt::Display for Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for Base64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Convert a hex string to its underlying bytes.
impl From<Hex> for Vec<u8> {
    fn from(s: Hex) -> Self {
        s.0.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}

/// Encode bytes to hex.
impl<T: AsRef<[u8]>> From<T> for Hex {
    fn from(bytes: T) -> Self {
        let s: String = bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        Hex(s)
    }
}

/// Encode bytes to Base64.
impl<T: AsRef<[u8]>> From<T> for Base64 {
    fn from(bytes: T) -> Self {
        let s: String = bytes
            .as_ref()
            .chunks_exact(3) // TODO: handle the remaining
            .flat_map(|tr| {
                [
                    tr[0] >> 2,
                    (tr[0] & 0b11) << 4 | tr[1] >> 4,
                    (tr[1] & 0b1111) << 2 | tr[2] >> 6,
                    tr[2] & 0b111111,
                ]
                .into_iter()
                .map(|b| match b {
                    0..=25 => (b + b'A') as char,
                    26..=51 => (b - 26 + b'a') as char,
                    52..=61 => (b - 52 + b'0') as char,
                    62 => '+',
                    63 => '/',
                    _ => unreachable!(),
                })
            })
            .collect();

        Base64(s)
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

/// Crack single character XOR encryption.
/// Returns the plaintext with its score (lower is better),
/// or None if every possible XOR is not valid UTF-8.
fn single_char_xor_decrypt(cipher: impl AsRef<[u8]>) -> Option<(f32, String)> {
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
    fn q1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let bytes: Vec<u8> = hex.parse::<Hex>().unwrap().into();

        assert_eq!(Base64::from(bytes).to_string(), base64);
    }

    #[test]
    fn q2() {
        let s1 = "1c0111001f010100061a024b53535009181c";
        let s2 = "686974207468652062756c6c277320657965";
        let s3 = "746865206b696420646f6e277420706c6179";

        let b1: Vec<u8> = s1.parse::<Hex>().unwrap().into();
        let b2: Vec<u8> = s2.parse::<Hex>().unwrap().into();
        let b3 = xor(b1, b2);

        assert_eq!(Hex::from(b3).to_string(), s3);
    }

    #[test]
    fn q3() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        let bytes: Vec<u8> = hex.parse::<Hex>().unwrap().into();
        let (_, plain) = single_char_xor_decrypt(bytes).unwrap();

        assert_eq!(plain, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn q4() {
        let s = include_str!("../data/4.txt");

        let (_, plain) = s
            .split('\n')
            .filter_map(|s| {
                let bytes: Vec<u8> = s.parse::<Hex>().unwrap().into();
                single_char_xor_decrypt(bytes)
            })
            .min_by(|x, y| x.0.total_cmp(&y.0))
            .unwrap();

        assert_eq!(plain, "Now that the party is jumping\n");
    }
}
