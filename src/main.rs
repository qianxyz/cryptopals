mod basics;

use basics::{hex, single_char_xor_decrypt};

fn main() {
    single_byte_xor();
    single_byte_xor_detect();
}

fn single_byte_xor() {
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let bytes: Vec<u8> = hex::decode(hex).unwrap();
    let (score, plain) = single_char_xor_decrypt(bytes).unwrap();

    println!("{plain} {score}");
}

fn single_byte_xor_detect() {
    let s = include_str!("../data/4.txt");

    let (score, plain) = s
        .split('\n')
        .filter_map(|s| {
            let bytes: Vec<u8> = hex::decode(s).unwrap();
            single_char_xor_decrypt(bytes)
        })
        .min_by(|x, y| x.0.total_cmp(&y.0))
        .unwrap();

    println!("{plain} {score}");
}
