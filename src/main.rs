mod basics;

use basics::{base64, hex, repeating_key_xor_decrypt, single_char_xor_decrypt};

fn main() {
    q3();
    q4();
    q6();
}

fn q3() {
    let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    let bytes = hex::decode(hex).unwrap();
    let plains = single_char_xor_decrypt(bytes);

    println!("{}", plains[0]);
}

fn q4() {
    let s = include_str!("../data/4.txt");

    let plains: Vec<_> = s
        .split('\n')
        .flat_map(|s| {
            let bytes: Vec<u8> = hex::decode(s).unwrap();
            single_char_xor_decrypt(bytes)
        })
        .collect();

    println!("{}", plains[0]);
}

fn q6() {
    let s = include_str!("../data/6.txt");
    let s = s.replace("\n", "");

    let bytes = base64::decode(s).unwrap();
    let plain = repeating_key_xor_decrypt(bytes);

    println!("{plain}");
}
