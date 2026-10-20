use std::fs::read;

use p384::{NistP384, elliptic_curve::{ScalarValue, SecretKey}};
use x509_cert::{Certificate, der::Decode };

const KEYS: &[(&str, u64)] = &[
    ("certs/EMOVTLSCAG3C.crt", 4),
    ("certs/EMEVTLSCAG3C.crt", 56),
    ("certs/EMOVCSCAG3B.crt", 66),
    ("certs/EMEVTLSCAG3B.crt", 115),
    ("certs/EMOVTLSCAG3B.crt", 155),
    ("certs/EMDVTLSCAG3B.crt", 156),
    ("certs/EMDVTLSCAG3C.crt", 230),
    ("certs/EMOVCSCAG3C.crt", 237),
];

fn make_key(n: u64) -> SecretKey<NistP384> {
    SecretKey::<NistP384>::from_scalar(ScalarValue::<NistP384>::new(n.into()).expect("scalar")).expect("private key")
}

fn verify_key(cert_path: &str, private_key: u64) -> bool {
    let contents = read(cert_path).expect("failed to read");
    let cert = Certificate::from_der(&contents).expect("decode cert");
    let actual_key = cert.tbs_certificate().subject_public_key_info().subject_public_key.raw_bytes();
    let private_key = make_key(private_key);
    let given_key = private_key.public_key().to_sec1_bytes();
    actual_key == &*given_key
}

fn main() -> Result<(), &'static str> {
    println!("Verifying leaked keys");
    let mut failures = 0;
    for (path, key) in KEYS {
        println!("Verifying {path}, expecting key {key}...");
        if verify_key(path, *key) {
            println!("{path} matches key {key}!")
        } else {
            println!("{path} does not match key {key}!");
            failures += 1;
        }
    }
    if failures > 0 {
        Err("Verification failed for some keys!")
    } else {
        println!("all verified!");
        Ok(())
    }
}
