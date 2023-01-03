#![allow(dead_code)]

use ckb_testtool::ckb_hash::blake2b_256;
use keccak_hash::keccak_256;
use sha2::{Digest, Sha256};

pub const EXTENSION_SMT_TYPE: [u8; 2] = [0xFFu8, 0x00u8]; // 0xFF00
pub const SUB_TYPE_SUBKEY: &str = "subkey";
pub const SECP256R1_ALG_INDEX: [u8; 2] = [0x00, 0x01]; // 0x0001
pub const SECP256K1_ALG_INDEX: [u8; 2] = [0x00, 0x02]; // 0x0001
pub const PADDING: u8 = 0xFF;
pub const BYTE9_ZERO: [u8; 9] = [0u8; 9];

pub const SCRIPT_TYPE: u8 = 1;
pub const COTA_TYPE_CODE_HASH: [u8; 32] = [
    137, 205, 128, 3, 160, 234, 248, 230, 94, 12, 49, 82, 91, 125, 29, 92, 27, 236, 239, 210, 234,
    117, 187, 76, 255, 135, 129, 10, 227, 119, 100, 216,
];

// personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32
pub const ETH_PREFIX: [u8; 28] = [
    0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64,
    0x20, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32,
];

pub fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

pub fn base64_hex(message: &[u8]) -> Vec<u8> {
    let msg = hex::encode(message);
    let mut output: Vec<u8> = Vec::new();
    output.resize(msg.len() * 4 / 3 + 4, 0);
    let bytes_written = base64::encode_config_slice(&msg, base64::STANDARD_NO_PAD, &mut output);
    output.resize(bytes_written, 0);
    output
}

pub fn keccak_160(message: &[u8]) -> [u8; 20] {
    let mut result = [0u8; 32];
    keccak_256(message, &mut result);

    let mut hash = [0u8; 20];
    hash.copy_from_slice(&result[12..]);
    hash
}

// AuthData: https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
// ClientData: https://www.w3.org/TR/webauthn-2/#clientdatajson-serialization
pub fn generate_sign_origin_data(message: &mut [u8], challenge_error: bool) -> (Vec<u8>, Vec<u8>) {
    let challenge = hex::encode(message);
    let auth_data =
        hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630162f9fb77")
            .unwrap();
    let client_data =
        format!("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22{}222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38303030222c2263726f73734f726967696e223a66616c73657d", challenge);
    let mut client_data_bytes = hex::decode(client_data).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(client_data_bytes.clone());
    let mut client_data_hash: Vec<u8> = hasher.finalize().to_vec();

    let mut sign_data = auth_data.clone();
    sign_data.append(&mut client_data_hash);

    let mut sign_origin_data = auth_data;
    if challenge_error {
        client_data_bytes.reverse();
    }
    sign_origin_data.append(&mut client_data_bytes);

    (sign_data, sign_origin_data)
}
