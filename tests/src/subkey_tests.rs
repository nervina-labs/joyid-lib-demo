use crate::helper::{base64_hex, blake160, generate_sign_origin_data, keccak_160};
use crate::helper::{
    COTA_TYPE_CODE_HASH, ETH_PREFIX, SCRIPT_TYPE, SECP256K1_ALG_INDEX, SECP256R1_ALG_INDEX,
    SUB_TYPE_SUBKEY,
};

use super::*;
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::ckb_crypto::secp::{Generator, Privkey};
use ckb_testtool::ckb_hash::new_blake2b;
use ckb_testtool::ckb_types::H256 as CKBH256;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::{self, *},
    prelude::*,
};
use ckb_testtool::context::Context;
use joyid_smt::common::{BytesBuilder, Uint16, Uint32};
use joyid_smt::joyid::SubKeyUnlockEntriesBuilder;
use joyid_smt::smt::{Blake2bHasher, H256, SMT};
use keccak_hash::keccak_256;
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::ecdsa::{signature::Verifier, VerifyingKey};
use rand::{thread_rng, Rng};
use rand_core::OsRng;

const MAX_CYCLES: u64 = 70_000_000;
const WITNESS_LOCK_R1_LEN: usize = 129;
const WITNESS_LOCK_K1_LEN: usize = 86;

// error numbers
const WITNESS_MODE_ERROR: i8 = 7;
const SECP256R1_SIG_VERIFY_ERROR: i8 = 9;
const SECP256K1_SIG_VERIFY_ERROR: i8 = 10;
const CELL_DEP_COTA_CELL_ERROR: i8 = 13;
const SMT_PROOF_VERIFY_FAILED: i8 = 14;
const CELL_DEP_COTA_DATA_ERROR: i8 = 15;

#[derive(PartialEq, Eq, Clone, Copy)]
enum SubkeyError {
    NoErrorWithSecp256r1,
    NoErrorWithSecp256k1,
    WitnessModeError,
    Secp256r1SigVerifyError,
    SMTProofVerifyFailed,
    Secp256k1SigVerifyError,
    CellDepCotaCellError,
    CellDepCotaCellTypeError,
    CellDepCotaDataError,
}

fn is_secp256k1(subkey_error: SubkeyError) -> bool {
    return subkey_error == SubkeyError::NoErrorWithSecp256k1
        || subkey_error == SubkeyError::Secp256k1SigVerifyError;
}

fn generate_unlock_subkey(
    pubkey_hash: [u8; 20],
    subkey_error: SubkeyError,
) -> (Vec<u8>, [u8; 32], SMT) {
    let mut smt = SMT::default();
    let mut rng = thread_rng();
    for _ in 0..3 {
        let key: H256 = rng.gen::<[u8; 32]>().into();
        let value: H256 = rng.gen::<[u8; 32]>().into();
        smt.update(key, value).expect("SMT update leave error");
    }
    let mut update_leaves: Vec<(H256, H256)> = Vec::with_capacity(1);
    let mut key_temp: [u8; 32] = [0; 32];
    key_temp[0..2].copy_from_slice(&[0xFF, 0x00]);
    key_temp[2..8].copy_from_slice(SUB_TYPE_SUBKEY.as_bytes());
    let ext_data = [0u8, 0, 0, 1];
    key_temp[8..12].copy_from_slice(&ext_data);
    let key: H256 = H256::from(key_temp);

    let mut value_temp: [u8; 32] = [0; 32];
    value_temp[0..2].copy_from_slice(&SECP256R1_ALG_INDEX);
    if is_secp256k1(subkey_error) {
        value_temp[0..2].copy_from_slice(&SECP256K1_ALG_INDEX);
    }
    value_temp[2..22].copy_from_slice(&pubkey_hash);
    value_temp[31] = 0xFF;
    let value: H256 = H256::from(value_temp);

    update_leaves.push((key, value));
    smt.update(key, value).expect("SMT update leave error");

    let root_hash = smt.root().clone();
    let mut root_hash_bytes = [0u8; 32];
    root_hash_bytes.copy_from_slice(root_hash.as_slice());

    let merkle_proof = smt
        .merkle_proof(update_leaves.iter().map(|leave| leave.0).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof
        .compile(update_leaves.iter().map(|leave| leave.0).collect())
        .unwrap();
    let verify_result = merkle_proof_compiled
        .verify::<Blake2bHasher>(&root_hash, update_leaves.clone())
        .expect("smt proof verify failed");
    assert!(verify_result, "smt proof verify failed");

    let merkel_proof_vec: Vec<u8> = merkle_proof_compiled.into();

    let merkel_proof_bytes = BytesBuilder::default()
        .extend(merkel_proof_vec.iter().map(|v| Byte::from(*v)))
        .build();

    let alg_index = if is_secp256k1(subkey_error) {
        SECP256K1_ALG_INDEX
    } else {
        SECP256R1_ALG_INDEX
    };
    let unlock_entries = SubKeyUnlockEntriesBuilder::default()
        .alg_index(Uint16::from_slice(&alg_index).unwrap())
        .ext_data(Uint32::from_slice(&ext_data).unwrap())
        .subkey_proof(merkel_proof_bytes)
        .build();

    (unlock_entries.as_slice().to_vec(), root_hash_bytes, smt)
}

fn sign_tx(
    tx: TransactionView,
    unlock_entries: Vec<u8>,
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
    privkey: &Privkey,
    subkey_error: SubkeyError,
) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();

    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut message = [0u8; 32];

    let mut buffer: Vec<u8> = vec![];
    if is_secp256k1(subkey_error) {
        buffer.extend(&ETH_PREFIX);
    }
    buffer.extend(&tx_hash.raw_data());

    // digest the first witness
    let mut unlock_entries_slice: Vec<u8> = vec![];
    unlock_entries_slice.extend(unlock_entries);
    let witness = WitnessArgsBuilder::default()
        .output_type(Some(Bytes::from(unlock_entries_slice)).pack())
        .build();

    let witness_lock_len = if is_secp256k1(subkey_error) {
        WITNESS_LOCK_K1_LEN
    } else {
        WITNESS_LOCK_R1_LEN
    };
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(witness_lock_len, 0);
        buf.into()
    };

    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    buffer.extend(&witness_len.to_le_bytes());
    buffer.extend(&witness_for_digest.as_bytes());
    (1..witnesses_len).for_each(|n| {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        buffer.extend(&witness_len.to_le_bytes());
        buffer.extend(&witness.raw_data());
    });

    let mut signed_signature = if subkey_error == SubkeyError::WitnessModeError {
        vec![0x00u8]
    } else {
        vec![0x02u8]
    };

    if is_secp256k1(subkey_error) {
        keccak_256(&buffer, &mut message);
        let mut message = CKBH256::from(message);
        if subkey_error == SubkeyError::Secp256k1SigVerifyError {
            message = CKBH256::from_slice(&[240u8; 32]).unwrap();
        }
        let signature = privkey.sign_recoverable(&message).expect("sign");
        let mut sig_vec = signature.serialize();
        let public_key = privkey.pubkey().expect("pubkey");
        let mut pubkey_hash = keccak_160(&public_key.0).to_vec();

        signed_signature.append(&mut pubkey_hash);
        signed_signature.append(&mut sig_vec);
    } else {
        let mut blake2b = new_blake2b();
        blake2b.update(&buffer);
        blake2b.finalize(&mut message);
        let mut challenge = base64_hex(&message);
        let (sign_data, mut sign_origin_data) = generate_sign_origin_data(&mut challenge, false);
        let signature = signing_key.sign(&sign_data);
        let result = verifying_key.verify(&sign_data, &signature).is_ok();
        assert!(result, "P256 validate signature fail");
        let mut sig_vec = signature.to_vec();

        let public_key = verifying_key.to_encoded_point(false);
        let mut pubkey = public_key.as_bytes()[1..].to_vec();

        signed_signature.append(&mut pubkey);
        if subkey_error == SubkeyError::Secp256r1SigVerifyError {
            sig_vec.reverse();
        }
        signed_signature.append(&mut sig_vec);
        signed_signature.append(&mut sign_origin_data);
    };

    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(signed_signature)).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for index in 1..witnesses_len {
        signed_witnesses.push(tx.witnesses().get(index).unwrap());
    }
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn create_test_context(subkey_error: SubkeyError) -> (Context, TransactionView) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let public_key = verifying_key.to_encoded_point(false);

    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");

    let pubkey_hash = if is_secp256k1(subkey_error) {
        keccak_160(&pubkey.0)
    } else {
        blake160(&public_key.as_bytes()[1..])
    };

    // deploy contract
    let mut context = Context::default();
    let caller_bin: Bytes = Loader::default().load_binary("joyid-lib-demo");
    let caller_out_point = context.deploy_cell(caller_bin);

    let joyid_bin: Bytes = fs::read("../ckb-lib-joyid/build/joyid.so")
        .expect("load joyid")
        .into();
    let joyid_out_point = context.deploy_cell(joyid_bin);
    let joyid_dep = CellDep::new_builder().out_point(joyid_out_point).build();

    let secp256k1_data_bin = BUNDLED_CELL.get("specs/cells/secp256k1_data").unwrap();
    let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin.to_vec().into());
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_data_out_point)
        .build();

    let mut joyid_args = [0u8; 22];
    // alg index
    joyid_args[1] = 1u8;
    if is_secp256k1(subkey_error) {
        joyid_args[1] = 2u8;
    }
    joyid_args[2..22].copy_from_slice(&pubkey_hash);

    // prepare scripts
    let joyid_lock_script = context
        .build_script(&caller_out_point, joyid_args.to_vec().into())
        .expect("script");
    let joyid_lock_hash = blake160(joyid_lock_script.as_slice());
    let caller_dep = CellDep::new_builder().out_point(caller_out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(joyid_lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let inputs = vec![CellInput::new_builder()
        .previous_output(input_out_point.clone())
        .build()];
    let outputs = vec![CellOutput::new_builder()
        .capacity(500u64.pack())
        .lock(joyid_lock_script.clone())
        .build()];

    let outputs_data = vec![Bytes::new(); 1];
    let mut witnesses = vec![];
    for _ in 0..inputs.len() {
        witnesses.push(Bytes::new())
    }

    let (unlock_entries, root_hash, _) = generate_unlock_subkey(pubkey_hash, subkey_error);
    let cota_code_hash = if subkey_error == SubkeyError::CellDepCotaCellTypeError {
        [245u8; 32]
    } else {
        COTA_TYPE_CODE_HASH
    };
    let cota_type = ScriptBuilder::default()
        .code_hash(Byte32::from_slice(&cota_code_hash).unwrap())
        .hash_type(Byte::from_slice(&[SCRIPT_TYPE]).unwrap())
        .args(Bytes::copy_from_slice(&joyid_lock_hash).pack())
        .build();
    let cota_type_script = if subkey_error == SubkeyError::CellDepCotaCellError {
        None
    } else {
        Some(cota_type)
    };
    let cell_output = CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(joyid_lock_script.clone())
        .type_(cota_type_script.pack())
        .build();
    let mut cota_cell_data = [2u8; 33];
    if subkey_error != SubkeyError::SMTProofVerifyFailed {
        cota_cell_data[1..].copy_from_slice(&root_hash);
    }
    let cota_out_point = if subkey_error == SubkeyError::CellDepCotaDataError {
        context.create_cell(cell_output, Bytes::copy_from_slice(&[2u8; 20]))
    } else {
        context.create_cell(cell_output, Bytes::copy_from_slice(&cota_cell_data))
    };
    let cota_cell_dep = CellDep::new_builder().out_point(cota_out_point).build();
    let cell_deps = vec![cota_cell_dep, caller_dep, joyid_dep, secp256k1_data_dep];

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_deps(cell_deps)
        .witnesses(witnesses.pack())
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(
        tx,
        unlock_entries,
        &signing_key,
        &verifying_key,
        &privkey,
        subkey_error,
    );

    // sign
    (context, tx)
}

#[test]
fn test_subkey_secp256r1_signature_success() {
    let (context, tx) = create_test_context(SubkeyError::NoErrorWithSecp256r1);
    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_subkey_secp256k1_signature_success() {
    let (context, tx) = create_test_context(SubkeyError::NoErrorWithSecp256k1);
    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_subkey_pubkey_smt_proof_error() {
    let (context, tx) = create_test_context(SubkeyError::SMTProofVerifyFailed);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, SMT_PROOF_VERIFY_FAILED);
}

#[test]
fn test_subkey_secp256r1_witness_mode_error() {
    let (context, tx) = create_test_context(SubkeyError::WitnessModeError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, WITNESS_MODE_ERROR);
}

#[test]
fn test_subkey_secp256r1_signature_error() {
    let (context, tx) = create_test_context(SubkeyError::Secp256r1SigVerifyError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, SECP256R1_SIG_VERIFY_ERROR);
}

#[test]
fn test_subkey_secp256k1_signature_error() {
    let (context, tx) = create_test_context(SubkeyError::Secp256k1SigVerifyError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, SECP256K1_SIG_VERIFY_ERROR);
}

#[test]
fn test_subkey_unlock_cota_cell_type_none_error() {
    let (context, tx) = create_test_context(SubkeyError::CellDepCotaCellError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, CELL_DEP_COTA_CELL_ERROR);
}

#[test]
fn test_subkey_unlock_cota_cell_type_error() {
    let (context, tx) = create_test_context(SubkeyError::CellDepCotaCellTypeError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, CELL_DEP_COTA_CELL_ERROR);
}

#[test]
fn test_subkey_unlock_cota_cell_data_error() {
    let (context, tx) = create_test_context(SubkeyError::CellDepCotaDataError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, CELL_DEP_COTA_DATA_ERROR);
}
