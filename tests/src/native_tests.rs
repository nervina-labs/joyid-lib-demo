use crate::helper::ETH_PREFIX;
use crate::helper::{base64_hex, blake160, generate_sign_origin_data, keccak_160};

use super::*;
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::ckb_crypto::secp::{Generator, Message, Privkey};
use ckb_testtool::ckb_hash::new_blake2b;
use ckb_testtool::ckb_types::H256;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::{self, *},
    prelude::*,
};
use ckb_testtool::context::Context;
use keccak_hash::keccak_256;
use p256::ecdsa::{signature::Signer, SigningKey};
use p256::ecdsa::{signature::Verifier, VerifyingKey};
use rand_core::OsRng;

const MAX_CYCLES: u64 = 70_000_000;
const WITNESS_LOCK_R1_LEN: usize = 129;
const WITNESS_LOCK_K1_LEN: usize = 86;

// error numbers
const TYPE_ARGS_INVALID: i8 = 5;
const WITNESS_LENGTH_ERROR: i8 = 6;
const WITNESS_MODE_ERROR: i8 = 7;
const SECP256R1_SIG_VERIFY_ERROR: i8 = 9;
const SECP256K1_SIG_VERIFY_ERROR: i8 = 10;
const CLIENT_WITHOUT_CHALLENGE: i8 = 11;
const ARGS_ALG_INDEX_ERROR: i8 = 12;

#[derive(PartialEq, Eq, Clone, Copy)]
enum NativeError {
    NoErrorWithSecp256r1,
    NoErrorWithSecp256k1,
    TypeArgsInvalid,
    WitnessLengthError,
    WitnessModeError,
    ArgsAlgIndexError,
    Secp256r1SigVerifyError,
    ClientWithoutChallenge,
    Secp256k1SigVerifyError,
}

fn is_secp256k1(native_error: NativeError) -> bool {
    return native_error == NativeError::NoErrorWithSecp256k1
        || native_error == NativeError::Secp256k1SigVerifyError;
}

fn sign_tx(
    tx: TransactionView,
    signing_key: &SigningKey,
    verifying_key: &VerifyingKey,
    privkey: &Privkey,
    native_error: NativeError,
) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();

    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];

    let mut buffer: Vec<u8> = vec![];
    buffer.extend(&tx_hash.raw_data());

    let output_type: Bytes = {
        let metadata = "7b226964223a2243544d657461222c22766572223a22312e30222c226d65746164617461223a7b22746172676574223a226f75747075742330222c2274797065223a226a6f795f6964222c2264617461223a7b2276657273696f6e223a2230222c226e616d65223a224b656c6c79222c226465736372697074696f6e223a2257656233205465737420446576656c6f706d656e742de689b9e9878fe6b3a8e5868c3177222c22617661746172223a2268747470733a2f2f73312e3332383838382e78797a2f323032322f30392f32372f736b7974792e77656270222c227075624b6579223a2230786437343630613736313539356337343665653563613965306237633430306232643335343862613635316436333535656435656262626132353630306165303034646237663634666162623631303339623539393635313630303062383233653661333665393863343736393038386162346338343130303736353665663230222c2263726564656e7469616c4964223a22307861623266646165633834633531383433383132613237386230623063326238626237636164396564316430366162613930343937636463386630303262663662222c22616c67223a2230783031222c227375624b657973223a5b7b227075624b6579223a2230786236616139356261343965333130353239333033336238323665353230306639383862336133303237613437636637643036313336626236313930303939636239333730393963623264663464343735646137653032626430303966336461353032313636343564373434656530343836346531623230306362393439653739222c2263726564656e7469616c4964223a22307836646561346439396634626430363938313261383233363264393363393035643066616133616336376132366164663530343663313837393033636432376665222c22616c67223a2230783031227d2c7b227075624b6579223a2230783161386533646464653137333966383561306666376638653839303830303364643163613439333066363432316536656239363865323734363030303633393962633837303065393130303834333032633330386664313530303062656361666637373530303738373135323637613862373964336530303265653537383532222c2263726564656e7469616c4964223a22307865346336623533313030396631326236353661366538373933313631306139313865613565363432336333316264396461313666353334666133613761323138222c22616c67223a2230783031227d5d7d7d7d";
        let buf = hex::decode(metadata).unwrap();
        buf.into()
    };

    // digest the first witness
    let witness = WitnessArgsBuilder::default()
        .output_type(
            BytesOptBuilder::default()
                .set(Some(output_type.pack()))
                .build(),
        )
        .build();
    let witness_lock_len = if is_secp256k1(native_error) {
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

    let mut signed_signature = if native_error == NativeError::WitnessModeError {
        vec![0x00u8]
    } else {
        vec![0x01u8]
    };

    if is_secp256k1(native_error) {
        keccak_256(&buffer, &mut message);

        let mut buf: Vec<u8> = vec![];
        buf.extend(&ETH_PREFIX);
        buf.extend(&message);

        let mut sign_data = [0u8; 32];
        keccak_256(&buf, &mut sign_data);

        let mut sign_data = H256::from(sign_data);
        if native_error == NativeError::Secp256k1SigVerifyError {
            sign_data = H256::from_slice(&[240u8; 32]).unwrap();
        }
        let signature = privkey.sign_recoverable(&sign_data).expect("sign");
        let mut sig_vec = signature.serialize();
        let public_key = privkey.pubkey().expect("pubkey");
        let sign_msg = Message::from_slice(sign_data.as_bytes()).unwrap();
        let result = public_key.verify(&sign_msg, &signature).is_ok();
        assert!(result, "Secp256k1 validate signature fail");
        let mut pubkey_hash = keccak_160(&public_key.0).to_vec();

        signed_signature.append(&mut pubkey_hash);
        signed_signature.append(&mut sig_vec);
    } else {
        blake2b.update(&buffer);
        blake2b.finalize(&mut message);
        let mut challenge = base64_hex(&message);

        let challenge_error = native_error == NativeError::ClientWithoutChallenge;
        let (sign_data, mut sign_origin_data) =
            generate_sign_origin_data(&mut challenge, challenge_error);
        let signature = signing_key.sign(&sign_data);
        let result = verifying_key.verify(&sign_data, &signature).is_ok();
        assert!(result, "P256 validate signature fail");
        let mut sig_vec = signature.to_vec();

        let public_key = verifying_key.to_encoded_point(false);
        let mut pubkey = public_key.as_bytes()[1..].to_vec();

        signed_signature.append(&mut pubkey);
        if native_error == NativeError::Secp256r1SigVerifyError {
            sig_vec.reverse();
        }
        signed_signature.append(&mut sig_vec);

        if native_error == NativeError::WitnessLengthError {
            sign_origin_data.truncate(6);
        }
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

fn create_test_context(native_error: NativeError) -> (Context, TransactionView) {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let public_key = verifying_key.to_encoded_point(false);

    let privkey = Generator::random_privkey();
    let pubkey = privkey.pubkey().expect("pubkey");

    let mut pubkey_hash = if native_error == NativeError::NoErrorWithSecp256k1 {
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

    if native_error == NativeError::TypeArgsInvalid {
        pubkey_hash.reverse()
    }
    let mut joyid_args = [0u8; 22];
    joyid_args[2..22].copy_from_slice(&pubkey_hash);
    if is_secp256k1(native_error) {
        joyid_args[1] = 2u8;
    } else if native_error != NativeError::ArgsAlgIndexError {
        joyid_args[1] = 1u8;
    }

    // prepare scripts
    let joyid_lock_script = context
        .build_script(&caller_out_point, joyid_args.to_vec().into())
        .expect("script");
    let caller_dep = CellDep::new_builder()
        .out_point(caller_out_point.clone())
        .build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(joyid_lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let inputs = vec![
        CellInput::new_builder()
            .previous_output(input_out_point.clone())
            .build(),
        CellInput::new_builder()
            .previous_output(input_out_point.clone())
            .build(),
    ];

    let outputs = vec![CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(joyid_lock_script.clone())
        .build()];

    let outputs_data = vec![Bytes::new(); 1];

    let mut witnesses = vec![];
    for _ in 0..inputs.len() {
        witnesses.push(Bytes::from_static(
            "7b226964223a2243544d657461222c22766572223a".as_bytes(),
        ))
    }

    let meta_bytes: Bytes = {
        let metadata = "7b226964223a2243544d657461222c22766572223a22312e30222c226d65746164617461223a7b22746172676574223a226f75747075742330222c2274797065223a226a6f795f6964222c2264617461223a7b2276657273696f6e223a2230222c226e616d65223a224b656c6c79222c226465736372697074696f6e223a2257656233205465737420446576656c6f706d656e742de689b9e9878fe6b3a8e5868c3177222c22617661746172223a2268747470733a2f2f73312e3332383838382e78797a2f323032322f30392f32372f736b7974792e77656270222c227075624b6579223a2230786437343630613736313539356337343665653563613965306237633430306232643335343862613635316436333535656435656262626132353630306165303034646237663634666162623631303339623539393635313630303062383233653661333665393863343736393038386162346338343130303736353665663230222c2263726564656e7469616c4964223a22307861623266646165633834633531383433383132613237386230623063326238626237636164396564316430366162613930343937636463386630303262663662222c22616c67223a2230783031222c227375624b657973223a5b7b227075624b6579223a2230786236616139356261343965333130353239333033336238323665353230306639383862336133303237613437636637643036313336626236313930303939636239333730393963623264663464343735646137653032626430303966336461353032313636343564373434656530343836346531623230306362393439653739222c2263726564656e7469616c4964223a22307836646561346439396634626430363938313261383233363264393363393035643066616133616336376132366164663530343663313837393033636432376665222c22616c67223a2230783031227d2c7b227075624b6579223a2230783161386533646464653137333966383561306666376638653839303830303364643163613439333066363432316536656239363865323734363030303633393962633837303065393130303834333032633330386664313530303062656361666637373530303738373135323637613862373964336530303265653537383532222c2263726564656e7469616c4964223a22307865346336623533313030396631326236353661366538373933313631306139313865613565363432336333316264396461313666353334666133613761323138222c22616c67223a2230783031227d5d7d7d7d";
        let buf = hex::decode(metadata).unwrap();
        buf.into()
    };
    witnesses.push(meta_bytes);

    let cell_deps = vec![caller_dep, joyid_dep, secp256k1_data_dep];
    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_deps(cell_deps)
        .witnesses(witnesses.pack())
        .build();
    let tx = context.complete_tx(tx);
    let tx = sign_tx(tx, &signing_key, &verifying_key, &privkey, native_error);

    // sign
    (context, tx)
}

#[test]
fn test_native_secp256r1_signature_success() {
    let (context, tx) = create_test_context(NativeError::NoErrorWithSecp256r1);
    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_native_secp256k1_signature_success() {
    let (context, tx) = create_test_context(NativeError::NoErrorWithSecp256k1);
    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_native_secp256r1_lock_args_error() {
    let (context, tx) = create_test_context(NativeError::TypeArgsInvalid);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, TYPE_ARGS_INVALID);
}

#[test]
fn test_native_secp256r1_witness_length_error() {
    let (context, tx) = create_test_context(NativeError::WitnessLengthError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, WITNESS_LENGTH_ERROR);
}

#[test]
fn test_native_secp256r1_witness_mode_error() {
    let (context, tx) = create_test_context(NativeError::WitnessModeError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, WITNESS_MODE_ERROR);
}

#[test]
fn test_native_args_alg_index_error() {
    let (context, tx) = create_test_context(NativeError::ArgsAlgIndexError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, ARGS_ALG_INDEX_ERROR);
}

#[test]
fn test_native_challenge_error() {
    let (context, tx) = create_test_context(NativeError::ClientWithoutChallenge); // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, CLIENT_WITHOUT_CHALLENGE);
}

#[test]
fn test_native_secp256r1_signature_error() {
    let (context, tx) = create_test_context(NativeError::Secp256r1SigVerifyError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, SECP256R1_SIG_VERIFY_ERROR);
}

#[test]
fn test_native_secp256k1_signature_error() {
    let (context, tx) = create_test_context(NativeError::Secp256k1SigVerifyError);
    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    assert_script_error(err, SECP256K1_SIG_VERIFY_ERROR);
}
