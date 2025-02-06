use bytemuck::bytes_of;
use hex::FromHex;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, EcPointRef},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sha::{sha256, Sha256},
    sign::{Signer, Verifier},
};
use solana_feature_set::FeatureSet;
use solana_precompile_error::PrecompileError;
use solana_secp256r1_program::{
    new_secp256r1_instruction, verify, Secp256r1SignatureOffsets,
    COMPRESSED_PUBKEY_SERIALIZED_SIZE, DATA_START, SECP256R1_ORDER, SIGNATURE_SERIALIZED_SIZE,
};

const FIELD_SIZE: usize = 32;

const SECP256R1_HALF_ORDER: [u8; FIELD_SIZE] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

const MESSAGE: &[u8] = b"hello";

#[allow(dead_code)]
fn convert_base64url_to_base64(base64url: &str) -> String {
    base64url.replace("-", "+").replace("_", "/")
}

#[allow(dead_code)]
fn verify_ecdsa_signature(public_key: &EcPointRef, signature: &[u8], data: &[u8]) -> bool {
    // Load the public key
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::from_public_key(&group, public_key).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    // Parse the signature
    let ecdsa_sig = EcdsaSig::from_der(signature).unwrap();

    // Create a verifier
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
    verifier.update(data).unwrap();

    // Verify the signature
    verifier.verify(&ecdsa_sig.to_der().unwrap()).unwrap()
}

#[allow(dead_code)]
fn test_secp256r1() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let signing_key = EcKey::generate(&group).unwrap();
    let public_key = signing_key.public_key();
    let mut ctx = BigNumContext::new().unwrap();
    let public_key_der = public_key
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )
        .unwrap();

    println!("public_key_der: {:?}", public_key_der);

    let mut instruction = new_secp256r1_instruction(MESSAGE, signing_key).unwrap();

    println!("instruction: {:?}", instruction.data);

    let ix = new_instruction().unwrap();
    println!("ix: {:?}", ix);

    // let result = verify(
    //     instruction.data.as_slice(),
    //     &[instruction.data.as_slice()],
    //     &feature_set,
    // );

    // println!("result: {:?}", result);

    // let tx = Transaction::new_signed_with_payer(
    //     &[instruction.clone()],
    //     Some(&mint_keypair.pubkey()),
    //     &[&mint_keypair],
    //     Hash::default(),
    // );

    // assert!(tx.verify_precompiles(&feature_set).is_ok());

    // // The message is the last field in the instruction data so
    // // changing its last byte will also change the signature validity
    // let message_byte_index = instruction.data.len() - 1;
    // instruction.data[message_byte_index] =
    //     instruction.data[message_byte_index].wrapping_add(12);
    // let tx = Transaction::new_signed_with_payer(
    //     &[instruction.clone()],
    //     Some(&mint_keypair.pubkey()),
    //     &[&mint_keypair],
    //     Hash::default(),
    // );

    // assert!(tx.verify_precompiles(&feature_set).is_err());
}

pub fn test_verify() -> Result<(), Box<dyn std::error::Error>> {
    // PUBLIC KEY
    // from passkey (webauthn)
    let public_key_hex = "049f394ccc793d90eb50f266eb34af61be004b1cf220e08bb3359ad99ecd6bdb28644ce1e0b0885a2ce830812d9c56aa8cb230563e6ed8310547156d05d4c16b5f";

    // let public_key_hex = "04f9cbc15e08acedae8d7040763e4a7f693f15932b4cd5172d20c6a855d3ecf5efba1feb2fac947907cd134e36fb6c7fa5aba31fc465d91954bb8a8c7932e0dddf"; // valid
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let pub_key_bytes = hex::decode(public_key_hex)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, &pub_key_bytes, &mut ctx)?;
    let pub_key = EcKey::from_public_key(&group, &point)?;
    let pkey = PKey::from_ec_key(pub_key.clone())?;

    println!("pkey bytes: {:?}", pub_key_bytes);

    // SIGNATURE
    // from passkey (webauthn)
    let signature_hex = "3046022100aa509fe80998f37d258bf0f5e27f91b66c41ee9497a005ca0074cc849db051b6022100f5c05e5c3bce24aa1b648301dfd0cc1beda46d549658b11f80d4b9091e2215d7"; // from passkey (webauthn)

    // let signature_hex = "3046022100a8e943e5bbd264eedc42fc8d50ed0c6c93e43b574920aee61b98ec61048f3bef022100cb3a7a4df1a79d5824248076834e6659df5d425394d166dccb1c0d53fb6902ac"; // valid
    let signature_bytes = hex::decode(signature_hex)?;
    let ecdsa_sig = EcdsaSig::from_der(&signature_bytes)?;
    let r = ecdsa_sig.r().to_vec();
    let s = ecdsa_sig.s().to_vec();

    println!("r: {:?}", hex::encode(&r));
    println!("s: {:?}", hex::encode(&s));

    let mut signature = vec![0u8; SIGNATURE_SERIALIZED_SIZE];

    // Pad r and s to 32 bytes
    let mut padded_r = vec![0u8; FIELD_SIZE];
    let mut padded_s = vec![0u8; FIELD_SIZE];
    padded_r[FIELD_SIZE.saturating_sub(r.len())..].copy_from_slice(&r);
    padded_s[FIELD_SIZE.saturating_sub(s.len())..].copy_from_slice(&s);

    signature[..FIELD_SIZE].copy_from_slice(&padded_r);
    signature[FIELD_SIZE..].copy_from_slice(&padded_s);

    println!("signature: {:?}", hex::encode(&signature));

    // Check if s > half_order, if so, compute s = order - s
    let s_bignum = BigNum::from_slice(&s)?;
    let half_order = BigNum::from_slice(&SECP256R1_HALF_ORDER)?;
    let order = BigNum::from_slice(&SECP256R1_ORDER)?;
    if s_bignum > half_order {
        let mut new_s = BigNum::new()?;
        new_s.checked_sub(&order, &s_bignum)?;
        let new_s_bytes = new_s.to_vec();

        let mut new_padded_s = vec![0u8; FIELD_SIZE];
        new_padded_s[FIELD_SIZE.saturating_sub(new_s_bytes.len())..].copy_from_slice(&new_s_bytes);
        signature[FIELD_SIZE..].copy_from_slice(&new_padded_s);
    }

    let message = hex::decode("68656c6c6f")?; // "hello" in hex

    println!("Signature bytes: {:?}", signature);
    println!("Signature hex: {:?}", hex::encode(signature));

    println!("================");
    let mut sample_ctx = BigNumContext::new()?;
    let signing_key = EcKey::generate(&group)?;
    let public_key = signing_key.public_key();
    let pub_key_bytes = public_key.to_bytes(
        &group,
        openssl::ec::PointConversionForm::UNCOMPRESSED,
        &mut sample_ctx,
    )?;

    let pk_compressed = public_key.to_bytes(
        &group,
        openssl::ec::PointConversionForm::COMPRESSED,
        &mut sample_ctx,
    )?;

    println!("pk_compressed: {:?}", hex::encode(pk_compressed));
    println!("pub_key_bytes: {:?}", pub_key_bytes);
    println!("pub_key_hex: {:?}", hex::encode(pub_key_bytes));
    // test sign message
    let signing_key_pkey = PKey::from_ec_key(signing_key)?;

    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &signing_key_pkey)?;
    signer.update(&message)?;
    let signature = signer.sign_to_vec()?;
    println!("signature: {:?}", hex::encode(signature));

    // VERIFY
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
    verifier.update(&message)?;
    let valid = verifier.verify(&signature_bytes)?;

    println!("Valid: {:?}", valid);

    Ok(())
}

pub fn new_instruction() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // let public_key_hex = "04982c96b21b3e0366c12afd3ef246cf1a35300dfa816abb614e14435699eced3d8508132381dcc7a3be4ad463f07928200dcafee0112c68a06b6c4c812fd22fdf";
    // let signature_hex = "3046022100f166e3989bbaa6455cd34f50aa0c540e28ace847f52f5e60fc2c7c13f3782d5d022100c8794828d8a56d4b2ca9b6b11b91cefc96cfd3f6d197b6eaed61f4232d81f1a0";
    // let message_hex = "68656c6c6f";

    // // Create the secp256r1 (P-256) group
    // let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    // let mut point_bytes = vec![0x04];

    // let mut ctx = BigNumContext::new()?;
    // let mut compressed_bytes = BigNumContext::new()?;

    // point_bytes.extend_from_slice(&public_key_bytes);
    // let point = EcPoint::from_bytes(&group, &point_bytes, &mut ctx)?;

    // println!("public_key_bytes: {:?}", public_key_bytes);

    // // Extract the actual public key coordinates from the DER format (skip the ASN.1 header)
    // // let point = EcPoint::from_bytes(&group, &public_key_bytes[26..], &mut ctx)?;
    // let pubkey = point.to_bytes(
    //     &group,
    //     openssl::ec::PointConversionForm::COMPRESSED,
    //     &mut compressed_bytes,
    // )?;

    // println!("pubkey: {:?}", pubkey);

    // // Decode hex string to bytes
    // let pub_key_bytes = hex::decode(public_key_hex)?;

    // // Create point from the public key bytes
    // let point = EcPoint::from_bytes(&group, &pub_key_bytes, &openssl::bn::BigNumContext::new()?)?;

    // // Convert to compressed format
    // let compressed = point.to_bytes(
    //     &group,
    //     openssl::ec::PointConversionForm::COMPRESSED,
    //     &mut openssl::bn::BigNumContext::new()?,
    // )?;

    // // Convert compressed bytes to hex string
    // let compressed_hex = hex::encode(compressed);
    // println!("Compressed public key: {}", compressed_hex);

    // let message_bytes = Vec::from_hex(message_hex).expect("Invalid hex string");
    // let signature_bytes = Vec::from_hex(signature_hex).expect("Invalid hex string");
    // let public_key_bytes = Vec::from_hex(public_key_hex).expect("Invalid hex string");

    // // Parse the DER signature
    // let ecdsa_sig = EcdsaSig::from_der(&signature_bytes)?;
    // let r = ecdsa_sig.r().to_vec();
    // let s = ecdsa_sig.s().to_vec();
    // let mut signature = vec![0u8; SIGNATURE_SERIALIZED_SIZE];

    // // Pad r and s to 32 bytes
    // let mut padded_r = vec![0u8; FIELD_SIZE];
    // let mut padded_s = vec![0u8; FIELD_SIZE];
    // padded_r[FIELD_SIZE.saturating_sub(r.len())..].copy_from_slice(&r);
    // padded_s[FIELD_SIZE.saturating_sub(s.len())..].copy_from_slice(&s);

    // signature[..FIELD_SIZE].copy_from_slice(&padded_r);
    // signature[FIELD_SIZE..].copy_from_slice(&padded_s);

    // // Check if s > half_order, if so, compute s = order - s
    // let s_bignum = BigNum::from_slice(&s)?;
    // let half_order = BigNum::from_slice(&SECP256R1_HALF_ORDER)?;
    // let order = BigNum::from_slice(&SECP256R1_ORDER)?;
    // if s_bignum > half_order {
    //     let mut new_s = BigNum::new()?;
    //     new_s.checked_sub(&order, &s_bignum)?;
    //     let new_s_bytes = new_s.to_vec();

    //     let mut new_padded_s = vec![0u8; FIELD_SIZE];
    //     new_padded_s[FIELD_SIZE.saturating_sub(new_s_bytes.len())..].copy_from_slice(&new_s_bytes);
    //     signature[FIELD_SIZE..].copy_from_slice(&new_padded_s);
    // }

    // assert_eq!(pubkey.len(), COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    // assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);

    // let mut instruction_data = Vec::with_capacity(
    //     DATA_START
    //         .saturating_add(SIGNATURE_SERIALIZED_SIZE)
    //         .saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE)
    //         .saturating_add(message_bytes.len()),
    // );

    // let num_signatures: u8 = 1;
    // let public_key_offset = DATA_START;
    // let signature_offset = public_key_offset.saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    // let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);

    // instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));

    // let offsets = Secp256r1SignatureOffsets {
    //     signature_offset: signature_offset as u16,
    //     signature_instruction_index: u16::MAX,
    //     public_key_offset: public_key_offset as u16,
    //     public_key_instruction_index: u16::MAX,
    //     message_data_offset: message_data_offset as u16,
    //     message_data_size: MESSAGE.len() as u16,
    //     message_instruction_index: u16::MAX,
    // };

    // instruction_data.extend_from_slice(bytes_of(&offsets));
    // instruction_data.extend_from_slice(&pubkey);
    // instruction_data.extend_from_slice(&signature);
    // instruction_data.extend_from_slice(&message_bytes);

    Ok(vec![])
}

fn test_instruction() -> Result<(), PrecompileError> {
    let instruction = new_instruction().map_err(|e| {
        println!("Error creating instruction: {:?}", e);
        PrecompileError::InvalidSignature
    })?;

    println!("instruction: {:?}", instruction);

    let result = verify(
        instruction.as_slice(),
        &[instruction.as_slice()],
        &FeatureSet::all_enabled(),
    );

    match &result {
        Ok(_) => println!("Verification succeeded!"),
        Err(e) => println!("Verification failed: {:?}", e),
    }

    result
}

fn test_ecdsa_signature() -> Result<(), Box<dyn std::error::Error>> {
    let public_key_hex = "04982c96b21b3e0366c12afd3ef246cf1a35300dfa816abb614e14435699eced3d8508132381dcc7a3be4ad463f07928200dcafee0112c68a06b6c4c812fd22fdf";
    let signature_hex = "3046022100f166e3989bbaa6455cd34f50aa0c540e28ace847f52f5e60fc2c7c13f3782d5d022100c8794828d8a56d4b2ca9b6b11b91cefc96cfd3f6d197b6eaed61f4232d81f1a0";
    let message_hex = "686868";

    let signature_bytes = Vec::from_hex(signature_hex).expect("Invalid hex string");
    let message_bytes = Vec::from_hex(message_hex).expect("Invalid hex string");

    // let signature_der = hex::decode(signature_hex)?;
    let pubkey_der = Vec::from_hex(public_key_hex).expect("Invalid hex string");

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;

    // Extract the actual public key coordinates from the DER format (skip the ASN.1 header)
    let point = EcPoint::from_bytes(&group, &pubkey_der[26..], &mut ctx)?;

    // Parse the DER signature
    let ecdsa_sig = EcdsaSig::from_der(&signature_bytes)?;
    let r = ecdsa_sig.r().to_vec();
    let s = ecdsa_sig.s().to_vec();
    let mut signature = vec![0u8; SIGNATURE_SERIALIZED_SIZE];

    // Pad r and s to 32 bytes
    let mut padded_r = vec![0u8; FIELD_SIZE];
    let mut padded_s = vec![0u8; FIELD_SIZE];
    padded_r[FIELD_SIZE.saturating_sub(r.len())..].copy_from_slice(&r);
    padded_s[FIELD_SIZE.saturating_sub(s.len())..].copy_from_slice(&s);

    signature[..FIELD_SIZE].copy_from_slice(&padded_r);
    signature[FIELD_SIZE..].copy_from_slice(&padded_s);

    // Check if s > half_order, if so, compute s = order - s
    let s_bignum = BigNum::from_slice(&s)?;
    let half_order = BigNum::from_slice(&SECP256R1_HALF_ORDER)?;
    let order = BigNum::from_slice(&SECP256R1_ORDER)?;
    if s_bignum > half_order {
        let mut new_s = BigNum::new()?;
        new_s.checked_sub(&order, &s_bignum)?;
        let new_s_bytes = new_s.to_vec();

        let mut new_padded_s = vec![0u8; FIELD_SIZE];
        new_padded_s[FIELD_SIZE.saturating_sub(new_s_bytes.len())..].copy_from_slice(&new_s_bytes);
        signature[FIELD_SIZE..].copy_from_slice(&new_padded_s);
    }

    println!("signature: {:?}", signature);

    if verify_ecdsa_signature(&point, &signature, &message_bytes) {
        println!("The signature is valid ECDSA.");
    } else {
        println!("The signature is NOT valid ECDSA.");
    }

    Ok(())
}

// let _ = test_verify();

fn main() {
    let _ = test_verify();
}
