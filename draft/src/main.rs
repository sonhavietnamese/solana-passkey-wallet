use bytemuck::bytes_of;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::Verifier,
};
use solana_feature_set::FeatureSet;
use solana_precompile_error::PrecompileError;
use solana_secp256r1_program::{
    verify, Secp256r1SignatureOffsets, COMPRESSED_PUBKEY_SERIALIZED_SIZE, DATA_START,
    SECP256R1_ORDER, SIGNATURE_SERIALIZED_SIZE,
};

const FIELD_SIZE: usize = 32;

const SECP256R1_HALF_ORDER: [u8; FIELD_SIZE] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

pub fn test_verify() -> Result<(), Box<dyn std::error::Error>> {
    // from passkey (webauthn)
    let public_key_hex = "04cdfc52917e67195204e0a5a218d12cd2e32b7caceb977e200c92022f3f6952ebf96c869d3450803eecfda119a2a1aaf1cc7a8d336c4800f068135eaafa2091ab";

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let pub_key_bytes = hex::decode(public_key_hex)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, &pub_key_bytes, &mut ctx)?;
    let pub_key = EcKey::from_public_key(&group, &point)?;
    let pkey = PKey::from_ec_key(pub_key.clone())?;

    println!("pkey bytes: {:?}", pub_key_bytes);

    // SIGNATURE
    let signature_hex = "304402202e18b2d789ede3626c804f6248224d17b3a9c007bcf5f896f16183ea30b3fa490220026b72e98d41718b1cb1b259382e7903d3836f8632a0978d9cc6a9ffd689b855"; // from passkey (webauthn)

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

    let message = hex::decode("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000a907a3b1e88d68dacd386df18f8e1c4289a0e5b70e31270c837dab0cb2194f2d")?; // "hello" in hex

    println!("Signature bytes: {:?}", signature);
    println!("Signature hex: {:?}", hex::encode(signature));

    // VERIFY
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
    verifier.update(&message)?;
    let valid = verifier.verify(&signature_bytes)?;

    println!("Valid: {:?}", valid);

    Ok(())
}

pub fn new_instruction() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let public_key_hex = "04cdfc52917e67195204e0a5a218d12cd2e32b7caceb977e200c92022f3f6952ebf96c869d3450803eecfda119a2a1aaf1cc7a8d336c4800f068135eaafa2091ab";
    let signature_hex = "304402202e18b2d789ede3626c804f6248224d17b3a9c007bcf5f896f16183ea30b3fa490220026b72e98d41718b1cb1b259382e7903d3836f8632a0978d9cc6a9ffd689b855"; // from passkey (webauthn)
    let message_hex = "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000a907a3b1e88d68dacd386df18f8e1c4289a0e5b70e31270c837dab0cb2194f2d"; // "hello" in hex

    let message = hex::decode(message_hex)?;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let pub_key_bytes = hex::decode(public_key_hex)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, &pub_key_bytes, &mut ctx)?;
    let pub_key = EcKey::from_public_key(&group, &point)?;
    let pkey = PKey::from_ec_key(pub_key.clone())?;

    let pubkey = pub_key.public_key().to_bytes(
        &group,
        openssl::ec::PointConversionForm::COMPRESSED,
        &mut ctx,
    )?;

    let signature_bytes = hex::decode(signature_hex)?;

    let ecdsa_sig = EcdsaSig::from_der(&signature_bytes)?;
    let r = ecdsa_sig.r().to_vec();
    let s = ecdsa_sig.s().to_vec();
    let mut signature = vec![0u8; SIGNATURE_SERIALIZED_SIZE];

    // Incase of an r or s value of 31 bytes we need to pad it to 32 bytes
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

        // Incase the new s value is 31 bytes we need to pad it to 32 bytes
        let mut new_padded_s = vec![0u8; FIELD_SIZE];
        new_padded_s[FIELD_SIZE.saturating_sub(new_s_bytes.len())..].copy_from_slice(&new_s_bytes);

        signature[FIELD_SIZE..].copy_from_slice(&new_padded_s);
    }

    assert_eq!(pubkey.len(), COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);

    let mut instruction_data = Vec::with_capacity(
        DATA_START
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE)
            .saturating_add(message.len()),
    );

    let num_signatures: u8 = 1;
    let public_key_offset = DATA_START;
    let signature_offset = public_key_offset.saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE);
    let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);

    instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));

    let offsets = Secp256r1SignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: u16::MAX,
        public_key_offset: public_key_offset as u16,
        public_key_instruction_index: u16::MAX,
        message_data_offset: message_data_offset as u16,
        message_data_size: message.len() as u16,
        message_instruction_index: u16::MAX,
    };

    instruction_data.extend_from_slice(bytes_of(&offsets));
    instruction_data.extend_from_slice(&pubkey);
    instruction_data.extend_from_slice(&signature);
    instruction_data.extend_from_slice(&message);

    Ok(instruction_data)
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

fn main() {
    let _ = test_instruction();
}
