use rc::{generate_dh, dh};
use sha2::Sha256;
use hkdf::Hkdf;
use hex_literal::hex;

fn main() {
    // Alice and Bob generate their secret and public key for the secret exchange
    let alice_dh = generate_dh();
    let bob_dh = generate_dh();

    // Alice and Bob now have a shared secret SK (32 bytes).
    let alice_pk_copy = alice_dh.public.clone();
    let alice_shared_secret = dh(alice_dh, bob_dh.public);
    let bob_shared_secret = dh(bob_dh, alice_pk_copy);

    assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());

    let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex!("000102030405060708090a0b0c");
    let info = hex!("f0f1f2f3f4f5f6f7f8f9");

    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm)
        .expect("42 is a valid length for Sha256 to output");

    println!("{:?}", okm);

}
