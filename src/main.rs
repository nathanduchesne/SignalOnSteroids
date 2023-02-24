use RC::{get_diffie_hellman_params, get_shared_secret_key};

fn main() {
    let alice_dh = get_diffie_hellman_params();
    let bob_dh = get_diffie_hellman_params();

    let alice_pk_copy = alice_dh.public.clone();
    let alice_shared_secret = get_shared_secret_key(alice_dh, bob_dh.public);
    let bob_shared_secret = get_shared_secret_key(bob_dh, alice_pk_copy);
    //let fake = get_diffie_hellman_params();
    //let bob_shared_secret = get_shared_secret_key(bob_dh, fake.public);
    if alice_shared_secret.as_bytes().eq(bob_shared_secret.as_bytes()) {
        println!("All good!");
    }
    else {
        print!("Failed");
    }
    assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
}
