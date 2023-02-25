use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub fn add(left: usize, right: usize) -> usize {
    left + right
}



/// Using the curve25519-dalek generator.
pub struct DiffieHellmanParameters {
    pub secret: EphemeralSecret,
    pub public: PublicKey
}

pub fn get_shared_secret_key(user_dh_params:DiffieHellmanParameters, other_user_public: PublicKey) -> SharedSecret {
    return user_dh_params.secret.diffie_hellman(&other_user_public);
}

pub fn get_diffie_hellman_params() -> DiffieHellmanParameters {
    let user_secret = EphemeralSecret::new(OsRng);
    let user_public = PublicKey::from(&user_secret);
    DiffieHellmanParameters { secret: user_secret, public: user_public}
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_works() {
        let alice_dh = get_diffie_hellman_params();
        let bob_dh = get_diffie_hellman_params();

        let alice_pk_copy = alice_dh.public.clone();
        let alice_shared_secret = get_shared_secret_key(alice_dh, bob_dh.public);
        let bob_shared_secret = get_shared_secret_key(bob_dh, alice_pk_copy);
        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    }

    #[test]
    fn shared_secret_with_non_matching_secrets_fails() {
        let alice_dh = get_diffie_hellman_params();
        let bob_dh = get_diffie_hellman_params();
    
        let alice_shared_secret = get_shared_secret_key(alice_dh, bob_dh.public);
        let fake = get_diffie_hellman_params();
        let bob_shared_secret = get_shared_secret_key(bob_dh, fake.public);
        assert_ne!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes()); 
    }    
    #[test]
    fn it_works() {
        let result = 2+2;
        assert_eq!(result, 4);
    }
}
