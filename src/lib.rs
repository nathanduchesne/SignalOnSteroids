use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

struct state {
    active: bool,
    username: String,
    email: String,
    sign_in_count: u64,
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
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
