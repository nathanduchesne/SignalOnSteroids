#[cfg(test)]
mod tests {
    use digest::{Update, Reset};
    use sha2::Sha512;
    use crate::RistrettoHash;

    #[test]
    fn implementation_has_safety() {
        let mut hash = RistrettoHash::<Sha512>::default();
        hash.add(b"cat", 2);
        hash.add(b"dog", 2);

        let mut hash2 = RistrettoHash::<Sha512>::default();
        hash2.add(b"dog", 1);
        hash2.add(b"cat", 1);
        hash2.add(b"dog", 1);
        hash2.add(b"cat", 1);

        hash2.update(b"test");
        hash2.end_update(1);

        hash.add(b"test", 1);

        assert_eq!(hash.finalize(), hash2.finalize());
    }

    #[test]
    fn implementation_has_liveness() {
        let mut hash = RistrettoHash::<Sha512>::default();
        hash.add(b"cat", 2);
        hash.add(b"dog", 2);
    
        let mut hash2 = RistrettoHash::<Sha512>::default();
        hash2.add(b"dog", 1);
        hash2.add(b"cat", 1);
        hash2.add(b"dog", 1);
        hash2.add(b"cat", 5);
    
        assert_ne!(hash.finalize(), hash2.finalize());
    }

    #[test]
    fn reset_hash_works() {
        let mut hash1 = RistrettoHash::<Sha512>::default();
        hash1.add(b"nothing", 1);
        hash1.reset();

        let hash2 = RistrettoHash::<Sha512>::default();
        assert_eq!(hash1.finalize(), hash2.finalize());
    }
}
