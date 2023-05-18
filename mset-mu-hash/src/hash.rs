// Credits go to @cronokirby for heavily inspiring this crate based on this blog: https://cronokirby.com/posts/2021/07/on_multi_set_hashing/

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use digest::{
    consts::U64,
    Digest, Reset, Update
};

#[derive(Clone)]
pub struct RistrettoHash<H> {
    hash: H,
    updating: bool,
    acc: RistrettoPoint,
}

impl<H: Digest<OutputSize = U64> + Default> RistrettoHash<H> {
    /// This function updates the multiset-hash with the given byte element multiplicity number of times.
    pub fn add(&mut self, data: impl AsRef<[u8]>, multiplicity: u64) {
        if self.updating {
            panic!("add called before end_update");
        }
        self.hash.update(data);
        self.end_update(multiplicity);
    }

    /// This function should be called to mark the end of an object provided with `update`.
    ///
    /// This must always be called after calls to `update`, otherwise panics will happen
    /// when finalizing or adding new objects.
    ///
    /// If called without any prior calls to `update`, this function is equivalent
    /// to calling `add` with an empty slice.
    pub fn end_update(&mut self, multiplicity: u64) {
        self.updating = false;

        let old = std::mem::replace(&mut self.hash, H::default());
        let h_point = RistrettoPoint::from_hash(old);
        self.acc += Scalar::from(multiplicity) * h_point;
    }

    /// Returns the hash corresponding to the multi-set hash of the RistrettoHash object.
    pub fn finalize(self) -> [u8; 32] {
        let mut out: [u8;32] = [0; 32];
        out.copy_from_slice(&self.acc.compress().as_bytes()[..]);
        return out;
    }
}

impl<H: Digest<OutputSize = U64> + Default> digest::OutputSizeUser for RistrettoHash<H> {
    type OutputSize = <H as digest::OutputSizeUser>::OutputSize;
}

impl<H: Digest<OutputSize = U64> + Default> Default for RistrettoHash<H> {
    fn default() -> Self {
        Self {
            hash: H::default(),
            acc: RistrettoPoint::default(),
            updating: false,
        }
    }
}

impl<H: Digest<OutputSize = U64> + Default> Update for RistrettoHash<H> {
    /// Useful if only part of a message is known when updating the hash:
    /// 
    /// hash.update(b"hello ")
    /// hash.update(b"i am Nathan")
    /// 
    /// results in the same hash as
    /// 
    /// hash.add(b"hello i am Nathan", 1)
    /// 
    fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
        self.updating = true;
    }
}

impl<H: Digest<OutputSize = U64> + Default + Reset> Reset for RistrettoHash<H> {
    /// Resets the hash object by initializing the accumulator to the generator of the elliptic curve.
    fn reset(&mut self) {
        Digest::reset(&mut self.hash);
        self.updating = false;
        self.acc = RistrettoPoint::default();
    }
}

