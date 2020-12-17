use math::{FromBytes, ToBytes};
use merlin::Transcript;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

use crate::Vec;

/// A `SeedableRng` that refreshes its seed by hashing together the previous seed
/// and the new seed material.
// TODO: later: re-evaluate decision about ChaChaRng
pub struct FiatShamirRng {
    r: ChaChaRng,
    seed: [u8; 32],
}

impl RngCore for FiatShamirRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.r.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.r.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.r.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(self.r.fill_bytes(dest))
    }
}

impl FiatShamirRng {
    /// Create a new `Self` by initializing with a fresh seed.
    /// `self.seed = H(self.seed || new_seed)`.
    #[inline]
    pub fn from_seed<'a, T: 'a + ToBytes>(s: &'a T) -> Self {
        let mut bytes = Vec::new();
        s.write(&mut bytes).expect("failed to convert to bytes");

        let mut seed: [u8; 32] = [0u8; 32];
        let mut transcript = Transcript::new(b"MARLINSEED");
        transcript.append_message(b"Seed", &bytes);
        transcript.challenge_bytes(b"x", &mut seed);

        let r = ChaChaRng::from_seed(seed.clone());
        Self { r, seed }
    }

    /// Refresh `self.seed` with new material. Achieved by setting
    /// `self.seed = H(self.seed || new_seed)`.
    #[inline]
    pub fn absorb<'a, T: 'a + ToBytes>(&mut self, seed: &'a T) {
        let mut bytes = Vec::new();
        seed.write(&mut bytes).expect("failed to convert to bytes");
        bytes.extend_from_slice(&self.seed);

        let mut transcript = Transcript::new(b"MARLINSEED");
        transcript.append_message(b"Seed", &bytes);
        transcript.challenge_bytes(b"x", &mut self.seed);

        let seed: [u8; 32] = FromBytes::read(self.seed.as_ref()).expect("failed to get [u32; 8]");
        self.r = ChaChaRng::from_seed(seed);
    }
}
