pub mod p_dashu;
pub mod p_ibig;
pub mod p_rug;
pub mod p_malachite;
pub mod p_bigint;
pub mod p_bigint_dig;
pub mod p_unknown;

mod small_primes;
pub mod two_primes;

pub fn main() {
    println!("Hello, world!");
}

#[derive(Debug)]
pub enum Error {
    /// p,q are invalid
    InvalidPQ,
    /// encryption error
    Encrypt,
    /// decryption error
    Decrypt(&'static str),
    /// homomorphic operation failed: invalid inputs
    Ops,
    /// could not precompute data for faster exponentiation
    BuildFastExp,
    /// pow mod undefined
    PowModUndef,
}
