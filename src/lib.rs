mod small_primes;
pub mod p_rug;

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
    Decrypt,
    /// homomorphic operation failed: invalid inputs
    Ops,
    /// could not precompute data for faster exponentiation
    BuildFastExp,
    /// pow mod undefined
    PowModUndef,
}
