// I hate this api. I'm not using it.
use malachite::{integer::Integer, num::{arithmetic::traits::{ModAssign, ModInverse, ModPow, UnsignedAbs}, basic::traits::{One as _, Zero as _}, conversion::traits::FromStringBase as _}, Natural};

use crate::Error;

pub type Plaintext = Integer;
pub type Ciphertext = Integer;
pub type Nonce = Integer;

#[derive(Clone)]
pub struct EncryptionKey {
    n: Integer,
    nn: Integer,
    half_n: Integer,
    neg_half_n: Integer,
}

impl EncryptionKey {
    pub fn from_n(n: Integer) -> Self {
        let nn = n.clone() * &n;
        let half_n = n.clone() >> 1usize;
        let neg_half_n = -half_n.clone();
        Self {
            n,
            nn,
            half_n,
            neg_half_n,
        }
    }

    pub fn n(&self) -> &Integer {
        &self.n
    }
    pub fn half_n(&self) -> &Integer {
        &self.half_n
    }

    fn l(&self, x: &Integer) -> Option<Integer> {
        if x % &self.n != Integer::ONE {
            return None;
        }
        if !in_mult_group(x, &self.nn) {
            return None;
        }

        // (x - 1) / N
        Some((x - Integer::ONE) / &self.n)
    }

    /// Checks whether `x` is `{-N/2, .., N/2}`
    pub fn in_signed_group(&self, x: &Integer) -> bool {
        self.neg_half_n <= *x && *x <= self.half_n
    }

    /// Encrypts the plaintext `x` in `{-N/2, .., N_2}` with `nonce` in `Z*_n`
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Integer, Error> {
        if !self.in_signed_group(x) || !in_mult_group(nonce, &self.n) {
            return Err(Error::Encrypt);
        }

        let x = if x >= &Integer::ZERO {
            x.clone()
        } else {
            x + &self.n
        };

        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let a = (Integer::ONE + (&x * &self.n)) % &self.nn;
        // b = nonce^N mod N^2
        let b =
            pow_mod(nonce.clone(), self.n.clone(), self.nn.clone()).ok_or(Error::PowModUndef)?;

        let c = modulo(&(a * Integer::from(b)), &self.nn);
        Ok(c)
    }

    /// Homomorphic addition of two ciphertexts
    pub fn oadd(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !in_mult_group(c1, &self.nn) || !in_mult_group(c2, &self.nn) {
            Err(Error::Ops)
        } else {
            Ok((c1 * c2) % &self.nn)
        }
    }

    /// Homomorphic subtraction of two ciphertexts
    pub fn osub(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !in_mult_group(c1, &self.nn) {
            Err(Error::Ops)
        } else {
            let c2 = self.oneg(c2)?;
            Ok((c1 * c2) % &self.nn)
        }
    }

    /// Homomorphic multiplication of scalar at ciphertext
    pub fn omul(&self, scalar: &Integer, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        if !in_mult_group_abs(scalar, &self.n) || !in_mult_group(ciphertext, &self.nn) {
            Err(Error::Ops)
        } else {
            pow_mod(ciphertext.clone(), scalar.clone(), self.nn.clone()).ok_or(Error::Ops)
        }
    }

    /// Homomorphic negation of a ciphertext
    pub fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        invert(ciphertext.clone(), self.nn.clone())
            .ok_or(Error::Ops)
            .map(Into::into)
    }
}

/// Paillier decryption key
#[derive(Clone)]
pub struct DecryptionKey {
    ek: EncryptionKey,
    /// `lambda^-1 mod N`
    mu: Integer,

    crt_mod_nn: CrtExp,
    /// Calculates `x ^ N mod N^2`. It's used for faster encryption
    exp_n: Exponent,
    /// Calculates `x ^ lambda mod N^2`. It's used for faster decryption
    exp_lambda: Exponent,
}

impl DecryptionKey {
    /*
    /// Generates a paillier key
    ///
    /// Samples two safe 1536-bits primes that meets 128 bits security level
    pub fn generate(
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    ) -> Result<Self, Error> {
        let p = generate_safe_prime(rng, 1536);
        let q = generate_safe_prime(rng, 1536);
        Self::from_primes(p, q)
    }
    */

    /// Constructs a paillier key from primes `p`, `q`
    ///
    /// `p` and `q` need to be safe primes sufficiently large to meet security level requirements.
    ///
    /// Returns error if `p` and `q` do not correspond to a valid paillier key.
    #[allow(clippy::many_single_char_names)]
    pub fn from_primes(p: Integer, q: Integer) -> Result<Self, Error> {
        // Paillier doesn't work if p == q
        if p == q {
            return Err(Error::InvalidPQ);
        }
        let pm1 = &p - Integer::ONE;
        let qm1 = &q - Integer::ONE;
        let ek = EncryptionKey::from_n(&p * &q);
        let lambda = lcm(&pm1, &qm1);
        if lambda == Integer::ZERO {
            return Err(Error::InvalidPQ);
        }

        // u = lambda^-1 mod N
        let u = invert(lambda.clone(), ek.n.clone())
            .ok_or(Error::InvalidPQ)?
            .into();

        let crt_mod_nn = CrtExp::build_nn(&p, &q).ok_or(Error::BuildFastExp)?;
        let exp_n = crt_mod_nn.prepare_exponent(&ek.n);
        let exp_lambda = crt_mod_nn.prepare_exponent(&lambda);

        Ok(Self {
            ek,
            mu: u,
            crt_mod_nn,
            exp_n,
            exp_lambda,
        })
    }

    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.ek
    }

    /// Decrypts the ciphertext, returns plaintext in `{-N/2, .., N_2}`
    pub fn decrypt(&self, c: &Ciphertext) -> Result<Plaintext, Error> {
        if !in_mult_group(c, &self.ek.nn) {
            return Err(Error::Decrypt("not in mult group"));
        }

        // a = c^\lambda mod n^2
        let a = self
            .crt_mod_nn
            .exp(c, &self.exp_lambda)
            .ok_or(Error::Decrypt("exponentiate"))?;

        // ell = L(a, N)
        let l = self.ek.l(&a).ok_or(Error::Decrypt("compute l"))?;

        // m = lu = L(a)*u = L(c^\lamba*)u mod n
        let plaintext = (l * &self.mu) % &self.ek.n;

        if Integer::from(&plaintext << 1) >= self.ek.n {
            Ok(plaintext - &self.ek.n)
        } else {
            Ok(plaintext)
        }
    }

    /// Encrypts a plaintext `x` in `{-N/2, .., N/2}` with `nonce` from `Z*_n`
    ///
    /// It uses the fact that factorization of `N` is known to speed up encryption.
    ///
    /// Returns error if inputs are not in specified range
    pub fn encrypt_with(&self, x: &Plaintext, nonce: &Nonce) -> Result<Ciphertext, Error> {
        if !self.ek.in_signed_group(x) || !in_mult_group(nonce, &self.ek.n) {
            return Err(Error::Encrypt);
        }

        let x = if x >= &Integer::ZERO {
            x.clone()
        } else {
            x + &self.ek.n
        };

        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let a = (Integer::ONE + x * &self.ek.n) % &self.ek.nn;
        // b = nonce^N mod N^2
        let b = self
            .crt_mod_nn
            .exp(nonce, &self.exp_n)
            .ok_or(Error::Encrypt)?;

        Ok((a * b) % &self.ek.nn)
    }

    /// Homomorphic multiplication of scalar at ciphertext
    ///
    /// It uses the fact that factorization of `N` is known to speed up an operation.
    pub fn omul(&self, scalar: &Integer, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        if !in_mult_group_abs(scalar, &self.ek.n) || !in_mult_group(ciphertext, &self.ek.nn) {
            return Err(Error::Ops);
        }

        let e = self.crt_mod_nn.prepare_exponent(scalar);
        self.crt_mod_nn.exp(ciphertext, &e).ok_or(Error::Ops)
    }
}

/// Checks that `x` is in Z*_n
#[inline(always)]
pub fn in_mult_group(x: &Integer, n: &Integer) -> bool {
    x >= &Integer::ZERO && in_mult_group_abs(x, n)
}

/// Checks that `abs(x)` is in Z*_n
#[inline(always)]
pub fn in_mult_group_abs(x: &Integer, n: &Integer) -> bool {
    malachite::num::arithmetic::traits::ExtendedGcd::extended_gcd(x, n)
        .0 == Natural::ONE
}

/// Faster algorithm for modular exponentiation based on Chinese remainder theorem when modulo factorization is known
///
/// `CrtExp` makes exponentation modulo `n` faster when factorization `n = n1 * n2` is known as well as `phi(n1)` and `phi(n2)`
/// (note that `n1` and `n2` don't need to be primes). In this case, you can [build](Self::build) a `CrtExp` and use provided
/// [exponentiation algorithm](Self::exp).
#[derive(Clone)]
pub struct CrtExp {
    n: Integer,
    n1: Integer,
    phi_n1: Integer,
    n2: Integer,
    phi_n2: Integer,
    beta: Integer,
}

/// Exponent for [modular exponentiation](CrtExp::exp) via [`CrtExp`]
#[derive(Clone)]
pub struct Exponent {
    e_mod_phi_pp: Integer,
    e_mod_phi_qq: Integer,
    is_negative: bool,
}

impl CrtExp {
    /// Builds a `CrtExp` for exponentation modulo `n = n1 * n2`
    ///
    /// `phi_n1 = phi(n1)` and `phi_n2 = phi(n2)` need to be known. For instance, if `p` is a prime,
    /// then `phi(p) = p - 1` and `phi(p^2) = p * (p - 1)`.
    ///
    /// [`CrtExp::build_n`] and [`CrtExp::build_nn`] can be used when `n1` and `n2` are primes or
    /// square of primes.
    pub fn build(n1: Integer, phi_n1: Integer, n2: Integer, phi_n2: Integer) -> Option<Self> {
        if n1 <= Integer::ZERO
            || n2 <= Integer::ZERO
            || phi_n1 <= Integer::ZERO
            || phi_n2 <= Integer::ZERO
            || phi_n1 >= n1
            || phi_n2 >= n2
        {
            return None;
        }

        let beta = invert(n1.clone(), n2.clone())?;
        Some(Self {
            n: &n1 * &n2,
            n1,
            phi_n1,
            n2,
            phi_n2,
            beta,
        })
    }

    /// Builds a `CrtExp` for exponentiation modulo `n = p * q` where `p`, `q` are primes
    pub fn build_n(p: &Integer, q: &Integer) -> Option<Self> {
        let phi_p = p - Integer::ONE;
        let phi_q = q - Integer::ONE;
        Self::build(p.clone(), phi_p, q.clone(), phi_q)
    }

    /// Builds a `CrtExp` for exponentiation modulo `nn = (p * q)^2` where `p`, `q` are primes
    pub fn build_nn(p: &Integer, q: &Integer) -> Option<Self> {
        let pp = p * p;
        let qq = q * q;
        let phi_pp = &pp - p;
        let phi_qq = &qq - q;
        Self::build(pp, phi_pp, qq, phi_qq)
    }

    /// Prepares exponent to perform [modular exponentiation](Self::exp)
    pub fn prepare_exponent(&self, e: &Integer) -> Exponent {
        let neg_e = -e;
        let is_negative = e <= &Integer::ZERO;
        let e = if is_negative { &neg_e } else { e };
        let e_mod_phi_pp = e % &self.phi_n1;
        let e_mod_phi_qq = e % &self.phi_n2;
        Exponent {
            e_mod_phi_pp,
            e_mod_phi_qq,
            is_negative,
        }
    }

    /// Performs exponentiation modulo `n`
    ///
    /// Exponent needs to be output of [`CrtExp::prepare_exponent`]
    pub fn exp(&self, x: &Integer, e: &Exponent) -> Option<Integer> {
        let s1 = modulo(x, &self.n1);
        let s2 = modulo(x, &self.n2);

        // `e_mod_phi_pp` and `e_mod_phi_qq` are guaranteed to be non-negative by construction
        #[allow(clippy::expect_used)]
        let r1 = pow_mod(s1, e.e_mod_phi_pp.clone(), self.n1.clone())
            .expect("exponent is guaranteed to be non-negative");
        #[allow(clippy::expect_used)]
        let r2 = pow_mod(s2, e.e_mod_phi_qq.clone(), self.n2.clone())
            .expect("exponent is guaranteed to be non-negative");

        let result = modulo(&((r2 - &r1) * &self.beta), &self.n2) * &self.n1 + &r1;

        if e.is_negative {
            invert(result, self.n.clone())
        } else {
            Some(result)
        }
    }
}

fn pow_mod(mut x: Integer, e: Integer, m: Integer) -> Option<Integer> {
    x.mod_assign(&m);
    let x = x.unsigned_abs();
    let m = m.unsigned_abs();
    if e >= Integer::ZERO {
        let e = e.unsigned_abs();
        Some(x.mod_pow(e, m).into())
    } else {
        let e = e.unsigned_abs();
        let x = x.mod_inverse(&m)?;
        Some(x.mod_pow(e, m).into())
    }
}

fn invert(mut x: Integer, m: Integer) -> Option<Integer> {
    x.mod_assign(&m);
    let x = x.unsigned_abs();
    let m = m.unsigned_abs();
    x.mod_inverse(&m).map(Into::into)
}

fn lcm(a: &Integer, b: &Integer) -> Integer {
    let gcd: Integer = malachite::num::arithmetic::traits::ExtendedGcd::extended_gcd(a, b).0.into();
    a * b / gcd
}

/// Result is always positive
fn modulo(x: &Integer, m: &Integer) -> Integer {
    if x < &Integer::ZERO {
        m + x % m
    } else {
        x % m
    }
}

pub fn random_bits(bits: usize, rng: &mut impl rand_core::RngCore) -> Natural {
    let ubig = crate::p_dashu::random_bits(bits, rng);
    let digits = ubig.to_string();
    <Natural as std::str::FromStr>::from_str(&digits).unwrap()
}

pub fn random_below(num: Integer, rng: &mut impl rand_core::RngCore) -> Integer {
    let num = dashu::integer::IBig::from_str_radix(&num.to_string(), 10).unwrap();
    let ibig = crate::p_dashu::random_below(num, rng);
    let digits = ibig.to_string();
    <Integer as std::str::FromStr>::from_str(&digits).unwrap()
}

/*
/// Generates a random safe prime
pub fn generate_safe_prime(rng: &mut impl rand_core::RngCore, bits: usize) -> Integer {
    sieve_generate_safe_primes(rng, bits, 135)
}

/// Generate a random safe prime with a given sieve parameter.
///
/// For different bit sizes, different parameter value will give fastest
/// generation, the higher bit size - the higher the sieve parameter.
/// The best way to select the parameter is by trial. The one used by
/// [`generate_safe_prime`] is indistinguishable from optimal for 500-1700 bit
/// lengths.
pub fn sieve_generate_safe_primes(
    rng: &mut impl rand_core::RngCore,
    bits: usize,
    amount: usize,
) -> Integer {
    use rug::integer::IsPrime;

    let amount = amount.min(crate::small_primes::SMALL_PRIMES.len());
    let mut x = Natural::ZERO;

    'trial: loop {
        // generate an odd number of length `bits - 2`
        x = random_bits(bits - 1, &mut rng);
        // `random_bits` is guaranteed to not set `bits-1`-th bit, but not
        // guaranteed to set the `bits-2`-th
        x.set_bit(bits - 2);
        x |= 1u32;

        for &small_prime in &crate::small_primes::SMALL_PRIMES[0..amount] {
            let mod_result = x % small_prime;
            if mod_result == (small_prime - 1) / 2 {
                continue 'trial;
            }
        }

        // 25 taken same as one used in mpz_nextprime
        if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
            x <<= 1;
            x += 1;
            if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
                return x.into();
            }
        }
    }
}
*/

/// Samples `x` in Z*_n
pub fn sample_in_mult_group(rng: &mut impl rand_core::RngCore, n: &Integer) -> Integer {
    let mut x;
    loop {
        x = random_below(n.clone(), rng);
        if in_mult_group(&x, n) {
            return x;
        }
    }
}

pub fn a_dk() -> DecryptionKey {
    let p = Integer::from_string_base(16, crate::two_primes::P).unwrap();
    let q = Integer::from_string_base(16, crate::two_primes::Q).unwrap();
    DecryptionKey::from_primes(p, q).unwrap()
}

#[cfg(test)]
mod test {
    use malachite::{integer::Integer, num::{basic::traits::One as _, conversion::traits::FromStringBase as _}};

    use super::{random_below, DecryptionKey};

    #[test]
    fn encrypt_decrypt() {
        let mut rng = rand_dev::DevRng::new();
        let dk = random_key_for_tests(&mut rng);
        let ek = &dk.ek;

        for _ in 0..20 {
            // Generate plaintext in [-N/2; N/2)
            let plaintext = super::random_below(ek.n.clone(), &mut rng);
            let plaintext = plaintext - (&ek.n / Integer::from(2u8));
            println!("Plaintext: {plaintext}");

            // Encrypt and decrypt
            let nonce = super::sample_in_mult_group(&mut rng, &ek.n);
            let ciphertext = ek.encrypt_with(&plaintext, &nonce).unwrap();
            println!("Ciphertext: {ciphertext}");
            println!("Nonce: {nonce}");

            let decrypted = dk.decrypt(&ciphertext).unwrap();
            println!("Decrypted: {decrypted}");

            assert_eq!(plaintext, decrypted);
            println!();
        }

        // Check corner cases

        let lower_bound = -&ek.n / Integer::from(2u8);
        let upper_bound = &ek.n / Integer::from(2u8);

        let corner_cases = [
            lower_bound.clone(),
            lower_bound.clone() + Integer::ONE,
            upper_bound.clone() - Integer::ONE,
            upper_bound.clone(),
        ];
        for (i, plaintext) in corner_cases.into_iter().enumerate() {
            println!("Corner case {i}");
            let nonce = super::sample_in_mult_group(&mut rng, &ek.n);
            let ciphertext = ek.encrypt_with(&plaintext, &nonce).unwrap();
            let ciphertext_ = dk.encrypt_with(&plaintext, &nonce).unwrap();
            assert_eq!(ciphertext, ciphertext_);
            let decrypted = dk.decrypt(&ciphertext).unwrap();
            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn homorphic_ops() {
        let mut rng = rand_dev::DevRng::new();
        let dk = random_key_for_tests(&mut rng);
        let ek = &dk.ek;

        for _ in 0..10 {
            let a = random_below(ek.n.clone(), &mut rng);
            let b = random_below(ek.n.clone(), &mut rng);
            let a = a - (&ek.n / Integer::from(2u8));
            let b = b - (&ek.n / Integer::from(2u8));
            println!("a: {a}");
            println!("b: {b}");

            let nonce = super::sample_in_mult_group(&mut rng, &ek.n);
            let enc_a = ek.encrypt_with(&a, &nonce).unwrap();
            let nonce = super::sample_in_mult_group(&mut rng, &ek.n);
            let enc_b = ek.encrypt_with(&b, &nonce).unwrap();

            // Addition
            {
                let enc_a_plus_b = ek.oadd(&enc_a, &enc_b).unwrap();
                let a_plus_b = dk.decrypt(&enc_a_plus_b).unwrap();
                assert_eq!(a_plus_b, signed_modulo(&(&a + &b), &ek.n));
            }

            // Subtraction
            {
                let enc_a_minus_b = ek.osub(&enc_a, &enc_b).unwrap();
                let a_minus_b = dk.decrypt(&enc_a_minus_b).unwrap();
                assert_eq!(a_minus_b, signed_modulo(&(&a - &b), &ek.n));
            }

            // Negation
            {
                let enc_neg_a = ek.oneg(&enc_a).unwrap();
                let neg_a = dk.decrypt(&enc_neg_a).unwrap();
                assert_eq!(neg_a, signed_modulo(&-&a, &ek.n));
            }

            // Multiplication
            {
                let enc_a_at_b = ek.omul(&a, &enc_b).unwrap();
                let a_at_b = dk.decrypt(&enc_a_at_b).unwrap();
                assert_eq!(a_at_b, signed_modulo(&(&a * &b), &ek.n));
            }
        }
    }

    fn random_key_for_tests(_rng: &mut impl rand_core::RngCore) -> DecryptionKey {
        let p = Integer::from_string_base(16, crate::two_primes::P).unwrap();
        let q = Integer::from_string_base(16, crate::two_primes::Q).unwrap();
        DecryptionKey::from_primes(p, q).unwrap()
    }

    /// Takes `x mod n` and maps result to `{-N/2, .., N/2}`
    fn signed_modulo(x: &Integer, n: &Integer) -> Integer {
        let x = super::modulo(x, n);
        unsigned_mod_to_signed(x, n)
    }

    /// Maps `{0, .., N-1}` to `{-N/2, .., N/2}`
    fn unsigned_mod_to_signed(x: Integer, n: &Integer) -> Integer {
        if Integer::from(2u8) * &x >= *n {
            x - n
        } else {
            x
        }
    }

    #[test]
    fn pow_mod() {
        let mut rng = rand_dev::DevRng::new();
        let m: Integer = super::random_bits(512, &mut rng).into();
        let x = super::random_below(m.clone(), &mut rng);
        let e = super::random_below(m.clone(), &mut rng);
        let r = super::pow_mod(x.clone(), e.clone(), m.clone()).unwrap();

        let m = to_rug(&m);
        let x = to_rug(&x);
        let e = to_rug(&e);
        let r_ = x.pow_mod(&e, &m).unwrap();
        assert_eq!(to_rug(&r), r_);
    }

    #[test]
    fn invert() {
        let mut rng = rand_dev::DevRng::new();
        let m: Integer = super::random_bits(512, &mut rng).into();
        let (x, r) = loop {
            let x = super::random_below(m.clone(), &mut rng);
            if let Some(r) = super::invert(x.clone(), m.clone()) {
                break (x, r);
            }
        };

        let m = to_rug(&m);
        let x = to_rug(&x);
        let r_ = x.invert(&m).unwrap();
        assert_eq!(to_rug(&r), r_);
    }

    #[test]
    fn encrypt_decrypt_compare() {
        let mut rng = rand_dev::DevRng::new();
        let dk = {
            let p = Integer::from_string_base(16, crate::two_primes::P).unwrap();
            let q = Integer::from_string_base(16, crate::two_primes::Q).unwrap();
            DecryptionKey::from_primes(p, q).unwrap()
        };
        let dk_ = {
            let p = rug::Integer::from_str_radix(crate::two_primes::P, 16).unwrap();
            let q = rug::Integer::from_str_radix(crate::two_primes::Q, 16).unwrap();
            crate::p_rug::DecryptionKey::from_primes(p, q).unwrap()
        };
        let ek = &dk.ek;
        let ek_ = &dk_.ek;

        let plaintext = super::random_below(ek.n.clone(), &mut rng);
        let plaintext = plaintext - (&ek.n / Integer::from(2u8));
        let plaintext_ = to_rug(&plaintext);
        let nonce = super::sample_in_mult_group(&mut rng, &ek.n);
        let nonce_ = to_rug(&nonce);

        let ciphertext = ek.encrypt_with(&plaintext, &nonce).unwrap();
        let ciphertext_ = ek_.encrypt_with(&plaintext_, &nonce_).unwrap();
        assert_eq!(to_rug(&ciphertext), ciphertext_);

        let a = dk.crt_mod_nn.exp(&ciphertext, &dk.exp_lambda).unwrap();
        let a_ = dk_.crt_mod_nn.exp(&ciphertext_, &dk_.exp_lambda).unwrap();
        assert_eq!(to_rug(&a), a_);

        let decrypted = dk.decrypt(&ciphertext).unwrap();
        let decrypted_ = dk_.decrypt(&ciphertext_).unwrap();
        assert_eq!(to_rug(&decrypted), decrypted_);
    }

    fn to_rug(x: &Integer) -> rug::Integer {
        let x_dec = x.to_string();
        rug::Integer::from_str_radix(&x_dec, 10).unwrap()
    }
}
