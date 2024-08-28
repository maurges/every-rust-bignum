use rug::{Assign as _, Complete, Integer};

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
        let half_n = n.clone() >> 1u32;
        let neg_half_n = -half_n.clone();
        Self {
            n, nn, half_n, neg_half_n
        }
    }

    pub fn n(&self) -> &Integer {
        &self.n
    }
    pub fn half_n(&self) -> &Integer {
        &self.half_n
    }

    fn l(&self, x: &Integer) -> Option<Integer> {
        if (x % &self.n).complete() != *Integer::ONE {
            return None;
        }
        if !in_mult_group(x, &self.nn) {
            return None;
        }

        // (x - 1) / N
        Some((x - Integer::ONE).complete() / &self.n)
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

        let x = if x.cmp0().is_ge() {
            x.clone()
        } else {
            (x + &self.n).complete()
        };

        // a = (1 + N)^x mod N^2 = (1 + xN) mod N^2
        let a = (Integer::ONE + (&x * &self.n).complete()) % &self.nn;
        // b = nonce^N mod N^2
        let b = nonce
            .clone()
            .pow_mod(&self.n, &self.nn)
            .or(Err(Error::PowModUndef))?;

        let c = (a * b).modulo(&self.nn);
        Ok(c)
    }

    /// Homomorphic addition of two ciphertexts
    pub fn oadd(&self, c1: &Ciphertext, c2: &Ciphertext) -> Result<Ciphertext, Error> {
        if !in_mult_group(c1, &self.nn) || !in_mult_group(c2, &self.nn) {
            Err(Error::Ops)
        } else {
            Ok((c1 * c2).complete() % &self.nn)
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
        if !in_mult_group_abs(scalar, &self.n)
            || !in_mult_group(ciphertext, &self.nn)
        {
            Err(Error::Ops)
        } else {
            Ok(ciphertext
                .pow_mod_ref(scalar, &self.nn)
                .ok_or(Error::Ops)?
                .into()
                )
        }
    }

    /// Homomorphic negation of a ciphertext
    pub fn oneg(&self, ciphertext: &Ciphertext) -> Result<Ciphertext, Error> {
        ciphertext.invert_ref(&self.nn).ok_or(Error::Ops).map(Into::into)
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
    /// Generates a paillier key
    ///
    /// Samples two safe 1536-bits primes that meets 128 bits security level
    pub fn generate(rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Result<Self, Error> {
        let p = generate_safe_prime(rng, 1536);
        let q = generate_safe_prime(rng, 1536);
        Self::from_primes(p, q)
    }

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
        let pm1 = Integer::from(&p - 1);
        let qm1 = Integer::from(&q - 1);
        let ek = EncryptionKey::from_n((&p * &q).complete());
        let lambda = pm1.clone().lcm(&qm1);
        if lambda.cmp0().is_eq() {
            return Err(Error::InvalidPQ);
        }

        // u = lambda^-1 mod N
        let u = lambda.invert_ref(&ek.n).ok_or(Error::InvalidPQ)?.into();

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
            return Err(Error::Decrypt);
        }

        // a = c^\lambda mod n^2
        let a = self
            .crt_mod_nn
            .exp(c, &self.exp_lambda)
            .ok_or(Error::Decrypt)?;

        // ell = L(a, N)
        let l = self.ek.l(&a).ok_or(Error::Decrypt)?;

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

        let x = if x.cmp0().is_ge() {
            x.clone()
        } else {
            (x + &self.ek.n).complete()
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
        if !in_mult_group_abs(scalar, &self.ek.n)
            || !in_mult_group(ciphertext, &self.ek.nn)
        {
            return Err(Error::Ops);
        }

        let e = self.crt_mod_nn.prepare_exponent(scalar);
        self.crt_mod_nn.exp(ciphertext, &e).ok_or(Error::Ops)
    }
}

/// Checks that `x` is in Z*_n
#[inline(always)]
pub fn in_mult_group(x: &Integer, n: &Integer) -> bool {
    x.cmp0().is_ge() && in_mult_group_abs(x, n)
}

/// Checks that `abs(x)` is in Z*_n
#[inline(always)]
pub fn in_mult_group_abs(x: &Integer, n: &Integer) -> bool {
    x.gcd_ref(n).complete() == *Integer::ONE
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
        if n1.cmp0().is_le()
            || n2.cmp0().is_le()
            || phi_n1.cmp0().is_le()
            || phi_n2.cmp0().is_le()
            || phi_n1 >= n1
            || phi_n2 >= n2
        {
            return None;
        }

        let beta = n1.invert_ref(&n2)?.into();
        Some(Self {
            n: (&n1 * &n2).complete(),
            n1,
            phi_n1,
            n2,
            phi_n2,
            beta,
        })
    }

    /// Builds a `CrtExp` for exponentiation modulo `n = p * q` where `p`, `q` are primes
    pub fn build_n(p: &Integer, q: &Integer) -> Option<Self> {
        let phi_p = (p - 1u8).complete();
        let phi_q = (q - 1u8).complete();
        Self::build(p.clone(), phi_p, q.clone(), phi_q)
    }

    /// Builds a `CrtExp` for exponentiation modulo `nn = (p * q)^2` where `p`, `q` are primes
    pub fn build_nn(p: &Integer, q: &Integer) -> Option<Self> {
        let pp = p.square_ref().complete();
        let qq = q.square_ref().complete();
        let phi_pp = (&pp - p).complete();
        let phi_qq = (&qq - q).complete();
        Self::build(pp, phi_pp, qq, phi_qq)
    }

    /// Prepares exponent to perform [modular exponentiation](Self::exp)
    pub fn prepare_exponent(&self, e: &Integer) -> Exponent {
        let neg_e = (-e).complete();
        let is_negative = e.cmp0().is_lt();
        let e = if is_negative { &neg_e } else { e };
        let e_mod_phi_pp = e.modulo_ref(&self.phi_n1).complete();
        let e_mod_phi_qq = e.modulo_ref(&self.phi_n2).complete();
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
        let s1 = x.modulo_ref(&self.n1).complete();
        let s2 = x.modulo_ref(&self.n2).complete();

        // `e_mod_phi_pp` and `e_mod_phi_qq` are guaranteed to be non-negative by construction
        #[allow(clippy::expect_used)]
        let r1 = s1
            .pow_mod(&e.e_mod_phi_pp, &self.n1)
            .expect("exponent is guaranteed to be non-negative");
        #[allow(clippy::expect_used)]
        let r2 = s2
            .pow_mod(&e.e_mod_phi_qq, &self.n2)
            .expect("exponent is guaranteed to be non-negative");

        let result = ((r2 - &r1) * &self.beta).modulo(&self.n2) * &self.n1 + &r1;

        if e.is_negative {
            result.invert(&self.n).ok()
        } else {
            Some(result)
        }
    }
}


/// Generates a random safe prime
pub fn generate_safe_prime(rng: &mut impl rand_core::RngCore, bits: u32) -> Integer {
    sieve_generate_safe_primes(rng, bits, 135)
}

/// Generate a random safe prime with a given sieve parameter.
///
/// For different bit sizes, different parameter value will give fastest
/// generation, the higher bit size - the higher the sieve parameter.
/// The best way to select the parameter is by trial. The one used by
/// [`generate_safe_prime`] is indistinguishable from optimal for 500-1700 bit
/// lengths.
pub fn sieve_generate_safe_primes(rng: &mut impl rand_core::RngCore, bits: u32, amount: usize) -> Integer {
    use rug::integer::IsPrime;

    let amount = amount.min(crate::small_primes::SMALL_PRIMES.len());
    let mut rng = external_rand(rng);
    let mut x = Integer::new();

    'trial: loop {
        // generate an odd number of length `bits - 2`
        x.assign(Integer::random_bits(bits - 1, &mut rng));
        // `random_bits` is guaranteed to not set `bits-1`-th bit, but not
        // guaranteed to set the `bits-2`-th
        x.set_bit(bits - 2, true);
        x |= 1u32;

        for &small_prime in &crate::small_primes::SMALL_PRIMES[0..amount] {
            let mod_result = x.mod_u(small_prime);
            if mod_result == (small_prime - 1) / 2 {
                continue 'trial;
            }
        }

        // 25 taken same as one used in mpz_nextprime
        if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
            x <<= 1;
            x += 1;
            if let IsPrime::Yes | IsPrime::Probably = x.is_probably_prime(25) {
                return x;
            }
        }
    }
}


/// Wraps any randomness source that implements [`rand_core::RngCore`] and makes
/// it compatible with [`rug::rand`].
pub fn external_rand(rng: &mut impl rand_core::RngCore) -> rug::rand::ThreadRandState<'_> {
    // This is a giant downside of rug, that it can't work with rand_core and
    // that this impl has to byte muck

    use bytemuck::TransparentWrapper;

    #[derive(TransparentWrapper)]
    #[repr(transparent)]
    pub struct ExternalRand<R>(R);

    impl<R: rand_core::RngCore> rug::rand::ThreadRandGen for ExternalRand<R> {
        fn gen(&mut self) -> u32 {
            self.0.next_u32()
        }
    }

    rug::rand::ThreadRandState::new_custom(ExternalRand::wrap_mut(rng))
}

/// Samples `x` in Z*_n
pub fn sample_in_mult_group(rng: &mut impl rand_core::RngCore, n: &Integer) -> Integer {
    let mut rng = external_rand(rng);
    let mut x = Integer::new();
    loop {
        x.assign(n.random_below_ref(&mut rng));
        if in_mult_group(&x, n) {
            return x;
        }
    }
}


#[cfg(test)]
mod test {
    use rug::{Complete as _, Integer};

    use super::DecryptionKey;

    #[test]
    fn encrypt_decrypt() {
        let mut rng = rand_dev::DevRng::new();
        let dk = random_key_for_tests(&mut rng);
        let ek = &dk.ek;

        for _ in 0..50 {
            // Generate plaintext in [-N/2; N/2)
            let plaintext = &ek
                .n
                .clone()
                .random_below(&mut super::external_rand(&mut rng));
            let plaintext = plaintext - (&ek.n / 2u8).complete();
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

        let lower_bound = -(&ek.n / 2u8).complete();
        let upper_bound = (&ek.n / 2u8).complete();

        let corner_cases = [
            lower_bound.clone(),
            lower_bound.clone() + 1,
            upper_bound.clone() - 1,
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

        for _ in 0..100 {
            let a = ek
                .n
                .clone()
                .random_below(&mut super::external_rand(&mut rng));
            let b = ek
                .n
                .clone()
                .random_below(&mut super::external_rand(&mut rng));
            let a = a - (&ek.n / 2u8).complete();
            let b = b - (&ek.n / 2u8).complete();
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
                assert_eq!(a_plus_b, signed_modulo(&(&a + &b).complete(), &ek.n));
            }

            // Subtraction
            {
                let enc_a_minus_b = ek.osub(&enc_a, &enc_b).unwrap();
                let a_minus_b = dk.decrypt(&enc_a_minus_b).unwrap();
                assert_eq!(a_minus_b, signed_modulo(&(&a - &b).complete(), &ek.n));
            }

            // Negation
            {
                let enc_neg_a = ek.oneg(&enc_a).unwrap();
                let neg_a = dk.decrypt(&enc_neg_a).unwrap();
                assert_eq!(neg_a, signed_modulo(&(-&a).complete(), &ek.n));
            }

            // Multiplication
            {
                let enc_a_at_b = ek.omul(&a, &enc_b).unwrap();
                let a_at_b = dk.decrypt(&enc_a_at_b).unwrap();
                assert_eq!(a_at_b, signed_modulo(&(&a * &b).complete(), &ek.n));
            }
        }
    }

    fn random_key_for_tests(rng: &mut impl rand_core::RngCore) -> DecryptionKey {
        let p = super::generate_safe_prime(rng, 512);
        let q = super::generate_safe_prime(rng, 512);
        DecryptionKey::from_primes(p, q).unwrap()
    }


    /// Takes `x mod n` and maps result to `{-N/2, .., N/2}`
    fn signed_modulo(x: &Integer, n: &Integer) -> Integer {
        let x = x.modulo_ref(n).complete();
        unsigned_mod_to_signed(x, n)
    }


    /// Maps `{0, .., N-1}` to `{-N/2, .., N/2}`
    fn unsigned_mod_to_signed(x: Integer, n: &Integer) -> Integer {
        if (2u8 * &x).complete() >= *n {
            x - n
        } else {
            x
        }
    }
}
