use every_bignum::p_rug;

/// Safe 1536 bit prime number in hex encoding
const P: &str = "e84f454a8dd9e923fc85be8ca09278e28c5a3d9419cf118ef56912910f364c5\
                 29d999dba2837e55d413827ccf97a4b6c49addd56f079032164d487fbd22d5e\
                 a9ff0c8fdc6bce1b878a7109f33061874f310ae35ac75db3ac3fd5f49d8b85b\
                 8823f05fc288602abf6a4ef641a3766a44d7ecbceebe3bf144a582639b55658\
                 e93cc57445715ce83c0e7088ec701ded2bcbd2e91a68cb26b1aaddadf99aeef\
                 927fb82459a3805c232e36162cbea024a2fe7485b96eeb278d45016c622261b\
                 3d3aa3";
/// Safe 1536 bit prime number in hex encoding
const Q: &str = "9461f6a273f4bdf08ce0b1071253e0688d622d6b714b407200fa709d964034c\
                 1b84b97057a8dd48904a99e83f1cb4c94d6927ac6424b8028eefe6503336e03\
                 1ff0d7379932b1f6fa457d8a1e4d9436c42df8ba86ad54cc83a708cd6385d4d\
                 5cbf0c62f9f692f04e500726d5d41224e2ec88d48bd3d04c004c9a8e6ce23ee\
                 fb54995d7b4473c021f8a72c06fe3ce6488e6b1b8ad51b635a853121f4285c0\
                 c364aab061aea672cb6dd86cee08b63a5b3f1fc78f1712e1a333b2552471e5a\
                 d8403f";

fn rug_dk() -> p_rug::DecryptionKey {
    let p = rug::Integer::from_str_radix(P, 16).unwrap();
    let q = rug::Integer::from_str_radix(Q, 16).unwrap();
    p_rug::DecryptionKey::from_primes(p, q).unwrap()
}

fn encrypt(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("encrypt");

    // ------ rug ------ //

    let mut rng = base_rng.clone();
    let dk = rug_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let x = ek.n().clone().random_below(&mut p_rug::external_rand(&mut rng))
            - ek.half_n();
        let nonce = p_rug::sample_in_mult_group(&mut rng, ek.n());
        (x, nonce)
    };

    group.bench_function("rug", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(x, nonce)| ek.encrypt_with(&x, &nonce).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn encrypt_with_factorization(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("encrypt with factorization");

    // ------ rug ------ //

    let mut rng = base_rng.clone();
    let dk = rug_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let x = ek.n().clone().random_below(&mut p_rug::external_rand(&mut rng))
            - ek.half_n();
        let nonce = p_rug::sample_in_mult_group(&mut rng, ek.n());
        (x, nonce)
    };

    group.bench_function("rug", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(x, nonce)| dk.encrypt_with(&x, &nonce).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn decrypt(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("decrypt");

    // ------ rug ------ //

    let mut rng = base_rng.clone();
    let dk = rug_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let x = ek.n().clone().random_below(&mut p_rug::external_rand(&mut rng))
            - ek.half_n();
        let nonce = p_rug::sample_in_mult_group(&mut rng, ek.n());
        let c = dk.encrypt_with(&x, &nonce).unwrap();
        c
    };

    group.bench_function("rug", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |c| dk.decrypt(&c).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn omul(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("omul");

    // ------ rug ------ //

    let mut rng = base_rng.clone();
    let dk = rug_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let k = p_rug::sample_in_mult_group(&mut rng, ek.n());
        let x = ek.n().clone().random_below(&mut p_rug::external_rand(&mut rng))
            - ek.half_n();
        let nonce = p_rug::sample_in_mult_group(&mut rng, ek.n());
        let c = dk.encrypt_with(&x, &nonce).unwrap();
        (c, k)
    };

    group.bench_function("rug", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(c, k)| ek.omul(&k, &c).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn omul_with_factorization(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("omul with factorization");

    // ------ rug ------ //

    let mut rng = base_rng.clone();
    let dk = rug_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let k = p_rug::sample_in_mult_group(&mut rng, ek.n());
        let x = ek.n().clone().random_below(&mut p_rug::external_rand(&mut rng))
            - ek.half_n();
        let nonce = p_rug::sample_in_mult_group(&mut rng, ek.n());
        let c = dk.encrypt_with(&x, &nonce).unwrap();
        (c, k)
    };

    group.bench_function("rug", |b| {
        b.iter_batched(
            &mut generate_inputs,
            |(c, k)| dk.omul(&k, &c).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn safe_prime(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("safe primes");
    group.sample_size(10);
    let bits = 1024;

    let mut rng = base_rng.clone();
    group.bench_function("rug", |b| {
        b.iter(|| p_rug::generate_safe_prime(&mut rng, bits))
    });
}

criterion::criterion_group!(
    benches,
    encrypt,
    encrypt_with_factorization,
    decrypt,
    omul,
    omul_with_factorization,
    safe_prime,
);
criterion::criterion_main!(benches);
