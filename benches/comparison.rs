use every_bignum::{p_rug, p_ibig};
use every_bignum::two_primes::{P, Q};

fn rug_dk() -> p_rug::DecryptionKey {
    let p = rug::Integer::from_str_radix(P, 16).unwrap();
    let q = rug::Integer::from_str_radix(Q, 16).unwrap();
    p_rug::DecryptionKey::from_primes(p, q).unwrap()
}

fn ibig_dk() -> p_ibig::DecryptionKey {
    let p = ibig::IBig::from_str_radix(P, 16).unwrap();
    let q = ibig::IBig::from_str_radix(Q, 16).unwrap();
    p_ibig::DecryptionKey::from_primes(p, q).unwrap()
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

    // ------ ibig ------ //

    let mut rng = base_rng.clone();
    let dk = ibig_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let x = p_ibig::random_below(ek.n().clone(), &mut rng) - ek.half_n();
        let nonce = p_ibig::sample_in_mult_group(&mut rng, ek.n());
        (x, nonce)
    };

    group.bench_function("ibig", |b| {
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

    // ------ ibig ------ //

    let mut rng = base_rng.clone();
    let dk = ibig_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let x = p_ibig::random_below(ek.n().clone(), &mut rng) - ek.half_n();
        let nonce = p_ibig::sample_in_mult_group(&mut rng, ek.n());
        (x, nonce)
    };

    group.bench_function("ibig", |b| {
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

    // ------ ibig ------ //

    let mut rng = base_rng.clone();
    let dk = ibig_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let x = p_ibig::random_below(ek.n().clone(), &mut rng) - ek.half_n();
        let nonce = p_ibig::sample_in_mult_group(&mut rng, ek.n());
        let c = dk.encrypt_with(&x, &nonce).unwrap();
        c
    };

    group.bench_function("ibig", |b| {
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

    // ------ ibig ------ //

    let mut rng = base_rng.clone();
    let dk = ibig_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let k = p_ibig::sample_in_mult_group(&mut rng, ek.n());
        let x = p_ibig::random_below(ek.n().clone(), &mut rng) - ek.half_n();
        let nonce = p_ibig::sample_in_mult_group(&mut rng, ek.n());
        let c = dk.encrypt_with(&x, &nonce).unwrap();
        (c, k)
    };

    group.bench_function("ibig", |b| {
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

    // ------ ibig ------ //

    let mut rng = base_rng.clone();
    let dk = ibig_dk();
    let ek = dk.encryption_key();
    let mut generate_inputs = || {
        let k = p_ibig::sample_in_mult_group(&mut rng, ek.n());
        let x = p_ibig::random_below(ek.n().clone(), &mut rng) - ek.half_n();
        let nonce = p_ibig::sample_in_mult_group(&mut rng, ek.n());
        let c = dk.encrypt_with(&x, &nonce).unwrap();
        (c, k)
    };

    group.bench_function("ibig", |b| {
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
