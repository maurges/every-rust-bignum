use every_bignum::{p_dashu, p_ibig, p_rug};

fn encrypt(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("encrypt");

    macro_rules! make {
        ($name:literal, $module:ident) => {
            let mut rng = base_rng.clone();
            let dk = $module::a_dk();
            let ek = dk.encryption_key();
            let mut generate_inputs = || {
                let x = $module::random_below(ek.n().clone(), &mut rng) - ek.half_n();
                let nonce = $module::sample_in_mult_group(&mut rng, ek.n());
                (x, nonce)
            };

            group.bench_function($name, |b| {
                b.iter_batched(
                    &mut generate_inputs,
                    |(x, nonce)| ek.encrypt_with(&x, &nonce).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            });
        };
    }

    make!("rug", p_rug);
    make!("ibig", p_ibig);
    make!("dashu", p_dashu);
}

fn encrypt_with_factorization(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("encrypt with factorization");

    // ------ rug ------ //

    macro_rules! make {
        ($name:literal, $module:ident) => {
            let mut rng = base_rng.clone();
            let dk = $module::a_dk();
            let ek = dk.encryption_key();
            let mut generate_inputs = || {
                let x = $module::random_below(ek.n().clone(), &mut rng) - ek.half_n();
                let nonce = $module::sample_in_mult_group(&mut rng, ek.n());
                (x, nonce)
            };

            group.bench_function($name, |b| {
                b.iter_batched(
                    &mut generate_inputs,
                    |(x, nonce)| dk.encrypt_with(&x, &nonce).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            });
        };
    }

    make!("rug", p_rug);
    make!("ibig", p_ibig);
    make!("dashu", p_dashu);
}

fn decrypt(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("decrypt");

    macro_rules! make {
        ($name:literal, $module:ident) => {
            let mut rng = base_rng.clone();
            let dk = $module::a_dk();
            let ek = dk.encryption_key();
            let mut generate_inputs = || {
                let x = $module::random_below(ek.n().clone(), &mut rng) - ek.half_n();
                let nonce = $module::sample_in_mult_group(&mut rng, ek.n());
                let c = dk.encrypt_with(&x, &nonce).unwrap();
                c
            };

            group.bench_function($name, |b| {
                b.iter_batched(
                    &mut generate_inputs,
                    |c| dk.decrypt(&c).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            });
        };
    }
    make!("rug", p_rug);
    make!("ibig", p_ibig);
    make!("dashu", p_dashu);
}

fn omul(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("omul");

    macro_rules! make {
        ($name:literal, $module:ident) => {
            let mut rng = base_rng.clone();
            let dk = $module::a_dk();
            let ek = dk.encryption_key();
            let mut generate_inputs = || {
                let k = $module::sample_in_mult_group(&mut rng, ek.n());
                let x = $module::random_below(ek.n().clone(), &mut rng) - ek.half_n();
                let nonce = $module::sample_in_mult_group(&mut rng, ek.n());
                let c = dk.encrypt_with(&x, &nonce).unwrap();
                (c, k)
            };

            group.bench_function($name, |b| {
                b.iter_batched(
                    &mut generate_inputs,
                    |(c, k)| ek.omul(&k, &c).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            });
        };
    }
    make!("rug", p_rug);
    make!("ibig", p_ibig);
    make!("dashu", p_dashu);
}

fn omul_with_factorization(c: &mut criterion::Criterion) {
    let base_rng = rand_dev::DevRng::new();

    let mut group = c.benchmark_group("omul with factorization");

    macro_rules! make {
        ($name:literal, $module:ident) => {
            let mut rng = base_rng.clone();
            let dk = $module::a_dk();
            let ek = dk.encryption_key();
            let mut generate_inputs = || {
                let k = $module::sample_in_mult_group(&mut rng, ek.n());
                let x = $module::random_below(ek.n().clone(), &mut rng) - ek.half_n();
                let nonce = $module::sample_in_mult_group(&mut rng, ek.n());
                let c = dk.encrypt_with(&x, &nonce).unwrap();
                (c, k)
            };

            group.bench_function($name, |b| {
                b.iter_batched(
                    &mut generate_inputs,
                    |(c, k)| dk.omul(&k, &c).unwrap(),
                    criterion::BatchSize::SmallInput,
                )
            });
        };
    }
    make!("rug", p_rug);
    make!("ibig", p_ibig);
    make!("dashu", p_dashu);
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
    //safe_prime,
);
criterion::criterion_main!(benches);
