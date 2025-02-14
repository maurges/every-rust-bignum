# quick summary

- rug - lgpl crate, really good
- crypto-bigint - constant time (unbelievably slow)

- awint - no modular arithmetic. No primes. Seemingly fixed width.
- bnum - fixed width. No modular arithmetic
- ibig - 10x slower than rug. No primes
- dashu - same as ibig, with slightly better api
- malachite - lgpl. Api is shit: convoluted traits, can't subtract {integer} from bigints. No primes. Api for random uses their own random generator and can only be seeded. And random doesn't even support generating big numbers! Why the fuck would I use your stupid random api to generate standart ints that I can generate with rand? It saddens me to say, but the performance is really good.
- num-bigint - slow. Api is nice-ish, just that modpow panics. It doesn't have primality test? That's weird, I was sure there is one
- num-bigint-dig - same as above, but has prime numbers and some minute differences (no ZERO)
- unknown-order - no longer supports arbitrary length. Gmp backend uses rug so we're back to square 1

