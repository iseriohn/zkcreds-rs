<h1 align="center">zkcreds-rs</h1>
<p align="center">
    <a href="https://github.com/rozbb/zkcreds-rs/blob/main/LICENSE-APACHE"><img src="https://img.shields.io/badge/license-APACHE-blue.svg"></a>
    <a href="https://github.com/rozbb/zkcreds-rs/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <!--<a href="https://deps.rs/repo/github/rozbb/zkcreds-rs"><img src="https://deps.rs/repo/github/rozbb/zkcreds-rs/status.svg"></a>-->
</p>

A cryptographic library for designing anonymous credential systems in a flexible, issuer-agnostic, and efficient manner using general-purpose zero-knowledge proofs. This code accompanies the zk-creds paper [here](https://eprint.iacr.org/2022/878).

While the core library is written in Rust, this repository also includes an associated Python wrapper module for some of the higher-level interfaces. See [`src/lib.rs`](src/lib.rs), [`python-examples`](python-examples), and Web Demo below for more details.

## Development and Examples

For an overview of this library and usage snippets, see the wiki [here](https://github.com/rozbb/zkcreds-rs/wiki).

## Web Demo

With the repository's Rust toolchain and Python v3.7+ installed:

```bash
$ cd zkcreds-rs
# Install appropriate `python3.Xvenv` package...
# Configure Python virtual environment
$ python3 -m venv .env
$ source .env/bin/activate
$ pip install maturin

# Compile Rust binaries and install as Python (PyO3) bindings
$ maturin develop
# Local webserver provides a high-level demo
$ python3 python-examples/web-demo.py
```

Interact with the demo to get an idea for how arbitrary attribute fields can be formulated into a credential, and how this credential can be issued and subsequently shown without revealing any more than the fact that it satisfies the given criteria.

**NOTE**: The Python wrapper is currently incomplete, and as such the high-level web demo will be available in a future version.

## Benchmarks

The repository selects Rust 1.85 automatically through `rust-toolchain.toml`. Run a focused benchmark with:

```bash
cargo bench --bench empty_show -- "Empty show: verifying linkage" --sample-size 10 --warm-up-time 1 --measurement-time 1 --noplot
```

Run the full suite with `cargo bench`. It includes many proof-generation benchmarks and can take a long time, including when listing or filtering the combined `bench` target. Criterion writes results to `target/criterion/`, and the benchmarks create `proof_sizes.csv`. Passport benchmarks are skipped when `benches/passport/passport_dump.json` is absent.

## AVES one-time presentations

`src/aves_show.rs` adds an `AvesShowChecker` predicate for credentials that implement
`AccountableAttrs` with a field-element seed. **The seed must be included in the attributes
committed at issuance.** The checker proves a per-poll token and a response tag derived from
that committed seed. It works with the existing tree/forest membership and linkage proof APIs;
the predicate proof alone does not establish that a credential was issued.

The circuit accepts the 32-byte canonical compressed Ristretto encoding of an AVES Pedersen
commitment as `payload_commitment`. It represents the bytes as two 128-bit public field inputs,
so no information is lost by reducing a 256-bit encoding modulo the proof field. The tag binds
both halves to the credential seed and poll ID in one Poseidon call:
`H(poll_id, seed, low_half, high_half)`. The verifier must compare these exact bytes with the
commitment in the sampled entry rather than trust a prover-supplied commitment.
The commitment opening is not checked by this credential predicate. The same predicate proving
key works for every commitment.
AVES COUNT entries that currently expose a plain choice need a matching Pedersen commitment
in the sampled entry before they can use this predicate.

After verifying the linked zkcreds proof and the AVES index proof, the AVES verifier must:

1. Compare `presentation.entry_id()` with the sampled entry ID.
2. Compare `payload_commitment` with the serialized commitment in the sampled entry.
3. Reject a token already accepted for that poll, using an atomic check-and-insert if shows
   can arrive concurrently.

This gives one accepted response **per issued credential per poll**. Issuer policy must prevent
one person from obtaining multiple eligible credentials if the application needs one response
per person. The AVES range/order/aggregation proofs remain responsible for validity of the
private value; the credential circuit authenticates the submitted commitment bytes. If a
value and opening are revealed, AVES can verify them by recomputing the Pedersen commitment.

The AVES authenticity proof benchmarks are maintained by the Rating repository under
`rating/aves/benches/`. When this fork is checked out at `rating/zkcreds-rs`, see
[the benchmark documentation](../aves/benches/README.md) for commands and measurement
boundaries. This crate keeps its original library microbenchmarks.

### Passport benches

In order to run the benchmarks in `benches/passport`, you need to have a JSON dump of a passport. You can create this from your own US passport by installing the Android app [here](https://github.com/rozbb/passport-reader/) (prebuilt APKs can be found in the root directory). Once you have your passport dump in the clipboard, send it to yourself, put it in a file named `passport_dump.json`, and move it to this repo in `benches/passport/passport_dump.json`.

## License

 This library is distributed under either of the following licenses:
 
 * Apache License v2.0 ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT License ([LICENSE-MIT](LICENSE-MIT))
 
Unless explicitly stated otherwise, any contribution made to this library shall be dual-licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.

## Authors

* Michael Rosenberg - micro@cs.umd.edu
* Jacob White - white570@purdue.edu
