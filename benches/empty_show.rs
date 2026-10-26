use criterion::{criterion_group, criterion_main};

mod empty;
mod util;

criterion_group!(empty_show, empty::bench_empty);
criterion_main!(util::new_size_file, empty_show);
