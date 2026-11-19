#!/bin/bash -eu
# ClusterFuzzLite build: every cargo-fuzz target in fuzz/ goes to $OUT, with its seed corpus
# and libFuzzer options (fuzz/options/<target>.options).
cd "$SRC/network-scope"
rustc --version
# -O: optimized; --debug-assertions: integer overflow and debug_assert! failures are crashes.
cargo fuzz build -O --debug-assertions
release="fuzz/target/x86_64-unknown-linux-gnu/release"
for target in $(cargo fuzz list); do
  cp "$release/$target" "$OUT/"
  if [ -d "fuzz/corpus/$target" ]; then
    (cd "fuzz/corpus/$target" && zip -q -r "$OUT/${target}_seed_corpus.zip" .)
  fi
  if [ -f "fuzz/options/$target.options" ]; then
    cp "fuzz/options/$target.options" "$OUT/"
  fi
done
# The fuzzers run in a different image (base-runner): they must not need extra shared
# libraries (the GUI crates load theirs with dlopen). Show what they link.
ldd "$OUT/$(cargo fuzz list | head -n 1)"
