# Client-Light Functional Secure Secret Shared Retrieval for Privacy-Preserving Cloud Database Analytics

This repository is a derivative implementation based on the Waldo research prototype
("Client-Light Functional Secure Secret Shared Retrieval for Privacy-Preserving Cloud Database Analytics").

**Warning**: this is an academic prototype and is not production-ready.

## What Is In This Repo

- 3-server private query execution (`query_server`, `bench`, `correctness_tests`)
- Predicate/query modes:
- `point`, `range`
- `vb-non-fss-point`, `vb-non-fss-range`
- `vb-fss-point`, `vb-fss-range`
- `bo-non-fss-point`, `bo-non-fss-range`
- `bo-fss-point`, `bo-fss-range`
- A benchmark orchestrator: `scripts/bench_compare.py`

## Prerequisites

- CMake >= 3.5
- C++14 toolchain (GCC/Clang)
- gRPC + Protobuf (C++ development packages)
- Boost (`thread`, `system`)
- OpenMP
- Relic (for libOTe/libPSI stack)

The code vendors `libOTe`/`libPSI` sources under `fss-core`, but they still need to be
configured/built in your environment.

## Build

From repository root:

```bash
# 1) Build libOTe
cd fss-core/libOTe
cmake . -DENABLE_RELIC=ON -DENABLE_NP=ON -DENABLE_KKRT=ON
make -j

# 2) Build libPSI
cd ../libPSI
cmake . -DENABLE_RELIC=ON -DENABLE_DRRN_PSI=ON -DENABLE_KKRT_PSI=ON
make -j

# 3) Build this project
cd ../..
cmake -S . -B build
cmake --build build -j
```

Main binaries are generated in `build/bin`:

- `query_server`
- `bench`
- `correctness_tests`
- `query_client`

## Quick Local Run

Use the default local configs in `config/`:

```bash
# terminal 1
./build/bin/query_server config/server0.config

# terminal 2
./build/bin/query_server config/server1.config

# terminal 3
./build/bin/query_server config/server2.config
```

Then in terminal 4:

```bash
# correctness smoke
./build/bin/correctness_tests config/client.config

# benchmark entry
./build/bin/bench config/client.config
```

`bench` writes timing rows to:

- `<experiment_dir>/results.dat` (from `config/client.config`)

## Benchmark Script

Primary benchmark driver:

- `scripts/bench_compare.py`
- detailed script doc: `scripts/README_bench_compare.md`

Example:

```bash
python3 scripts/bench_compare.py \
  --exp-tag point_vb_bo_v1 \
  --modes point vb-non-fss-point vb-fss-point bo-non-fss-point bo-fss-point \
  --ands 1 2 4 8 \
  --reps 5 \
  --warmup-runs 1
```

Script outputs are created under `result/<timestamp>__<exp-tag>/` by default.

## Project Layout

- `client/` client runtime and test entrypoints
- `server/` query server runtime
- `network/` gRPC proto and network glue
- `secure-indices/` secure index structures
- `fss-core/` FSS/crypto dependencies and core primitives
- `config/` local run configs
- `scripts/` benchmark and utility scripts

## Limitations

- Rollup functionality mentioned in the paper is not fully implemented.
- This implementation is for experimentation and measurement, not hardened deployment.

## Acknowledgements

Thanks to Natacha Crooks and Vivian Fang for contributing to the framework used for benchmarking.

## License

This project is licensed under Apache License 2.0. See [LICENSE](LICENSE).

For attribution and third-party notices, see:

- [NOTICE](NOTICE)
- [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)
