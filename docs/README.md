# KalqiX Signature POC — Documentation

Proof-of-concept for ZK signature verification in SP1, profiling cycle
costs to determine the optimal batch strategy for kalqix-zk-service.

## Documents

| Document | Purpose |
|----------|---------|
| [Architecture](architecture.md) | Guest program structure, witness types, ProgramInput dispatch |
| [JMT Integration](jmt-integration.md) | Jellyfish Merkle Tree fork, Poseidon2Hasher, proof types |
| [Optimization Journey](optimizations.md) | Progression from naive to flat+rkyv with benchmark data |
| [Wire Format](wire-format.md) | Borsh vs rkyv serialization, two-chunk stdin pattern |
| [Production Migration](production-migration.md) | Mapping POC patterns to kalqix-zk-service |
| [Profiling Guide](profiling-guide.md) | All CLI benchmark modes, how to run, how to interpret |

## Key Result

At 200 unique keys / 6000 orders (production-shaped workload):

| Mode | Deserialize | Merkle | Schnorr | Bind | Total |
|------|----------:|-------:|--------:|-----:|------:|
| **FlatBatch + rkyv** | 342 | 8.4M | 4.7M | 0.5M | **13.7M** |
| BatchExistence + rkyv | 342 | 12.0M | 4.7M | 0.5M | 17.2M |
| BatchExistence + borsh | ~18M | 12.0M | 4.5M | 0.5M | 35.3M |

The recommended production path is **FlatBatchExistenceProof + rkyv zero-copy**,
yielding a 2.6x reduction over borsh and 20% over rkyv-only.
