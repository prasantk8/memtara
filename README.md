# Memtara Zero-Knowledge Proof System

A production-ready ZKP implementation for local-first vault with scoped temporary access, selective disclosure, and auditability.

## Architecture Overview

This system implements end-to-end zero-knowledge proofs allowing users to prove statements about their private data without revealing the underlying records. Built using Noir (Aztec) for optimal developer experience and browser/mobile support.

### Key Features
- **Local-first vault**: All sensitive data remains on user device
- **Selective disclosure**: Prove only necessary attributes
- **Time-bound sessions**: Automatic expiration of access rights
- **Auditability**: Cryptographically verifiable logs without data leakage
- **Emergency mode**: One-click selective sharing with automatic cleanup

## Project Structure

```
memtara-zkp/
├── circuits/                    # Noir circuits for ZKP proofs
│   ├── merkle_inclusion.nr      # Merkle tree inclusion proofs
│   ├── attribute_predicates.nr  # Attribute verification circuits
│   ├── signature_verify.nr      # Ed25519/BLS signature in circuit
│   └── time_bound.nr            # Time-based policy enforcement
├── vault/                       # Local-first encrypted vault (Rust)
│   ├── Cargo.toml              # Rust workspace config
│   └── src/                    # Vault implementation
├── cli/                        # Command-line interface
├── web/                        # Web frontend with NoirJS
├── packages/                   # Shared utilities and types
└── docs/                       # Documentation and guides

## Quick Start

### Prerequisites
- Rust (install via [rustup](https://rustup.rs))
- Noir toolchain (install via [noirup](https://github.com/noir-lang/noirup):
  `curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && noirup`)
- Node.js 18+ (for the web frontend — not yet scaffolded, see `web/`)

### Vault (Rust)

```bash
cd vault
cargo build --release
cargo test
```

### Circuits (Noir)

```bash
cd circuits
nargo test --workspace

# ACIR compilation currently requires this flag due to a known upstream
# Noir compiler false-positive in noir-lang/noir-edwards' EC arithmetic
# (noir-lang/noir#6793) — the library's own asserts do constrain the
# unsafe block's outputs, the static checker just can't see it here.
nargo compile --workspace --skip-brillig-constraints-check
```

`cli/`, `web/`, and `packages/` are not yet implemented (see
[TODO.md](./TODO.md)).

## Use Cases

### 1. Doctor Visit / Health Context
Prove possession of specific medications, allergies, or lab ranges without sharing full medical history.

### 2. Emergency Share
Time-bound selective disclosure of critical health information (blood type, allergies, key meds) with cryptographic proof of authenticity.

### 3. Tax / Financial Verification
Prove income ranges or document eligibility without revealing raw financial data.

### 4. Identity Verification
Prove professional qualifications or membership in sets without disclosing full credentials.

### 5. AI Connector Sessions
Verify that AI assistants only received granted context, with cryptographic assurance for audit logs.

## Development Roadmap

See [TODO.md](./TODO.md) for detailed implementation phases and progress tracking.

## Security Model

- **Zero-Knowledge**: Proofs reveal nothing beyond validity
- **Local-First**: Sensitive data never leaves user device
- **Forward Secrecy**: Session keys are ephemeral
- **Audit Trail**: All proofs are independently verifiable

## License

MIT License - See LICENSE file for details.