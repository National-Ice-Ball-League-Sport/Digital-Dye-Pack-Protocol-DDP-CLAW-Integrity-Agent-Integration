# Digital Dye Pack Protocol + CLAW Integrity Agent — C++ prototype

A small C++20 reference implementation of transaction watermarking and a tamper-evident audit trail. It is a local prototype for integrity controls; it does not connect to a bank, move money, provide financial advice, or replace production approval systems.

## What it does

- Creates a stable transaction watermark using HMAC-SHA-256 over a transaction ID and integer amount in minor currency units.
- Writes append-only TSV events linked by SHA-256 hashes, and verifies sequence, links, event hashes, and watermark authentication.
- Implements a CLAW-style policy gate that records `allow`, `review_required`, or `reject` decisions. The default CLI review threshold is 100,000,000 minor units (for cents, 1,000,000.00).
- Rejects duplicate submitted transaction IDs and encodes free-text fields as hex so tabs/newlines cannot alter ledger structure.

The ledger is integrity-evident, not a fully immutable datastore: an attacker able to replace the entire file and obtain the HMAC key can rewrite it. Production use requires independent checkpoint anchoring, protected key management, authorization, durable storage, monitoring, privacy controls, and a separately enforced approval/execution system. This initial implementation is single-writer and does not provide concurrency locking.

## Build

Requirements: CMake 3.16+, a C++20 compiler, and OpenSSL development libraries.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Run

Set a secret key of at least 16 bytes through the environment. For production, use a managed secret store rather than a shell history or checked-in configuration.

```sh
export DDP_WATERMARK_KEY='replace-with-a-secret-of-at-least-16-bytes'
./build/ddp demo ./ledger.tsv
./build/ddp verify ./ledger.tsv
./build/ddp submit ./ledger.tsv txn-100 advisor-7 advisory.transfer 125000
```

Amounts are signed 64-bit integer minor units: `125000` means 1,250.00 if the currency has two decimal places. The prototype does not infer a currency; deployments must define currency and rounding semantics explicitly. CLI arguments should not contain secrets.

A successful `submit` records three events: `transaction.submitted`, the requested action, and a `claw.decision.*` result. The decision is a logged policy outcome, not a payment authorization. Non-positive amounts are recorded and rejected; amounts at or above the threshold are flagged for review.

## Ledger format

Each UTF-8/ASCII-compatible TSV row stores sequence, Unix timestamp in milliseconds, hex-encoded transaction ID/actor/action, amount-minor, HMAC watermark, previous event hash, and current event hash. Do not edit or truncate a ledger by hand. Keep key backups and ledger backups governed separately.
