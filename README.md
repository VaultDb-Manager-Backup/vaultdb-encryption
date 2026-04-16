# vaultdb-encryption

Public audit module for [VaultDB](https://vaultdb.com.br) — the database backup service with BYOK (Bring Your Own Key) encryption.

This repository contains the **complete encryption module** extracted from the VaultDB codebase. It is published separately so anyone can audit, fork and compile the cryptographic layer independently, without needing access to the full product.

## What this module does

- **AES-256-GCM file encryption** with random IV per file and authentication tags (`services/encryption.service.ts`)
- **BYOK key management** — customer keys are cached in RAM only, never persisted (`providers/direct-key.provider.ts`)
- **Key derivation** via PBKDF2 (100,000 iterations, SHA-512) (`providers/direct-key.provider.ts`)
- **Key wrapping** — per-organization keys are wrapped with the customer's key before storage (`providers/direct-key.provider.ts`)
- **Key rotation** with zero-downtime — old keys remain valid for existing backups (`services/key-rotation.service.ts`)
- **Key expiration monitoring** with configurable alerts (`services/key-expiration-monitor.service.ts`)
- **Field-level encryption** for sensitive database fields (`services/field-encryption.service.ts`)
- **Cloud KMS providers** for AWS KMS, GCP KMS and Azure Key Vault (`providers/aws-kms.provider.ts`, `providers/gcp-kms.provider.ts`, `providers/azure-kms.provider.ts`)
- **Managed key provider** for platform-managed encryption when BYOK is not enabled (`providers/managed-key.provider.ts`)

## Key security claims (and how to verify them)

| Claim | File to audit | What to look for |
|---|---|---|
| AES-256-GCM is the only algorithm | `services/encryption.service.ts` | `const ALGORITHM = 'aes-256-gcm'` — hardcoded, not configurable |
| IV is random per file | `services/encryption.service.ts` | `crypto.randomBytes(IV_LENGTH)` called in `encryptFile` |
| Customer key never touches disk | `providers/direct-key.provider.ts` | `keyCache` is a `Map<string, Buffer>` in RAM; no `fs.write` anywhere |
| Key length enforced at 32 bytes | `providers/direct-key.provider.ts` | `customerKeyHex.length !== 64` check in `cacheCustomerKey` |
| PBKDF2 iterations are high enough | `providers/direct-key.provider.ts` | `PBKDF2_ITERATIONS = 100_000` |

## Directory structure

```
.
├── encryption.module.ts        # NestJS module wiring
├── index.ts                    # Public API barrel
├── interfaces/
│   └── encryption.interface.ts # Types and contracts
├── providers/
│   ├── direct-key.provider.ts  # BYOK — the main audit target
│   ├── managed-key.provider.ts # Platform-managed key (fallback)
│   ├── aws-kms.provider.ts     # AWS KMS integration
│   ├── gcp-kms.provider.ts     # GCP Cloud KMS integration
│   ├── azure-kms.provider.ts   # Azure Key Vault integration
│   └── *.spec.ts               # Unit tests for each provider
├── services/
│   ├── encryption.service.ts   # Core AES-256-GCM file encryption
│   ├── key-management.service.ts
│   ├── key-rotation.service.ts
│   ├── key-expiration-monitor.service.ts
│   ├── field-encryption.service.ts
│   ├── cron-metric.util.ts
│   └── *.spec.ts               # Unit tests
├── schemas/                    # Mongoose schemas for key storage
├── errors/                     # Custom error types
└── utils/                      # Restore key resolver, BYOK backfill
```

## Running the tests

```bash
# Install dependencies (this module is part of a NestJS monorepo)
npm install

# Run all encryption tests
npx jest --testPathPattern='(encryption|direct-key|managed-key|key-rotation|key-management|field-encryption|key-expiration)' --no-cache
```

## Found a vulnerability?

Email **security@vaultdb.com.br** — we take every report seriously and respond within 24 hours. Please do not open a public issue for security vulnerabilities.

## License

[MIT](LICENSE)

---

This module is extracted from the [VaultDB](https://vaultdb.com.br) monorepo. The full product (API, worker, UI, agent) is proprietary; this encryption layer is published for transparency and independent audit.
