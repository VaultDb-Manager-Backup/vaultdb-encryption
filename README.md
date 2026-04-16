# vaultdb-encryption

Public audit repository for [VaultDB](https://vaultdb.com.br) cryptographic modules.

This repo contains the **production source code** of the encryption layer used by VaultDB Cloud and the open-source agent. It is published separately so anyone can audit, fork, and compile the cryptographic components independently.

## Repository structure

```
libs/
├── encryption/          # Core encryption library
│   └── src/
│       ├── services/    # AES-256-GCM, key management, rotation, field encryption
│       ├── providers/   # BYOK (DirectKey), ManagedKey, AWS KMS, GCP KMS, Azure KV
│       ├── schemas/     # Mongoose schemas (OrganizationKey, KeyAlertHistory)
│       ├── interfaces/  # TypeScript contracts
│       ├── errors/      # Custom error types
│       └── utils/       # Restore key resolver, BYOK backfill
└── checksum/            # File integrity verification
    └── src/
        └── checksum.utils.ts
```

## Security claims — where to verify

| Claim | File | What to look for |
|---|---|---|
| AES-256-GCM only | `libs/encryption/src/services/encryption.service.ts` | `const ALGORITHM = 'aes-256-gcm'` — hardcoded |
| Random IV per file | `libs/encryption/src/services/encryption.service.ts` | `crypto.randomBytes(IV_LENGTH)` in `encryptFile` |
| Customer key never on disk | `libs/encryption/src/providers/direct-key.provider.ts` | `keyCache = new Map<string, Buffer>()` in RAM; no `fs.write` |
| Key length = 32 bytes | `libs/encryption/src/providers/direct-key.provider.ts` | `customerKeyHex.length !== 64` guard |
| PBKDF2 100k iterations | `libs/encryption/src/providers/direct-key.provider.ts` | `PBKDF2_ITERATIONS = 100_000` |
| Auth tag verified on decrypt | `libs/encryption/src/services/encryption.service.ts` | `decipher.setAuthTag(authTag)` |

## Modules

### `libs/encryption`

The core library. Contains:

- **EncryptionService** — AES-256-GCM file encryption with streaming (plaintext never hits disk as a separate file), string encryption for field-level use.
- **DirectKeyProvider (BYOK)** — customer-supplied key, cached in RAM, PBKDF2-derived KEK wraps the per-org key. The wrapped key is the only thing VaultDB Cloud stores.
- **ManagedKeyProvider** — platform-managed fallback when BYOK is not enabled.
- **AWS/GCP/Azure KMS providers** — delegate key wrapping to cloud HSMs.
- **KeyManagementService** — orchestrates key creation, caching, and provider selection.
- **KeyRotationService** — zero-downtime rotation; old key stays valid for existing backups.
- **KeyExpirationMonitorService** — alerts when keys approach expiration.
- **FieldEncryptionService** — encrypts/decrypts individual document fields at rest.

### `libs/checksum`

SHA-256 file checksums used to verify backup integrity after encryption and transfer.

## Running tests

```bash
# From the repo root
npm install
npx jest --no-cache
```

Tests cover every provider, every service, key rotation edge cases, and schema validation.

## Relationship to the VaultDB product

This module is extracted from the [VaultDB monorepo](https://vaultdb.com.br). The full product (API, worker, site, admin, agent) is proprietary. Only the cryptographic layer is published here for transparency.

The module is kept in sync with production. When VaultDB ships a new encryption feature or fix, this repo is updated.

## Vulnerability disclosure

Email **security@vaultdb.com.br** — we respond within 24 hours. Do not open public issues for security vulnerabilities.

## License

[MIT](LICENSE)
