# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this encryption module, please report it responsibly:

**Email:** security@vaultdb.com.br

Please do NOT open a public GitHub issue for security vulnerabilities.

We will:
- Acknowledge your report within 24 hours
- Provide an estimated timeline for a fix within 72 hours
- Credit you in the fix commit (unless you prefer anonymity)

## Scope

This repository covers the encryption layer of VaultDB:
- AES-256-GCM file encryption
- BYOK key management (DirectKeyProvider)
- Key derivation (PBKDF2)
- Key wrapping/unwrapping
- Cloud KMS integrations (AWS, GCP, Azure)

## Supported Versions

| Version | Supported |
|---|---|
| Latest on `main` | Yes |
| Older commits | Best-effort |
