/// <reference path="./types/kms-sdk-shims.d.ts" />
import { Injectable, Logger } from '@nestjs/common';
import {
  KeyProvider,
  KeyProviderContext,
} from '../interfaces/encryption.interface';

/**
 * BYOK-023 / FR-02: Azure Key Vault key provider.
 *
 * Wraps/unwraps the per-organization encryption key via Azure Key Vault
 * using RSA-OAEP through the `@azure/keyvault-keys` `CryptographyClient`.
 * Mirrors the AwsKmsProvider / GcpKmsProvider pattern.
 *
 * Configuration:
 *   context.kmsConfig.provider = 'azure'
 *   context.kmsConfig.key_id   = full Key Vault key URI
 *     e.g. https://<vault>.vault.azure.net/keys/<name>/<version?>
 *
 * Authentication: `DefaultAzureCredential` chain. In the worker container,
 * credentials populate from env vars AZURE_TENANT_ID, AZURE_CLIENT_ID, and
 * AZURE_CLIENT_SECRET (set by BYOK-003 CI workflow). In managed-identity
 * environments the chain resolves those automatically — no code change.
 *
 * Algorithm: RSA-OAEP is hardcoded. The test key provisioned in BYOK-002
 * is RSA 2048 and all production deployments are expected to use RSA keys
 * to match. Changing the algorithm requires coordinated migration of
 * existing wrapped keys, which is out of scope for this spec.
 *
 * Note on AAD: Azure Key Vault's wrap/unwrap primitives do NOT support
 * additional authenticated data (unlike AWS KMS EncryptionContext or GCP
 * KMS additionalAuthenticatedData). The organization ID binding instead
 * comes from the `kms_config.key_id` itself — each organization should
 * provision its own dedicated Key Vault key, and the stored key_id in the
 * database record serves as the binding.
 */
@Injectable()
export class AzureKeyVaultProvider implements KeyProvider {
  private readonly logger = new Logger(AzureKeyVaultProvider.name);

  async wrap(orgKey: Buffer, context: KeyProviderContext): Promise<string> {
    if (!context.kmsConfig || context.kmsConfig.provider !== 'azure') {
      throw new Error(
        'Azure Key Vault config is required for Azure KMS provider',
      );
    }

    const client = await this.createCryptographyClient(
      context.kmsConfig.key_id,
    );

    let response: { result: Uint8Array; algorithm: string };
    try {
      response = await client.wrapKey('RSA-OAEP', orgKey);
    } catch (err) {
      throw this.translateError(err, 'wrap');
    }

    if (!response?.result) {
      throw new Error('Azure Key Vault wrap returned empty result');
    }

    this.logger.log(
      `Wrapped key via Azure Key Vault for organization: ${context.organizationId}`,
    );

    return Buffer.from(response.result).toString('base64');
  }

  async unwrap(
    wrappedKey: string,
    context: KeyProviderContext,
  ): Promise<Buffer> {
    if (!context.kmsConfig || context.kmsConfig.provider !== 'azure') {
      throw new Error(
        'Azure Key Vault config is required for Azure KMS provider',
      );
    }

    const client = await this.createCryptographyClient(
      context.kmsConfig.key_id,
    );

    let response: { result: Uint8Array; algorithm: string };
    try {
      response = await client.unwrapKey(
        'RSA-OAEP',
        Buffer.from(wrappedKey, 'base64'),
      );
    } catch (err) {
      throw this.translateError(err, 'unwrap');
    }

    if (!response?.result) {
      throw new Error('Azure Key Vault unwrap returned empty result');
    }

    this.logger.log(
      `Unwrapped key via Azure Key Vault for organization: ${context.organizationId}`,
    );

    return Buffer.from(response.result);
  }

  /**
   * Dynamic SDK import + client construction. Extracted as a helper so
   * the two call sites share it and tests can spy on construction if
   * they need to.
   */
  private async createCryptographyClient(keyUri: string): Promise<{
    wrapKey(
      algorithm: 'RSA-OAEP',
      key: Buffer,
    ): Promise<{ result: Uint8Array; algorithm: string }>;
    unwrapKey(
      algorithm: 'RSA-OAEP',
      encryptedKey: Buffer,
    ): Promise<{ result: Uint8Array; algorithm: string }>;
  }> {
    const { CryptographyClient } = await import('@azure/keyvault-keys');
    const { DefaultAzureCredential } = await import('@azure/identity');
    return new CryptographyClient(keyUri, new DefaultAzureCredential());
  }

  /**
   * Maps Azure SDK errors to stable human-readable messages. Azure errors
   * expose a `statusCode` (HTTP-like) and a `code` string (e.g. 'Forbidden',
   * 'KeyNotFound'). We map the two most actionable classes and fall through
   * to a generic message for everything else.
   */
  private translateError(err: unknown, op: 'wrap' | 'unwrap'): Error {
    const statusCode = (err as { statusCode?: number } | null)?.statusCode;
    const code = (err as { code?: string } | null)?.code;

    if (statusCode === 403 || code === 'Forbidden' || code === 'AccessDenied') {
      return new Error(`Azure Key Vault access denied (on ${op})`);
    }
    if (statusCode === 404 || code === 'KeyNotFound' || code === 'NotFound') {
      return new Error(`Azure Key Vault key not found (on ${op})`);
    }
    if (statusCode && statusCode >= 500) {
      return new Error(`Azure Key Vault unavailable, retry later (on ${op})`);
    }

    const baseMessage =
      err instanceof Error ? err.message : 'unknown Azure Key Vault error';
    return new Error(`Azure Key Vault ${op} failed: ${baseMessage}`);
  }
}
