/// <reference path="./types/kms-sdk-shims.d.ts" />
import { Injectable, Logger } from '@nestjs/common';
import {
  KeyProvider,
  KeyProviderContext,
} from '../interfaces/encryption.interface';

/**
 * BYOK-021 / FR-01: GCP KMS key provider.
 *
 * Wraps/unwraps the per-organization encryption key via Google Cloud KMS
 * using the official `@google-cloud/kms` SDK. Mirrors the AwsKmsProvider
 * pattern so the two implementations stay structurally aligned and easy
 * to cross-reference during maintenance.
 *
 * Configuration:
 *   context.kmsConfig.provider = 'gcp'
 *   context.kmsConfig.key_id   = full GCP resource name
 *     e.g. projects/P/locations/L/keyRings/R/cryptoKeys/K
 *
 * Authentication: Application Default Credentials (ADC) via the
 * GOOGLE_APPLICATION_CREDENTIALS env var pointing to a service account
 * JSON file. No explicit credential passing — the SDK picks it up from
 * the environment. In CI, the file is materialized by the workflow from
 * the GCP_KMS_TEST_SA_JSON secret (BYOK-003).
 *
 * AAD: the organization ID is bound to the ciphertext via
 * `additionalAuthenticatedData`. This prevents a ciphertext from being
 * decrypted against a different organization context.
 */
@Injectable()
export class GcpKmsProvider implements KeyProvider {
  private readonly logger = new Logger(GcpKmsProvider.name);

  async wrap(orgKey: Buffer, context: KeyProviderContext): Promise<string> {
    if (!context.kmsConfig || context.kmsConfig.provider !== 'gcp') {
      throw new Error('GCP KMS config is required for GCP KMS provider');
    }

    const { KeyManagementServiceClient } = await import('@google-cloud/kms');
    const client = new KeyManagementServiceClient();

    let response: [{ ciphertext: Uint8Array | null }];
    try {
      response = await client.encrypt({
        name: context.kmsConfig.key_id,
        plaintext: orgKey,
        additionalAuthenticatedData: Buffer.from(context.organizationId),
      });
    } catch (err) {
      throw this.translateError(err, 'encrypt');
    }

    const ciphertext = response?.[0]?.ciphertext;
    if (!ciphertext) {
      throw new Error('GCP KMS encrypt returned empty ciphertext');
    }

    this.logger.log(
      `Wrapped key via GCP KMS for organization: ${context.organizationId}`,
    );

    return Buffer.from(ciphertext).toString('base64');
  }

  async unwrap(
    wrappedKey: string,
    context: KeyProviderContext,
  ): Promise<Buffer> {
    if (!context.kmsConfig || context.kmsConfig.provider !== 'gcp') {
      throw new Error('GCP KMS config is required for GCP KMS provider');
    }

    const { KeyManagementServiceClient } = await import('@google-cloud/kms');
    const client = new KeyManagementServiceClient();

    let response: [{ plaintext: Uint8Array | null }];
    try {
      response = await client.decrypt({
        name: context.kmsConfig.key_id,
        ciphertext: Buffer.from(wrappedKey, 'base64'),
        additionalAuthenticatedData: Buffer.from(context.organizationId),
      });
    } catch (err) {
      throw this.translateError(err, 'decrypt');
    }

    const plaintext = response?.[0]?.plaintext;
    if (!plaintext) {
      throw new Error('GCP KMS decrypt returned empty plaintext');
    }

    this.logger.log(
      `Unwrapped key via GCP KMS for organization: ${context.organizationId}`,
    );

    return Buffer.from(plaintext);
  }

  /**
   * Maps gRPC error codes from the GCP KMS SDK to stable human-readable
   * messages. The SDK throws errors whose `code` property matches gRPC
   * status codes — NOT_FOUND=5, PERMISSION_DENIED=7, UNAVAILABLE=14. We
   * also accept string variants (`NOT_FOUND`) since the SDK's runtime
   * shape has varied across versions.
   *
   * Credentials and raw error payloads are NEVER included in the returned
   * message to avoid leaking secrets into logs.
   */
  private translateError(err: unknown, op: 'encrypt' | 'decrypt'): Error {
    const code = (err as { code?: number | string } | null)?.code;

    if (code === 5 || code === 'NOT_FOUND') {
      return new Error(`GCP KMS key not found (on ${op})`);
    }
    if (code === 7 || code === 'PERMISSION_DENIED') {
      return new Error(`GCP KMS permission denied (on ${op})`);
    }
    if (code === 14 || code === 'UNAVAILABLE') {
      return new Error(`GCP KMS unavailable, retry later (on ${op})`);
    }

    const baseMessage =
      err instanceof Error ? err.message : 'unknown GCP KMS error';
    return new Error(`GCP KMS ${op} failed: ${baseMessage}`);
  }
}
