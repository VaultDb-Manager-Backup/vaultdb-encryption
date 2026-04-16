/**
 * BYOK-014: Restore-path key resolution helper.
 *
 * Extracted as a standalone utility so the version-aware lookup logic is
 * unit-testable in isolation from the worker's `RestoreExecutorService`
 * (which has many dependencies irrelevant to the key-resolution path).
 *
 * The helper encapsulates three concerns:
 *   1. Legacy fallback — backups without a `keyVersion` in metadata are
 *      decrypted with the current org key (no historical lookup).
 *   2. Version-aware lookup — backups with `keyVersion` go through
 *      `getOrganizationKey(orgId, version)` which consults `key_history`.
 *   3. Orphan detection — a `KeyVersionNotFoundError` from the history
 *      path is logged at error level and re-thrown as an actionable
 *      error that the restore flow surfaces to the user verbatim.
 */

import { EncryptedFileMetadata } from '../interfaces/encryption.interface';
import { KeyVersionNotFoundError } from '../errors/key-rotation.errors';

export interface KeyResolverKms {
  getOrganizationKey(orgId: string, version?: number): Promise<Buffer>;
}

export interface KeyResolverLogger {
  warn(message: string): void;
  error(message: string): void;
}

/**
 * Thrown by the restore flow when the backup's `keyVersion` is no longer
 * present in the organization's `key_history`. The caller should convert
 * this to a user-facing message that explains the situation and lists
 * the available versions from the cause's `availableVersions` array.
 */
export class RestoreKeyUnavailableError extends Error {
  public readonly organizationId: string;
  public readonly requestedVersion: number;
  public readonly availableVersions: number[];

  constructor(
    organizationId: string,
    requestedVersion: number,
    availableVersions: number[],
  ) {
    super(
      `Cannot restore this backup: encryption key version ${requestedVersion} ` +
        `has been removed from history (available: ${availableVersions.join(', ') || '(none)'}). ` +
        `Increase BYOK_KEY_HISTORY_RETENTION or contact support.`,
    );
    this.name = 'RestoreKeyUnavailableError';
    this.organizationId = organizationId;
    this.requestedVersion = requestedVersion;
    this.availableVersions = availableVersions;
  }
}

export async function resolveOrgKeyForRestore(
  organizationId: string,
  encryptionMetadata: EncryptedFileMetadata | undefined | null,
  kms: KeyResolverKms,
  logger: KeyResolverLogger,
): Promise<Buffer> {
  const keyVersion = encryptionMetadata?.keyVersion;

  if (keyVersion == null) {
    logger.warn(
      `[Restore] Backup has no keyVersion in metadata — falling back to current organization key (legacy backup path). org=${organizationId}`,
    );
    return kms.getOrganizationKey(organizationId);
  }

  try {
    return await kms.getOrganizationKey(organizationId, keyVersion);
  } catch (err) {
    if (err instanceof KeyVersionNotFoundError) {
      logger.error(
        `[Restore] Key version ${keyVersion} no longer available for org ${organizationId}. ` +
          `Available: ${err.availableVersions.join(', ') || '(none)'}. ` +
          `This backup cannot be restored — the encryption key version has been removed from history.`,
      );
      throw new RestoreKeyUnavailableError(
        organizationId,
        keyVersion,
        err.availableVersions,
      );
    }
    throw err;
  }
}
