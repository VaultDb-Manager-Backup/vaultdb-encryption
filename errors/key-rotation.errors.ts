/**
 * Errors raised by the BYOK two-phase rotation flow (BYOK-011, BYOK-012).
 *
 * Each error carries enough context for callers to decide whether to retry
 * (transient) or bail (permanent). Validation failures are always permanent
 * for the current candidate key — the cron loop (BYOK-051) uses this
 * distinction to avoid retrying doomed rotations inside the same run.
 */

export class KeyRotationValidationError extends Error {
  public readonly organizationId: string;
  public readonly reason: string;

  constructor(organizationId: string, reason: string) {
    super(
      `Key rotation validation failed for organization ${organizationId}: ${reason}`,
    );
    this.name = 'KeyRotationValidationError';
    this.organizationId = organizationId;
    this.reason = reason;
  }
}

export class KeyRotationDatabaseError extends Error {
  public readonly organizationId: string;
  public readonly cause?: unknown;

  constructor(organizationId: string, cause?: unknown) {
    const message =
      cause instanceof Error ? cause.message : String(cause ?? 'unknown');
    super(
      `Key rotation database update failed for organization ${organizationId}: ${message}`,
    );
    this.name = 'KeyRotationDatabaseError';
    this.organizationId = organizationId;
    this.cause = cause;
  }
}

/**
 * Thrown by registerByokKey (BYOK-032) when the post-registration pipeline
 * validation fails. The created OrganizationKey document has already been
 * rolled back by the time this error escapes the service — callers should
 * surface the message to the user and ask them to verify their KMS
 * credentials or customer key.
 */
export class ByokRegistrationValidationError extends Error {
  public readonly organizationId: string;
  public readonly reason: string;

  constructor(organizationId: string, reason: string) {
    super(
      `BYOK registration validation failed for organization ${organizationId}: ${reason}. ` +
        `The encryption key was not activated — verify your KMS credentials or customer key and try again.`,
    );
    this.name = 'ByokRegistrationValidationError';
    this.organizationId = organizationId;
    this.reason = reason;
  }
}

/**
 * Thrown by getOrganizationKey(orgId, version) when the requested version
 * is neither the current key nor present in key_history. Carries the
 * requested version and the set of available versions so callers can
 * produce actionable error messages.
 *
 * Most commonly seen during restore of very old backups that were encrypted
 * with a key version that has since been trimmed from history retention.
 * See BYOK-014 (RestoreService integration) for the user-facing path.
 */
export class KeyVersionNotFoundError extends Error {
  public readonly organizationId: string;
  public readonly requestedVersion: number;
  public readonly availableVersions: number[];

  constructor(
    organizationId: string,
    requestedVersion: number,
    availableVersions: number[],
  ) {
    super(
      `Key version ${requestedVersion} not found for organization ${organizationId}. ` +
        `Available versions: ${availableVersions.join(', ') || '(none)'}`,
    );
    this.name = 'KeyVersionNotFoundError';
    this.organizationId = organizationId;
    this.requestedVersion = requestedVersion;
    this.availableVersions = availableVersions;
  }
}
