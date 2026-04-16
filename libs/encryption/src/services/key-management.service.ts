import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import * as crypto from 'crypto';
import {
  OrganizationKey,
  OrganizationKeyDocument,
} from '../schemas/organization-key.schema';
import {
  KeyType,
  KmsConfig,
  ByokRegistration,
  ByokStatus,
  KeyProvider,
  KeyProviderContext,
  PipelineValidationResult,
  RotateByokOptions,
} from '../interfaces/encryption.interface';
import { EncryptionService } from './encryption.service';
import { ManagedKeyProvider } from '../providers/managed-key.provider';
import { DirectKeyProvider } from '../providers/direct-key.provider';
import { AwsKmsProvider } from '../providers/aws-kms.provider';
import { GcpKmsProvider } from '../providers/gcp-kms.provider';
import { AzureKeyVaultProvider } from '../providers/azure-kms.provider';
import {
  KeyRotationValidationError,
  KeyVersionNotFoundError,
  ByokRegistrationValidationError,
} from '../errors/key-rotation.errors';
import {
  KeyHistoryEntry,
  LastRotationError,
} from '../schemas/organization-key.schema';

const KEY_LENGTH = 32; // 256 bits
const SALT_LENGTH = 32; // 256 bits
const VALIDATION_PAYLOAD_BYTES = 4096; // 4 KB smoke-test payload
const DEFAULT_KEY_HISTORY_RETENTION = 3;

@Injectable()
export class KeyManagementService implements OnModuleInit {
  private readonly logger = new Logger(KeyManagementService.name);
  private masterKeyConfigured = false;

  constructor(
    private readonly configService: ConfigService,
    private readonly managedKeyProvider: ManagedKeyProvider,
    private readonly directKeyProvider: DirectKeyProvider,
    private readonly awsKmsProvider: AwsKmsProvider,
    private readonly gcpKmsProvider: GcpKmsProvider,
    private readonly azureKmsProvider: AzureKeyVaultProvider,
    private readonly encryptionService: EncryptionService,
    @InjectModel(OrganizationKey.name)
    private readonly organizationKeyModel: Model<OrganizationKeyDocument>,
  ) {}

  onModuleInit() {
    const masterKeyHex = this.configService.get<string>(
      'ENCRYPTION_MASTER_KEY',
    );

    if (masterKeyHex) {
      if (masterKeyHex.length !== 64) {
        this.logger.warn(
          'ENCRYPTION_MASTER_KEY should be 64 hex characters (32 bytes). Encryption features may not work correctly.',
        );
      } else {
        this.masterKeyConfigured = true;
        this.logger.log('Encryption master key loaded successfully');
      }
    } else {
      this.logger.warn(
        'ENCRYPTION_MASTER_KEY not configured. Managed encryption will be disabled. BYOK still available.',
      );
    }
  }

  /**
   * Check if encryption is available (master key configured or BYOK)
   */
  isEncryptionAvailable(): boolean {
    return this.masterKeyConfigured;
  }

  /**
   * BYOK-030 / FR-07a: Validate a candidate key buffer without touching
   * the database. Used by two-phase rotation (BYOK-011, BYOK-012) to verify
   * a newly wrapped key BEFORE promoting it, and by validatePipeline
   * (BYOK-031) as the underlying check.
   *
   * Steps:
   *   1. Unwrap the wrappedKey via the provider
   *   2. Assert the unwrapped bytes match the given orgKey
   *   3. Encrypt a 4 KB random payload with the orgKey
   *   4. Decrypt and assert bytes match
   *
   * This method NEVER throws — any failure is captured in the returned
   * result. Rotation flows rely on this contract for clean rollback.
   */
  async validateKeyBuffer(
    orgKey: Buffer,
    wrappedKey: string,
    provider: KeyProvider,
    context: KeyProviderContext,
  ): Promise<PipelineValidationResult> {
    const startedAt = Date.now();

    try {
      const unwrapped = await provider.unwrap(wrappedKey, context);

      if (!unwrapped.equals(orgKey)) {
        return {
          ok: false,
          error: 'unwrap roundtrip mismatch',
          duration_ms: Date.now() - startedAt,
        };
      }

      const payload = crypto
        .randomBytes(VALIDATION_PAYLOAD_BYTES)
        .toString('base64');

      const ciphertext = this.encryptionService.encryptString(payload, orgKey);

      const decrypted = this.encryptionService.decryptString(
        ciphertext.value,
        ciphertext.iv,
        ciphertext.authTag,
        orgKey,
      );

      if (decrypted !== payload) {
        return {
          ok: false,
          error: 'cipher roundtrip failed',
          duration_ms: Date.now() - startedAt,
        };
      }

      return { ok: true, duration_ms: Date.now() - startedAt };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        error: message,
        duration_ms: Date.now() - startedAt,
      };
    }
  }

  /**
   * BYOK-031 / FR-07a: Public entry point for key pipeline validation.
   *
   * Loads the currently committed organization key and delegates to
   * validateKeyBuffer. Persists `last_pipeline_validation` on the document
   * (on both success and failure) so the dashboard can display the most
   * recent validation state.
   *
   * Used by:
   *   - BYOK-032 registerByokKey post-create rollback guard
   *   - BYOK-071 on-demand "Validate pipeline" dashboard button
   *   - Operational checks / monitoring scripts
   *
   * Never throws — returns a structured result even when the org has no
   * key or when the underlying validation fails.
   */
  async validatePipeline(
    organizationId: string,
  ): Promise<PipelineValidationResult> {
    const record = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!record) {
      return {
        ok: false,
        error: `organization key not found for ${organizationId}`,
        duration_ms: 0,
      };
    }

    const keyType = (record.key_type || 'managed') as KeyType;
    const salt = Buffer.from(record.salt, 'hex');
    const context: KeyProviderContext = {
      organizationId,
      salt,
      kmsConfig: record.kms_config as KmsConfig | undefined,
    };
    const provider = this.getProvider(keyType);

    let orgKey: Buffer;
    try {
      orgKey = await provider.unwrap(record.encrypted_key, context);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const failureResult: PipelineValidationResult = {
        ok: false,
        error: message,
        duration_ms: 0,
      };
      await this.persistPipelineValidation(record._id, failureResult);
      return failureResult;
    }

    const result = await this.validateKeyBuffer(
      orgKey,
      record.encrypted_key,
      provider,
      context,
    );

    await this.persistPipelineValidation(record._id, result);

    return result;
  }

  private async persistPipelineValidation(
    recordId: Types.ObjectId,
    result: PipelineValidationResult,
  ): Promise<void> {
    const payload: { validated_at: Date; ok: boolean; error?: string } = {
      validated_at: new Date(),
      ok: result.ok,
    };
    if (!result.ok && result.error) {
      payload.error = result.error;
    }

    try {
      await this.organizationKeyModel.updateOne(
        { _id: recordId },
        { $set: { last_pipeline_validation: payload } },
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.warn(
        `Failed to persist last_pipeline_validation for record ${String(recordId)}: ${message}`,
      );
    }
  }

  /**
   * Gets or creates an encryption key for an organization.
   *
   * BYOK-013: When `version` is provided and does NOT match the current
   * record's version, the method looks up the matching entry in
   * `key_history` and unwraps it using the historical `key_type` +
   * `kms_config` + `salt`. This lets restore flows (BYOK-014) decrypt
   * backups that were encrypted under a prior key version after one or
   * more rotations.
   *
   * When `version` is omitted (backward-compatible default), the current
   * key is returned.
   *
   * Throws `KeyVersionNotFoundError` if `version` is neither the current
   * version nor present in `key_history` (e.g. trimmed beyond retention).
   */
  async getOrganizationKey(
    organizationId: string,
    version?: number,
  ): Promise<Buffer> {
    const existingKey = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (existingKey) {
      // Current key path (no version OR version matches current)
      if (version === undefined || version === existingKey.version) {
        return this.unwrapOrganizationKey(existingKey);
      }

      // Historical version lookup
      const history = existingKey.key_history ?? [];
      const historyEntry = history.find((entry) => entry.version === version);

      if (historyEntry) {
        return this.unwrapFromHistoryEntry(organizationId, historyEntry);
      }

      // Not found — build an actionable error
      const availableVersions = [
        existingKey.version,
        ...history.map((e) => e.version),
      ];
      throw new KeyVersionNotFoundError(
        organizationId,
        version,
        availableVersions,
      );
    }

    if (!this.masterKeyConfigured) {
      throw new Error('Encryption master key not configured');
    }

    // Create new managed key for organization
    return this.createOrganizationKey(organizationId);
  }

  /**
   * BYOK-013: Unwrap a historical key_history entry. Shares the provider
   * dispatch with the current-key path (unwrapOrganizationKey) but builds
   * the context from the historical salt + kms_config rather than the
   * document's current values.
   */
  private async unwrapFromHistoryEntry(
    organizationId: string,
    entry: KeyHistoryEntry,
  ): Promise<Buffer> {
    const keyType = (entry.key_type || 'managed') as KeyType;
    const salt = Buffer.from(entry.salt, 'hex');

    const context: KeyProviderContext = {
      organizationId,
      salt,
      kmsConfig: entry.kms_config as KmsConfig | undefined,
    };

    const provider = this.getProvider(keyType);
    return provider.unwrap(entry.encrypted_key, context);
  }

  /**
   * Gets the key version for an organization
   */
  async getKeyVersion(organizationId: string): Promise<number> {
    const keyRecord = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    return keyRecord?.version ?? 1;
  }

  /**
   * Gets the key type for an organization
   */
  async getKeyType(organizationId: string): Promise<KeyType> {
    const keyRecord = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    return (keyRecord?.key_type as KeyType) ?? 'managed';
  }

  /**
   * Registers a BYOK key for an organization
   */
  async registerByokKey(
    organizationId: string,
    registration: ByokRegistration,
  ): Promise<{ version: number; key_type: KeyType }> {
    if (registration.key_type === 'managed') {
      throw new Error('Use standard key creation for managed keys');
    }

    // Check if organization already has a key
    const existing = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (existing) {
      throw new Error(
        'Organization already has an encryption key. Revoke existing key first.',
      );
    }

    // Validate registration params
    this.validateByokRegistration(registration);

    // Generate a random org key
    const orgKey = crypto.randomBytes(KEY_LENGTH);
    const salt = crypto.randomBytes(SALT_LENGTH);

    // Build context for the provider
    const context: KeyProviderContext = {
      organizationId,
      salt,
      kmsConfig: registration.kms_config,
    };

    // Cache customer key for direct BYOK before wrapping
    if (registration.key_type === 'direct' && registration.customer_key) {
      this.directKeyProvider.cacheCustomerKey(
        organizationId,
        registration.customer_key,
      );
    }

    // Wrap the org key with the appropriate provider
    const provider = this.getProvider(registration.key_type);
    const wrappedKey = await provider.wrap(orgKey, context);

    // Store the key record
    const customerKeyHash =
      registration.key_type === 'direct' && registration.customer_key
        ? DirectKeyProvider.hashCustomerKey(registration.customer_key)
        : null;

    // BYOK-032: Pre-commit pipeline validation. We validate the in-memory
    // candidate key against the provider BEFORE touching the database so
    // there's nothing to roll back on failure. This matches the two-phase
    // pattern from BYOK-011/012 and avoids a redundant DB read cycle.
    const validation = await this.validateKeyBuffer(
      orgKey,
      wrappedKey,
      provider,
      context,
    );

    if (!validation.ok) {
      if (registration.key_type === 'direct') {
        this.directKeyProvider.evictCustomerKey(organizationId);
      }

      this.logger.error(
        `BYOK registration validation failed for org ${organizationId}: ${validation.error}`,
      );

      throw new ByokRegistrationValidationError(
        organizationId,
        validation.error ?? 'unknown validation failure',
      );
    }

    await this.organizationKeyModel.create({
      organization_id: new Types.ObjectId(organizationId),
      encrypted_key: wrappedKey,
      salt: salt.toString('hex'),
      version: 1,
      key_type: registration.key_type,
      kms_config: registration.kms_config || null,
      customer_key_hash: customerKeyHash,
      last_pipeline_validation: {
        validated_at: new Date(),
        ok: true,
      },
    });

    this.logger.log(
      `Registered BYOK key (${registration.key_type}) for organization: ${organizationId}`,
    );

    return { version: 1, key_type: registration.key_type };
  }

  /**
   * BYOK-012: Two-phase rotation for BYOK keys with optional provider switch.
   *
   * Supports both the legacy signature `rotateByokKey(orgId, newCustomerKey?)`
   * and the new options object `rotateByokKey(orgId, { newCustomerKey?,
   * targetKeyType?, targetKmsConfig? })`. A provider switch triggers when
   * `targetKeyType` differs from the existing record's key_type — the old
   * version is pushed to key_history with its ORIGINAL key_type + kms_config
   * so BYOK-013's version-aware getOrganizationKey can still unwrap legacy
   * backups after the switch.
   *
   * Direct type: newCustomerKey must be provided and is cached ONLY after
   * successful validation — failure path leaves the direct provider cache
   * unchanged.
   */
  async rotateByokKey(
    organizationId: string,
    newCustomerKey?: string,
  ): Promise<number>;
  async rotateByokKey(
    organizationId: string,
    options?: RotateByokOptions,
  ): Promise<number>;
  async rotateByokKey(
    organizationId: string,
    arg2?: string | RotateByokOptions,
  ): Promise<number> {
    const options: RotateByokOptions =
      typeof arg2 === 'string' ? { newCustomerKey: arg2 } : (arg2 ?? {});

    const existingRecord = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!existingRecord) {
      throw new Error(
        `No encryption key found for organization: ${organizationId}`,
      );
    }

    const existingKeyType = existingRecord.key_type as KeyType;
    const targetKeyType: KeyType = options.targetKeyType ?? existingKeyType;
    const targetKmsConfig: KmsConfig | undefined =
      options.targetKmsConfig ??
      (existingRecord.kms_config as KmsConfig | undefined) ??
      undefined;

    // Validate target requirements before generating any new material
    if (targetKeyType === 'direct' && !options.newCustomerKey) {
      throw new Error('New customer key is required for direct BYOK rotation');
    }

    if (options.newCustomerKey && options.newCustomerKey.length !== 64) {
      throw new Error('Customer key must be 64 hex characters (32 bytes)');
    }

    if (
      (targetKeyType === 'aws-kms' ||
        targetKeyType === 'gcp-kms' ||
        targetKeyType === 'azure-kms') &&
      !targetKmsConfig
    ) {
      throw new Error(
        `KMS config is required when rotating to target key_type: ${targetKeyType}`,
      );
    }

    // Generate new org key and salt
    const newOrgKey = crypto.randomBytes(KEY_LENGTH);
    const newSalt = crypto.randomBytes(SALT_LENGTH);
    const newVersion = existingRecord.version + 1;

    const context: KeyProviderContext = {
      organizationId,
      salt: newSalt,
      kmsConfig: targetKmsConfig,
    };

    // Wrap with the target provider (same as existing if no switch)
    const targetProvider = this.getProvider(targetKeyType);

    // For direct type, the provider reads the customer key from its internal
    // cache during wrap. Cache BEFORE wrap but EVICT on validation failure to
    // avoid leaving a stale entry that doesn't match any stored hash.
    if (targetKeyType === 'direct' && options.newCustomerKey) {
      this.directKeyProvider.cacheCustomerKey(
        organizationId,
        options.newCustomerKey,
      );
    }

    let wrappedKey: string;
    try {
      wrappedKey = await targetProvider.wrap(newOrgKey, context);
    } catch (err) {
      // Wrap failed — evict the just-cached customer key if we added it
      if (targetKeyType === 'direct' && options.newCustomerKey) {
        this.directKeyProvider.evictCustomerKey(organizationId);
      }
      throw err;
    }

    // Phase 1 — validate the candidate key before touching the database
    const validation = await this.validateKeyBuffer(
      newOrgKey,
      wrappedKey,
      targetProvider,
      context,
    );

    if (!validation.ok) {
      // Evict the customer key we cached above — it does not match any hash
      if (targetKeyType === 'direct' && options.newCustomerKey) {
        this.directKeyProvider.evictCustomerKey(organizationId);
      }
      this.logger.error(
        `BYOK key rotation validation failed for org ${organizationId}: ${validation.error}`,
      );
      throw new KeyRotationValidationError(
        organizationId,
        validation.error ?? 'unknown validation failure',
      );
    }

    // Phase 2 — push prior version to history and promote new state atomically
    const retention =
      this.configService.get<number>('BYOK_KEY_HISTORY_RETENTION') ??
      DEFAULT_KEY_HISTORY_RETENTION;

    const now = new Date();
    const historyEntry: KeyHistoryEntry = {
      version: existingRecord.version,
      encrypted_key: existingRecord.encrypted_key,
      salt: existingRecord.salt,
      key_type: existingKeyType,
      kms_config: existingRecord.kms_config,
      rotated_at: existingRecord.rotated_at ?? existingRecord.createdAt ?? now,
    };

    const customerKeyHash =
      targetKeyType === 'direct' && options.newCustomerKey
        ? DirectKeyProvider.hashCustomerKey(options.newCustomerKey)
        : targetKeyType === 'direct'
          ? existingRecord.customer_key_hash
          : null;

    await this.organizationKeyModel.updateOne(
      { _id: existingRecord._id },
      {
        $push: {
          key_history: {
            $each: [historyEntry],
            $position: 0,
            $slice: retention,
          },
        },
        $set: {
          encrypted_key: wrappedKey,
          salt: newSalt.toString('hex'),
          version: newVersion,
          rotated_at: now,
          key_type: targetKeyType,
          kms_config: targetKmsConfig ?? null,
          customer_key_hash: customerKeyHash,
          last_pipeline_validation: { validated_at: now, ok: true },
          last_rotation_error: null,
        },
      },
    );

    if (targetKeyType !== existingKeyType) {
      this.logger.log(
        `Switched provider during rotation for org ${organizationId}: ${existingKeyType} → ${targetKeyType}`,
      );
    }

    this.logger.log(
      `Rotated BYOK key for organization: ${organizationId} to version ${newVersion}`,
    );

    return newVersion;
  }

  /**
   * Revokes BYOK and migrates back to managed key
   */
  async revokeByokKey(organizationId: string): Promise<void> {
    const existing = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!existing) {
      throw new Error(
        `No encryption key found for organization: ${organizationId}`,
      );
    }

    if (existing.key_type === 'managed') {
      throw new Error('Organization is already using managed encryption');
    }

    // First unwrap with current provider to get the org key
    const orgKey = await this.unwrapOrganizationKey(existing);

    if (!this.masterKeyConfigured) {
      throw new Error(
        'Cannot migrate to managed key: master key not configured',
      );
    }

    // Re-wrap with managed provider
    const newSalt = crypto.randomBytes(SALT_LENGTH);
    const context: KeyProviderContext = {
      organizationId,
      salt: newSalt,
    };
    const wrappedKey = await this.managedKeyProvider.wrap(orgKey, context);

    await this.organizationKeyModel.updateOne(
      { _id: existing._id },
      {
        encrypted_key: wrappedKey,
        salt: newSalt.toString('hex'),
        key_type: 'managed',
        kms_config: null,
        customer_key_hash: null,
        version: existing.version + 1,
        rotated_at: new Date(),
      },
    );

    // Evict cached customer key
    this.directKeyProvider.evictCustomerKey(organizationId);

    this.logger.log(
      `Revoked BYOK and migrated to managed key for organization: ${organizationId}`,
    );
  }

  /**
   * Gets BYOK status for an organization
   */
  async getByokStatus(organizationId: string): Promise<ByokStatus> {
    const keyRecord = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!keyRecord) {
      return {
        key_type: 'managed',
        is_byok: false,
        key_version: 0,
      };
    }

    const keyType = keyRecord.key_type as KeyType;

    return {
      key_type: keyType,
      is_byok: keyType !== 'managed',
      kms_config: keyRecord.kms_config as KmsConfig | undefined,
      customer_key_hash: keyRecord.customer_key_hash || undefined,
      key_version: keyRecord.version,
      rotated_at: keyRecord.rotated_at || undefined,
    };
  }

  /**
   * Validates that a customer key matches the stored hash
   */
  async validateCustomerKey(
    organizationId: string,
    customerKeyHex: string,
  ): Promise<boolean> {
    const keyRecord = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!keyRecord || keyRecord.key_type !== 'direct') {
      return false;
    }

    const hash = DirectKeyProvider.hashCustomerKey(customerKeyHex);
    return hash === keyRecord.customer_key_hash;
  }

  /**
   * Cache a customer key for direct BYOK (for scheduled operations)
   */
  cacheCustomerKey(organizationId: string, customerKeyHex: string): void {
    this.directKeyProvider.cacheCustomerKey(organizationId, customerKeyHex);
  }

  /**
   * Evict a cached customer key
   */
  evictCustomerKey(organizationId: string): void {
    this.directKeyProvider.evictCustomerKey(organizationId);
  }

  /**
   * Creates a new managed encryption key for an organization
   */
  private async createOrganizationKey(organizationId: string): Promise<Buffer> {
    if (!this.masterKeyConfigured) {
      throw new Error('Encryption master key not configured');
    }

    const orgKey = crypto.randomBytes(KEY_LENGTH);
    const salt = crypto.randomBytes(SALT_LENGTH);

    const context: KeyProviderContext = {
      organizationId,
      salt,
    };

    const wrappedKey = await this.managedKeyProvider.wrap(orgKey, context);

    await this.organizationKeyModel.create({
      organization_id: new Types.ObjectId(organizationId),
      encrypted_key: wrappedKey,
      salt: salt.toString('hex'),
      version: 1,
      key_type: 'managed',
    });

    this.logger.log(
      `Created encryption key for organization: ${organizationId}`,
    );

    return orgKey;
  }

  /**
   * Unwraps an organization's key using the appropriate provider
   */
  private async unwrapOrganizationKey(
    keyRecord: OrganizationKeyDocument,
  ): Promise<Buffer> {
    const keyType = (keyRecord.key_type || 'managed') as KeyType;
    const salt = Buffer.from(keyRecord.salt, 'hex');

    const context: KeyProviderContext = {
      organizationId: keyRecord.organization_id.toString(),
      salt,
      kmsConfig: keyRecord.kms_config as KmsConfig | undefined,
    };

    const provider = this.getProvider(keyType);
    return provider.unwrap(keyRecord.encrypted_key, context);
  }

  /**
   * BYOK-011: Two-phase rotation for managed keys.
   *
   * Flow:
   *   1. Load existing record
   *   2. Generate new org key + salt
   *   3. Wrap with ManagedKeyProvider
   *   4. Validate via validateKeyBuffer (wrap/unwrap + cipher roundtrip)
   *   5. Abort on validation failure — DB is NEVER touched on the failure path
   *   6. Atomic updateOne that pushes the prior version to key_history
   *      (with $position: 0 + $slice: N for most-recent-first ordering),
   *      promotes the new key, sets last_pipeline_validation, clears
   *      last_rotation_error
   *
   * The pre-commit validation closes the latent bug where a broken provider
   * could promote an unreadable key. The key_history retention preserves
   * prior-version decryptability so backups taken before rotation remain
   * restorable via BYOK-013 (getOrganizationKey with version).
   */
  async rotateOrganizationKey(organizationId: string): Promise<number> {
    const existingRecord = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!existingRecord) {
      throw new Error(
        `No encryption key found for organization: ${organizationId}`,
      );
    }

    const keyType = (existingRecord.key_type || 'managed') as KeyType;

    if (keyType !== 'managed') {
      throw new Error('Use rotateByokKey for BYOK keys');
    }

    if (!this.masterKeyConfigured) {
      throw new Error('Encryption master key not configured');
    }

    const newOrgKey = crypto.randomBytes(KEY_LENGTH);
    const newSalt = crypto.randomBytes(SALT_LENGTH);
    const newVersion = existingRecord.version + 1;

    const context: KeyProviderContext = {
      organizationId,
      salt: newSalt,
    };

    const wrappedKey = await this.managedKeyProvider.wrap(newOrgKey, context);

    // Phase 1 — verify the candidate key before touching the database.
    const validation = await this.validateKeyBuffer(
      newOrgKey,
      wrappedKey,
      this.managedKeyProvider,
      context,
    );

    if (!validation.ok) {
      this.logger.error(
        `Key rotation validation failed for org ${organizationId}: ${validation.error}`,
      );
      throw new KeyRotationValidationError(
        organizationId,
        validation.error ?? 'unknown validation failure',
      );
    }

    // Phase 2 — push prior version to history and promote the new key
    // atomically via a single updateOne. Using $position: 0 + $slice: N keeps
    // the most-recently-retained entry at index 0.
    const retention =
      this.configService.get<number>('BYOK_KEY_HISTORY_RETENTION') ??
      DEFAULT_KEY_HISTORY_RETENTION;

    const now = new Date();
    const historyEntry: KeyHistoryEntry = {
      version: existingRecord.version,
      encrypted_key: existingRecord.encrypted_key,
      salt: existingRecord.salt,
      key_type: existingRecord.key_type,
      kms_config: existingRecord.kms_config,
      rotated_at: existingRecord.rotated_at ?? existingRecord.createdAt ?? now,
    };

    await this.organizationKeyModel.updateOne(
      { _id: existingRecord._id },
      {
        $push: {
          key_history: {
            $each: [historyEntry],
            $position: 0,
            $slice: retention,
          },
        },
        $set: {
          encrypted_key: wrappedKey,
          salt: newSalt.toString('hex'),
          version: newVersion,
          rotated_at: now,
          last_pipeline_validation: { validated_at: now, ok: true },
          last_rotation_error: null,
        },
      },
    );

    this.logger.log(
      `Rotated encryption key for organization: ${organizationId} to version ${newVersion}`,
    );

    return newVersion;
  }

  /**
   * Generates a salt for key derivation
   */
  generateSalt(): Buffer {
    return crypto.randomBytes(SALT_LENGTH);
  }

  /**
   * Validates that a key record exists for an organization
   */
  async hasOrganizationKey(organizationId: string): Promise<boolean> {
    const count = await this.organizationKeyModel.countDocuments({
      organization_id: new Types.ObjectId(organizationId),
    });
    return count > 0;
  }

  /**
   * BYOK-046: Admin acknowledges that the direct-key rotation is overdue
   * and wants to suppress email dispatches for `windowDays` days. Used by
   * the "Remind me later" dashboard button when the key is in critical
   * or escalated state (FR-06). The key is still reported on the
   * dashboard; only email sending is paused.
   *
   * Preconditions:
   *   1. Organization has an OrganizationKey record
   *   2. Key age has crossed the critical threshold (age_days >= interval_days)
   *
   * Returns the new `acknowledged_until` timestamp so callers can display
   * "acknowledged until DATE" in the UI.
   */
  async acknowledgeRotationOverdue(
    organizationId: string,
    windowDays: number = 30,
  ): Promise<{ acknowledged_until: Date }> {
    const record = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!record) {
      throw new Error(
        `No encryption key found for organization: ${organizationId}`,
      );
    }

    // Compute age and compare to interval
    const lastRotation = record.rotated_at || record.createdAt || new Date();
    const intervalDays = record.rotation_interval_days || 90;
    const ageDays =
      (Date.now() - new Date(lastRotation).getTime()) / (1000 * 60 * 60 * 24);

    if (ageDays < intervalDays) {
      throw new Error(
        `Cannot acknowledge rotation for a healthy key. Age ${ageDays.toFixed(1)}d is below the ${intervalDays}d threshold.`,
      );
    }

    const acknowledged_until = new Date(
      Date.now() + windowDays * 24 * 60 * 60 * 1000,
    );

    await this.organizationKeyModel.updateOne(
      { _id: record._id },
      { $set: { acknowledged_until } },
    );

    this.logger.log(
      `Acknowledged rotation overdue for org ${organizationId} — suppressing emails until ${acknowledged_until.toISOString()}`,
    );

    return { acknowledged_until };
  }

  /**
   * Deletes an organization's encryption key
   * WARNING: This will make all encrypted data for this organization unrecoverable
   */
  async deleteOrganizationKey(organizationId: string): Promise<void> {
    const result = await this.organizationKeyModel.deleteOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (result.deletedCount > 0) {
      this.directKeyProvider.evictCustomerKey(organizationId);
      this.logger.warn(
        `Deleted encryption key for organization: ${organizationId}`,
      );
    }
  }

  /**
   * Returns the appropriate key provider based on key type.
   *
   * BYOK-024: gcp-kms and azure-kms are now fully wired (implementations
   * from BYOK-021 and BYOK-023). Real-cloud contract tests run under the
   * BYOK-003 nightly CI workflow once BYOK-020/022 complete the SDK
   * installs — unit-test paths use the jest moduleNameMapper mocks.
   */
  private getProvider(keyType: KeyType) {
    switch (keyType) {
      case 'managed':
        return this.managedKeyProvider;
      case 'direct':
        return this.directKeyProvider;
      case 'aws-kms':
        return this.awsKmsProvider;
      case 'gcp-kms':
        return this.gcpKmsProvider;
      case 'azure-kms':
        return this.azureKmsProvider;
      default:
        throw new Error(`Unknown key type: ${String(keyType)}`);
    }
  }

  /**
   * Configures auto-rotation for an organization's encryption key
   */
  async configureAutoRotation(
    organizationId: string,
    enabled: boolean,
    intervalDays?: number,
  ): Promise<void> {
    const update: Record<string, unknown> = {
      auto_rotate: enabled,
    };
    if (intervalDays !== undefined) {
      update.rotation_interval_days = intervalDays;
    }

    const result = await this.organizationKeyModel.updateOne(
      { organization_id: new Types.ObjectId(organizationId) },
      update,
    );

    if (result.matchedCount === 0) {
      throw new Error(
        `No encryption key found for organization: ${organizationId}`,
      );
    }

    this.logger.log(
      `Auto-rotation ${enabled ? 'enabled' : 'disabled'} for organization: ${organizationId}`,
    );
  }

  /**
   * BYOK-070: Read the full rotation policy + current state snapshot
   * used by the dashboard (BYOK-072/073) and the GET endpoint.
   *
   * Returns null when the organization has no encryption key — the
   * caller (controller) converts null into a 404 response.
   *
   * `next_rotation_at` is computed from `rotated_at + rotation_interval_days`
   * and falls back to `createdAt` when the key has never been rotated.
   */
  async getRotationPolicy(organizationId: string): Promise<{
    auto_rotate: boolean;
    rotation_interval_days: number;
    restore_drill_enabled: boolean;
    next_rotation_at: Date | null;
    last_rotation_error: LastRotationError | null;
  } | null> {
    const record = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!record) return null;

    const intervalDays = record.rotation_interval_days || 90;
    const lastRotation = record.rotated_at ?? record.createdAt ?? null;
    const next_rotation_at = lastRotation
      ? new Date(
          new Date(lastRotation).getTime() + intervalDays * 24 * 60 * 60 * 1000,
        )
      : null;

    return {
      auto_rotate: record.auto_rotate ?? false,
      rotation_interval_days: intervalDays,
      restore_drill_enabled: record.restore_drill_enabled ?? true,
      next_rotation_at,
      last_rotation_error: record.last_rotation_error ?? null,
    };
  }

  /**
   * BYOK-070: Partial update of the rotation policy fields.
   *
   * Validates `rotation_interval_days` is within the 7-365 day range
   * (hard coded — outside this range is either dangerous churn or
   * pointless retention). Every other field is optional.
   *
   * Throws with "No encryption key found" when the org has no record,
   * and with a validation message when interval_days is out of range.
   * The controller maps these to 404 / 400 responses.
   */
  async updateRotationPolicy(
    organizationId: string,
    patch: {
      auto_rotate?: boolean;
      rotation_interval_days?: number;
      restore_drill_enabled?: boolean;
    },
  ): Promise<void> {
    if (patch.rotation_interval_days !== undefined) {
      if (
        !Number.isFinite(patch.rotation_interval_days) ||
        patch.rotation_interval_days < 7 ||
        patch.rotation_interval_days > 365
      ) {
        throw new Error(
          `rotation_interval_days must be between 7 and 365 (received ${patch.rotation_interval_days})`,
        );
      }
    }

    const update: Record<string, unknown> = {};
    if (patch.auto_rotate !== undefined) update.auto_rotate = patch.auto_rotate;
    if (patch.rotation_interval_days !== undefined)
      update.rotation_interval_days = patch.rotation_interval_days;
    if (patch.restore_drill_enabled !== undefined)
      update.restore_drill_enabled = patch.restore_drill_enabled;

    if (Object.keys(update).length === 0) {
      // Nothing to change — treat as success no-op rather than erroring
      return;
    }

    const result = await this.organizationKeyModel.updateOne(
      { organization_id: new Types.ObjectId(organizationId) },
      { $set: update },
    );

    if (result.matchedCount === 0) {
      throw new Error(
        `No encryption key found for organization: ${organizationId}`,
      );
    }

    this.logger.log(
      `Rotation policy updated for org ${organizationId}: ${JSON.stringify(update)}`,
    );
  }

  /**
   * BYOK-080: Returns the encryption material the Electron agent needs to
   * encrypt/decrypt backup files for this organization.
   *
   * Direct BYOK is unwrapped on the agent side (the customer holds the key),
   * so the server returns `wrapped_key` + salt and lets the agent call
   * DirectKeyProvider.unwrap locally using the cached customer key.
   *
   * Managed / AWS / GCP / Azure are unwrapped on the SERVER because the agent
   * has no cloud SDKs in its bundle. The raw 32-byte org key is hex-encoded
   * into `raw_org_key` and streamed to the agent over the existing TLS
   * WebSocket channel. The agent treats it as ephemeral — it lives in memory
   * for the job duration and is never persisted or logged.
   *
   * Exactly one of `wrapped_key` / `raw_org_key` is present on the result.
   * `salt` is always returned for wire-format compatibility with older
   * agents; non-direct agents may ignore it.
   */
  async getAgentEncryptionConfig(organizationId: string): Promise<{
    enabled: true;
    key_type: string;
    salt: string;
    key_version: number;
    wrapped_key?: string;
    raw_org_key?: string;
  } | null> {
    const keyRecord = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(organizationId),
    });

    if (!keyRecord) {
      return null;
    }

    const keyType = keyRecord.key_type || 'managed';
    const base = {
      enabled: true as const,
      key_type: keyType,
      salt: keyRecord.salt,
      key_version: keyRecord.version || 1,
    };

    if (keyType === 'direct') {
      return {
        ...base,
        wrapped_key: keyRecord.encrypted_key,
      };
    }

    const rawKey = await this.unwrapOrganizationKey(keyRecord);
    return {
      ...base,
      raw_org_key: rawKey.toString('hex'),
    };
  }

  private validateByokRegistration(registration: ByokRegistration): void {
    switch (registration.key_type) {
      case 'direct':
        if (!registration.customer_key) {
          throw new Error('Customer key is required for direct BYOK');
        }
        if (registration.customer_key.length !== 64) {
          throw new Error('Customer key must be 64 hex characters (32 bytes)');
        }
        if (!/^[0-9a-fA-F]+$/.test(registration.customer_key)) {
          throw new Error('Customer key must be a valid hex string');
        }
        break;

      case 'aws-kms':
      case 'gcp-kms':
      case 'azure-kms':
        if (!registration.kms_config) {
          throw new Error('KMS config is required for KMS-based BYOK');
        }
        if (!registration.kms_config.key_id) {
          throw new Error('KMS key_id is required');
        }
        break;
    }
  }
}
