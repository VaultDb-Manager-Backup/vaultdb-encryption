/**
 * Metadata stored alongside encrypted backup files
 */
export interface EncryptedFileMetadata {
  algorithm: 'aes-256-gcm';
  iv: string; // hex encoded
  authTag: string; // hex encoded
  originalChecksum: string; // MD5 of original file
  keyVersion: number;
  encryptedAt: Date;
}

/**
 * Structure for encrypted fields in MongoDB documents
 */
export interface EncryptedField {
  value: string; // base64 encoded ciphertext
  iv: string; // hex encoded
  authTag: string; // hex encoded
  version: number; // key version for rotation support
}

/**
 * Organization encryption key record
 */
export interface OrganizationKeyRecord {
  organizationId: string;
  encryptedKey: string; // encrypted with master key
  salt: string; // hex encoded
  version: number;
  createdAt: Date;
  rotatedAt?: Date;
}

/**
 * Result of file encryption operation
 */
export interface EncryptFileResult {
  outputPath: string;
  metadata: EncryptedFileMetadata;
}

/**
 * Configuration for encryption service
 */
export interface EncryptionConfig {
  masterKey: string; // hex encoded 32-byte key
  algorithm?: 'aes-256-gcm';
  keyDerivationIterations?: number;
}

/**
 * Fields that can be encrypted in BackupSettings
 */
export type BackupSettingsEncryptableFields = 'password' | 'uri';

/**
 * Fields that can be encrypted in StorageSettings
 */
export type StorageSettingsEncryptableFields =
  | 'secret_key'
  | 'access_key'
  | 'ftp_password';

/**
 * BYOK key types
 */
export type KeyType =
  | 'managed'
  | 'direct'
  | 'aws-kms'
  | 'gcp-kms'
  | 'azure-kms';

/**
 * KMS provider configuration
 */
export interface KmsConfig {
  provider: 'aws' | 'gcp' | 'azure';
  key_id: string; // ARN, resource name, or key vault URI
  region?: string;
}

/**
 * BYOK registration request
 */
export interface ByokRegistration {
  key_type: KeyType;
  customer_key?: string; // hex encoded, only for 'direct'
  kms_config?: KmsConfig; // only for KMS providers
}

/**
 * Context passed to key providers for wrap/unwrap operations
 */
export interface KeyProviderContext {
  organizationId: string;
  salt: Buffer;
  kmsConfig?: KmsConfig;
}

/**
 * Interface for key providers that handle wrap/unwrap of organization keys
 */
export interface KeyProvider {
  wrap(orgKey: Buffer, context: KeyProviderContext): Promise<string>;
  unwrap(wrappedKey: string, context: KeyProviderContext): Promise<Buffer>;
}

/**
 * Options for BYOK rotation (BYOK-012).
 *
 * Supports same-provider rotation (empty options) AND provider switching
 * during rotation. When targetKeyType differs from the current key_type,
 * the old version is pushed to key_history with its ORIGINAL kms_config
 * so BYOK-013's version-aware getOrganizationKey can still unwrap it.
 */
export interface RotateByokOptions {
  newCustomerKey?: string; // required when target is 'direct'
  targetKeyType?: KeyType; // defaults to existing key_type
  targetKmsConfig?: KmsConfig; // required when target is a KMS type
}

/**
 * BYOK status response
 */
export interface ByokStatus {
  key_type: KeyType;
  is_byok: boolean;
  kms_config?: KmsConfig;
  customer_key_hash?: string;
  key_version: number;
  rotated_at?: Date;
}

/**
 * Result of a key pipeline validation (BYOK-030 / FR-07a).
 *
 * Used by validateKeyBuffer (internal, operates on raw buffers) and
 * validatePipeline (public, operates by orgId). The method never throws —
 * any error is captured as ok=false with a descriptive error string.
 */
export interface PipelineValidationResult {
  ok: boolean;
  error?: string;
  duration_ms: number;
}
