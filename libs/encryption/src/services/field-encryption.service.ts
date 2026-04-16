import { Injectable, Logger } from '@nestjs/common';
import { EncryptionService } from './encryption.service';
import { KeyManagementService } from './key-management.service';
import { EncryptedField } from '../interfaces/encryption.interface';

@Injectable()
export class FieldEncryptionService {
  private readonly logger = new Logger(FieldEncryptionService.name);

  constructor(
    private readonly encryptionService: EncryptionService,
    private readonly keyManagementService: KeyManagementService,
  ) {}

  /**
   * Encrypts a field value for storage in MongoDB
   * @param value The value to encrypt
   * @param organizationId The organization ID for key lookup
   * @returns Encrypted field structure
   */
  async encryptField(
    value: string,
    organizationId: string,
  ): Promise<EncryptedField> {
    if (!value) {
      throw new Error('Cannot encrypt empty value');
    }

    const key =
      await this.keyManagementService.getOrganizationKey(organizationId);
    const keyVersion =
      await this.keyManagementService.getKeyVersion(organizationId);

    const encrypted = this.encryptionService.encryptString(value, key);

    return {
      value: encrypted.value,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      version: keyVersion,
    };
  }

  /**
   * Decrypts an encrypted field value
   * @param encryptedField The encrypted field structure
   * @param organizationId The organization ID for key lookup
   * @returns Decrypted value
   */
  async decryptField(
    encryptedField: EncryptedField,
    organizationId: string,
  ): Promise<string> {
    if (!encryptedField || !encryptedField.value) {
      throw new Error('Invalid encrypted field');
    }

    const key =
      await this.keyManagementService.getOrganizationKey(organizationId);

    return this.encryptionService.decryptString(
      encryptedField.value,
      encryptedField.iv,
      encryptedField.authTag,
      key,
    );
  }

  /**
   * Encrypts multiple fields in an object
   * @param obj The object containing fields to encrypt
   * @param fieldNames Names of fields to encrypt
   * @param organizationId The organization ID for key lookup
   * @returns Object with encrypted fields added (original fields removed)
   */
  async encryptFields<T extends Record<string, unknown>>(
    obj: T,
    fieldNames: (keyof T)[],
    organizationId: string,
  ): Promise<T & Record<string, EncryptedField | null>> {
    const result = { ...obj } as Record<string, unknown>;

    for (const fieldName of fieldNames) {
      const value = obj[fieldName];
      const encryptedFieldName = `${String(fieldName)}_encrypted`;

      if (value && typeof value === 'string') {
        result[encryptedFieldName] = await this.encryptField(
          value,
          organizationId,
        );
        // Clear the plaintext field
        result[fieldName as string] = null;
      } else {
        result[encryptedFieldName] = null;
      }
    }

    return result as T & Record<string, EncryptedField | null>;
  }

  /**
   * Decrypts multiple encrypted fields in an object
   * @param obj The object containing encrypted fields
   * @param fieldNames Names of original fields (will look for fieldName_encrypted)
   * @param organizationId The organization ID for key lookup
   * @returns Object with decrypted values in original field names
   */
  async decryptFields<T extends Record<string, unknown>>(
    obj: T,
    fieldNames: string[],
    organizationId: string,
  ): Promise<T> {
    const result = { ...obj } as Record<string, unknown>;

    for (const fieldName of fieldNames) {
      const encryptedFieldName = `${fieldName}_encrypted`;
      const encryptedField = obj[encryptedFieldName] as EncryptedField | null;

      if (encryptedField && encryptedField.value) {
        try {
          result[fieldName] = await this.decryptField(
            encryptedField,
            organizationId,
          );
        } catch (error) {
          this.logger.error(
            `Failed to decrypt field ${fieldName}: ${(error as Error).message}`,
          );
          // Keep the original value (which may be null or legacy plaintext)
        }
      }
      // If no encrypted field, keep the original value (legacy support)
    }

    return result as T;
  }

  /**
   * Checks if a field has an encrypted version
   */
  hasEncryptedField<T extends Record<string, unknown>>(
    obj: T,
    fieldName: string,
  ): boolean {
    const encryptedFieldName = `${fieldName}_encrypted`;
    const encryptedField = obj[encryptedFieldName] as EncryptedField | null;
    return !!(encryptedField && encryptedField.value);
  }

  /**
   * Gets a field value, preferring decrypted value over plaintext
   * Provides backward compatibility for legacy unencrypted data
   */
  async getFieldValue<T extends Record<string, unknown>>(
    obj: T,
    fieldName: string,
    organizationId: string,
  ): Promise<string | null> {
    // First try to get the encrypted value
    if (this.hasEncryptedField(obj, fieldName)) {
      const encryptedFieldName = `${fieldName}_encrypted`;
      const encryptedField = obj[encryptedFieldName] as EncryptedField;
      try {
        return await this.decryptField(encryptedField, organizationId);
      } catch (error) {
        this.logger.error(
          `Failed to decrypt ${fieldName}, falling back to plaintext: ${(error as Error).message}`,
        );
      }
    }

    // Fall back to plaintext value (legacy support)
    const plainValue = obj[fieldName];
    return typeof plainValue === 'string' ? plainValue : null;
  }

  /**
   * Check if encryption is available
   */
  isEncryptionAvailable(): boolean {
    return this.keyManagementService.isEncryptionAvailable();
  }
}
