import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import {
  KeyProvider,
  KeyProviderContext,
} from '../interfaces/encryption.interface';
import { EncryptionService } from '../services/encryption.service';

const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_DIGEST = 'sha512';

@Injectable()
export class DirectKeyProvider implements KeyProvider {
  private readonly logger = new Logger(DirectKeyProvider.name);

  private readonly keyCache = new Map<string, Buffer>();

  constructor(private readonly encryptionService: EncryptionService) {}

  // eslint-disable-next-line @typescript-eslint/require-await
  async wrap(orgKey: Buffer, context: KeyProviderContext): Promise<string> {
    const customerKey = this.getCustomerKey(context.organizationId);
    const kek = this.deriveKey(customerKey, context.salt);
    const encrypted = this.encryptionService.encryptString(
      orgKey.toString('hex'),
      kek,
    );
    return JSON.stringify(encrypted);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async unwrap(
    wrappedKey: string,
    context: KeyProviderContext,
  ): Promise<Buffer> {
    const customerKey = this.getCustomerKey(context.organizationId);
    const kek = this.deriveKey(customerKey, context.salt);
    const encrypted = JSON.parse(wrappedKey) as {
      value: string;
      iv: string;
      authTag: string;
    };
    const decryptedHex = this.encryptionService.decryptString(
      encrypted.value,
      encrypted.iv,
      encrypted.authTag,
      kek,
    );
    return Buffer.from(decryptedHex, 'hex');
  }

  /**
   * Cache a customer key in memory for use during scheduled operations.
   * The key is NEVER persisted to disk or database.
   */
  cacheCustomerKey(organizationId: string, customerKeyHex: string): void {
    if (customerKeyHex.length !== 64) {
      throw new Error('Customer key must be 64 hex characters (32 bytes)');
    }
    this.keyCache.set(organizationId, Buffer.from(customerKeyHex, 'hex'));
    this.logger.log(`Cached customer key for organization: ${organizationId}`);
  }

  /**
   * Remove a customer key from the in-memory cache
   */
  evictCustomerKey(organizationId: string): void {
    this.keyCache.delete(organizationId);
    this.logger.log(`Evicted customer key for organization: ${organizationId}`);
  }

  /**
   * Check if a customer key is cached for the given organization
   */
  hasCustomerKey(organizationId: string): boolean {
    return this.keyCache.has(organizationId);
  }

  /**
   * Compute SHA-256 hash of a customer key (for storage/validation)
   */
  static hashCustomerKey(customerKeyHex: string): string {
    return crypto
      .createHash('sha256')
      .update(customerKeyHex, 'hex')
      .digest('hex');
  }

  private getCustomerKey(organizationId: string): Buffer {
    const cached = this.keyCache.get(organizationId);
    if (!cached) {
      throw new Error(
        `Customer key not available for organization: ${organizationId}. ` +
          'The key must be provided via API before encryption/decryption operations.',
      );
    }
    return cached;
  }

  private deriveKey(customerKey: Buffer, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(
      customerKey,
      salt,
      PBKDF2_ITERATIONS,
      KEY_LENGTH,
      PBKDF2_DIGEST,
    );
  }
}
