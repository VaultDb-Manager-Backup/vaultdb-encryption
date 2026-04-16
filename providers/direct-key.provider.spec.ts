import * as crypto from 'crypto';
import { EncryptionService } from '../services/encryption.service';
import { DirectKeyProvider } from './direct-key.provider';
import { KeyProviderContext } from '../interfaces/encryption.interface';

describe('DirectKeyProvider', () => {
  let provider: DirectKeyProvider;
  let encryptionService: EncryptionService;

  const mockConfigService = { get: jest.fn() };

  beforeEach(() => {
    encryptionService = new EncryptionService(mockConfigService as any);
    provider = new DirectKeyProvider(encryptionService);
  });

  describe('cacheCustomerKey / hasCustomerKey', () => {
    it('should store key and hasCustomerKey returns true', () => {
      const orgId = 'org-001';
      const customerKeyHex = crypto.randomBytes(32).toString('hex');

      provider.cacheCustomerKey(orgId, customerKeyHex);

      expect(provider.hasCustomerKey(orgId)).toBe(true);
    });

    it('should reject key with length != 64 hex characters', () => {
      const orgId = 'org-002';
      const shortKey = crypto.randomBytes(16).toString('hex'); // 32 chars

      expect(() => provider.cacheCustomerKey(orgId, shortKey)).toThrow(
        'Customer key must be 64 hex characters (32 bytes)',
      );
    });
  });

  describe('evictCustomerKey', () => {
    it('should remove key and hasCustomerKey returns false', () => {
      const orgId = 'org-003';
      const customerKeyHex = crypto.randomBytes(32).toString('hex');

      provider.cacheCustomerKey(orgId, customerKeyHex);
      expect(provider.hasCustomerKey(orgId)).toBe(true);

      provider.evictCustomerKey(orgId);
      expect(provider.hasCustomerKey(orgId)).toBe(false);
    });
  });

  describe('wrap / unwrap', () => {
    it('should round-trip wrap and unwrap with cached customer key', async () => {
      const orgId = 'org-004';
      const customerKeyHex = crypto.randomBytes(32).toString('hex');
      const orgKey = crypto.randomBytes(32);
      const salt = crypto.randomBytes(16);

      provider.cacheCustomerKey(orgId, customerKeyHex);

      const context: KeyProviderContext = { organizationId: orgId, salt };

      const wrapped = await provider.wrap(orgKey, context);
      const unwrapped = await provider.unwrap(wrapped, context);

      expect(unwrapped).toEqual(orgKey);
    });

    it('should throw when wrap is called with no cached key for org', async () => {
      const orgKey = crypto.randomBytes(32);
      const salt = crypto.randomBytes(16);
      const context: KeyProviderContext = {
        organizationId: 'org-missing',
        salt,
      };

      await expect(provider.wrap(orgKey, context)).rejects.toThrow(
        /Customer key not available for organization/,
      );
    });

    it('should throw when unwrap is called with no cached key for org', async () => {
      const salt = crypto.randomBytes(16);
      const context: KeyProviderContext = {
        organizationId: 'org-missing',
        salt,
      };

      await expect(provider.unwrap('{}', context)).rejects.toThrow(
        /Customer key not available for organization/,
      );
    });
  });

  describe('hashCustomerKey', () => {
    it('should be deterministic (same input produces same output)', () => {
      const customerKeyHex = crypto.randomBytes(32).toString('hex');

      const hash1 = DirectKeyProvider.hashCustomerKey(customerKeyHex);
      const hash2 = DirectKeyProvider.hashCustomerKey(customerKeyHex);

      expect(hash1).toBe(hash2);
    });

    it('should produce different output for different inputs', () => {
      const key1 = crypto.randomBytes(32).toString('hex');
      const key2 = crypto.randomBytes(32).toString('hex');

      const hash1 = DirectKeyProvider.hashCustomerKey(key1);
      const hash2 = DirectKeyProvider.hashCustomerKey(key2);

      expect(hash1).not.toBe(hash2);
    });
  });
});
