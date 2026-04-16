import * as crypto from 'crypto';
import { ManagedKeyProvider } from './managed-key.provider';
import { EncryptionService } from '../services/encryption.service';
import { KeyProviderContext } from '../interfaces/encryption.interface';

describe('ManagedKeyProvider', () => {
  let provider: ManagedKeyProvider;
  let encryptionService: EncryptionService;
  let originalMasterKey: string | undefined;

  beforeEach(() => {
    originalMasterKey = process.env.ENCRYPTION_MASTER_KEY;
    process.env.ENCRYPTION_MASTER_KEY = crypto.randomBytes(32).toString('hex');

    const mockConfigService = { get: jest.fn() };
    encryptionService = new EncryptionService(mockConfigService as any);
    provider = new ManagedKeyProvider(encryptionService);
  });

  afterEach(() => {
    if (originalMasterKey !== undefined) {
      process.env.ENCRYPTION_MASTER_KEY = originalMasterKey;
    } else {
      delete process.env.ENCRYPTION_MASTER_KEY;
    }
  });

  describe('wrap and unwrap', () => {
    it('should round-trip wrap/unwrap returning the original key', async () => {
      const orgKey = crypto.randomBytes(32);
      const context: KeyProviderContext = {
        organizationId: 'org-123',
        salt: crypto.randomBytes(16),
      };

      const wrapped = await provider.wrap(orgKey, context);
      const unwrapped = await provider.unwrap(wrapped, context);

      expect(unwrapped).toEqual(orgKey);
    });

    it('should produce a valid JSON string from wrap', async () => {
      const orgKey = crypto.randomBytes(32);
      const context: KeyProviderContext = {
        organizationId: 'org-456',
        salt: crypto.randomBytes(16),
      };

      const wrapped = await provider.wrap(orgKey, context);
      const parsed = JSON.parse(wrapped);

      expect(parsed).toHaveProperty('value');
      expect(parsed).toHaveProperty('iv');
      expect(parsed).toHaveProperty('authTag');
    });
  });

  describe('getMasterKey validation', () => {
    it('should throw when ENCRYPTION_MASTER_KEY is not set', async () => {
      delete process.env.ENCRYPTION_MASTER_KEY;

      const orgKey = crypto.randomBytes(32);
      const context: KeyProviderContext = {
        organizationId: 'org-789',
        salt: crypto.randomBytes(16),
      };

      await expect(provider.wrap(orgKey, context)).rejects.toThrow(
        'Encryption master key not configured or invalid',
      );
    });

    it('should throw when ENCRYPTION_MASTER_KEY has wrong length', async () => {
      process.env.ENCRYPTION_MASTER_KEY = 'abcdef1234';

      const orgKey = crypto.randomBytes(32);
      const context: KeyProviderContext = {
        organizationId: 'org-000',
        salt: crypto.randomBytes(16),
      };

      await expect(provider.wrap(orgKey, context)).rejects.toThrow(
        'Encryption master key not configured or invalid',
      );
    });
  });

  describe('salt sensitivity', () => {
    it('should fail to unwrap when a different salt is used', async () => {
      const orgKey = crypto.randomBytes(32);
      const wrapContext: KeyProviderContext = {
        organizationId: 'org-salt',
        salt: crypto.randomBytes(16),
      };
      const unwrapContext: KeyProviderContext = {
        organizationId: 'org-salt',
        salt: crypto.randomBytes(16),
      };

      const wrapped = await provider.wrap(orgKey, wrapContext);

      await expect(provider.unwrap(wrapped, unwrapContext)).rejects.toThrow();
    });

    it('should produce different wrapped output for different salts', async () => {
      const orgKey = crypto.randomBytes(32);
      const context1: KeyProviderContext = {
        organizationId: 'org-diff',
        salt: crypto.randomBytes(16),
      };
      const context2: KeyProviderContext = {
        organizationId: 'org-diff',
        salt: crypto.randomBytes(16),
      };

      const wrapped1 = await provider.wrap(orgKey, context1);
      const wrapped2 = await provider.wrap(orgKey, context2);

      expect(wrapped1).not.toEqual(wrapped2);
    });
  });
});
