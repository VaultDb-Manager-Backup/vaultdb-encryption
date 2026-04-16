import {
  resolveOrgKeyForRestore,
  RestoreKeyUnavailableError,
  KeyResolverKms,
  KeyResolverLogger,
} from './restore-key-resolver';
import { KeyVersionNotFoundError } from '../errors/key-rotation.errors';
import { EncryptedFileMetadata } from '../interfaces/encryption.interface';

describe('resolveOrgKeyForRestore', () => {
  const ORG_ID = '507f1f77bcf86cd799439011';

  let mockKms: { getOrganizationKey: jest.Mock };
  let mockLogger: { warn: jest.Mock; error: jest.Mock };

  beforeEach(() => {
    mockKms = { getOrganizationKey: jest.fn() };
    mockLogger = { warn: jest.fn(), error: jest.fn() };
  });

  const buildMeta = (
    overrides: Partial<EncryptedFileMetadata> = {},
  ): EncryptedFileMetadata => ({
    algorithm: 'aes-256-gcm',
    iv: 'iv-hex',
    authTag: 'tag-hex',
    originalChecksum: 'md5-hex',
    keyVersion: 2,
    encryptedAt: new Date('2026-03-01'),
    ...overrides,
  });

  describe('happy path with version present', () => {
    it('passes keyVersion through to getOrganizationKey', async () => {
      const expectedKey = Buffer.alloc(32, 0xab);
      mockKms.getOrganizationKey.mockResolvedValue(expectedKey);

      const result = await resolveOrgKeyForRestore(
        ORG_ID,
        buildMeta({ keyVersion: 3 }),
        mockKms as KeyResolverKms,
        mockLogger as KeyResolverLogger,
      );

      expect(result).toBe(expectedKey);
      expect(mockKms.getOrganizationKey).toHaveBeenCalledWith(ORG_ID, 3);
      expect(mockLogger.warn).not.toHaveBeenCalled();
      expect(mockLogger.error).not.toHaveBeenCalled();
    });
  });

  describe('legacy fallback when keyVersion missing', () => {
    it('calls getOrganizationKey without version and logs a warning (null metadata)', async () => {
      const expectedKey = Buffer.alloc(32, 0xcd);
      mockKms.getOrganizationKey.mockResolvedValue(expectedKey);

      const result = await resolveOrgKeyForRestore(
        ORG_ID,
        null,
        mockKms as KeyResolverKms,
        mockLogger as KeyResolverLogger,
      );

      expect(result).toBe(expectedKey);
      expect(mockKms.getOrganizationKey).toHaveBeenCalledWith(ORG_ID);
      expect(mockKms.getOrganizationKey).not.toHaveBeenCalledWith(
        ORG_ID,
        expect.any(Number),
      );
      expect(mockLogger.warn).toHaveBeenCalled();
      expect(mockLogger.warn.mock.calls[0][0]).toMatch(/legacy backup/i);
    });

    it('calls getOrganizationKey without version when keyVersion is undefined', async () => {
      const expectedKey = Buffer.alloc(32, 0xef);
      mockKms.getOrganizationKey.mockResolvedValue(expectedKey);

      const metaWithoutVersion = buildMeta();
      delete (metaWithoutVersion as Partial<EncryptedFileMetadata>).keyVersion;

      const result = await resolveOrgKeyForRestore(
        ORG_ID,
        metaWithoutVersion,
        mockKms as KeyResolverKms,
        mockLogger as KeyResolverLogger,
      );

      expect(result).toBe(expectedKey);
      expect(mockKms.getOrganizationKey).toHaveBeenCalledWith(ORG_ID);
      expect(mockLogger.warn).toHaveBeenCalled();
    });
  });

  describe('KeyVersionNotFoundError handling', () => {
    it('converts KeyVersionNotFoundError to RestoreKeyUnavailableError with context', async () => {
      mockKms.getOrganizationKey.mockRejectedValue(
        new KeyVersionNotFoundError(ORG_ID, 2, [4, 3]),
      );

      const promise = resolveOrgKeyForRestore(
        ORG_ID,
        buildMeta({ keyVersion: 2 }),
        mockKms as KeyResolverKms,
        mockLogger as KeyResolverLogger,
      );

      await expect(promise).rejects.toBeInstanceOf(RestoreKeyUnavailableError);

      try {
        await promise;
      } catch (err) {
        const typed = err as RestoreKeyUnavailableError;
        expect(typed.requestedVersion).toBe(2);
        expect(typed.availableVersions).toEqual([4, 3]);
        expect(typed.message).toContain('2');
        expect(typed.message).toContain('BYOK_KEY_HISTORY_RETENTION');
      }

      expect(mockLogger.error).toHaveBeenCalled();
      expect(mockLogger.error.mock.calls[0][0]).toMatch(/Key version 2/);
    });

    it('rethrows unrelated errors untouched', async () => {
      const unrelated = new Error('network timeout');
      mockKms.getOrganizationKey.mockRejectedValue(unrelated);

      await expect(
        resolveOrgKeyForRestore(
          ORG_ID,
          buildMeta({ keyVersion: 2 }),
          mockKms as KeyResolverKms,
          mockLogger as KeyResolverLogger,
        ),
      ).rejects.toBe(unrelated);

      expect(mockLogger.error).not.toHaveBeenCalled();
    });
  });

  describe('edge cases', () => {
    it('handles keyVersion = 0 as a present value (not falsy fallback)', async () => {
      mockKms.getOrganizationKey.mockResolvedValue(Buffer.alloc(32));

      await resolveOrgKeyForRestore(
        ORG_ID,
        buildMeta({ keyVersion: 0 }),
        mockKms as KeyResolverKms,
        mockLogger as KeyResolverLogger,
      );

      expect(mockKms.getOrganizationKey).toHaveBeenCalledWith(ORG_ID, 0);
      expect(mockLogger.warn).not.toHaveBeenCalled();
    });
  });
});
