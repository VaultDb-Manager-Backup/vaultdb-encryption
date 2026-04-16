import { FieldEncryptionService } from './field-encryption.service';

describe('FieldEncryptionService', () => {
  const orgId = '507f1f77bcf86cd799439011';
  const mockKey = Buffer.from('a'.repeat(64), 'hex');

  const mockEncryptionService = {
    encryptString: jest.fn(),
    decryptString: jest.fn(),
  };

  const mockKeyManagementService = {
    getOrganizationKey: jest.fn(),
    getKeyVersion: jest.fn(),
    isEncryptionAvailable: jest.fn(),
  };

  let service: FieldEncryptionService;

  beforeEach(() => {
    jest.clearAllMocks();

    service = new FieldEncryptionService(
      mockEncryptionService as any,
      mockKeyManagementService as any,
    );

    mockKeyManagementService.getOrganizationKey.mockResolvedValue(mockKey);
    mockKeyManagementService.getKeyVersion.mockResolvedValue(1);
  });

  describe('encryptField', () => {
    it('should encrypt a value and return encrypted field with version', async () => {
      const encryptedResult = {
        value: 'encryptedBase64',
        iv: 'abc123',
        authTag: 'tag456',
      };
      mockEncryptionService.encryptString.mockReturnValue(encryptedResult);

      const result = await service.encryptField('my-secret', orgId);

      expect(mockKeyManagementService.getOrganizationKey).toHaveBeenCalledWith(
        orgId,
      );
      expect(mockKeyManagementService.getKeyVersion).toHaveBeenCalledWith(
        orgId,
      );
      expect(mockEncryptionService.encryptString).toHaveBeenCalledWith(
        'my-secret',
        mockKey,
      );
      expect(result).toEqual({
        value: 'encryptedBase64',
        iv: 'abc123',
        authTag: 'tag456',
        version: 1,
      });
    });

    it('should throw when value is empty', async () => {
      await expect(service.encryptField('', orgId)).rejects.toThrow(
        'Cannot encrypt empty value',
      );
    });
  });

  describe('decryptField', () => {
    it('should decrypt an encrypted field and return the plaintext', async () => {
      const encryptedField = {
        value: 'encryptedBase64',
        iv: 'abc123',
        authTag: 'tag456',
        version: 1,
      };
      mockEncryptionService.decryptString.mockReturnValue('my-secret');

      const result = await service.decryptField(encryptedField, orgId);

      expect(mockKeyManagementService.getOrganizationKey).toHaveBeenCalledWith(
        orgId,
      );
      expect(mockEncryptionService.decryptString).toHaveBeenCalledWith(
        'encryptedBase64',
        'abc123',
        'tag456',
        mockKey,
      );
      expect(result).toBe('my-secret');
    });

    it('should throw when encryptedField is null', async () => {
      await expect(service.decryptField(null as any, orgId)).rejects.toThrow(
        'Invalid encrypted field',
      );
    });

    it('should throw when encryptedField has no value', async () => {
      const invalidField = { value: '', iv: 'abc', authTag: 'tag', version: 1 };
      await expect(service.decryptField(invalidField, orgId)).rejects.toThrow(
        'Invalid encrypted field',
      );
    });
  });

  describe('encryptFields', () => {
    it('should create _encrypted fields and null originals', async () => {
      const obj = { host: 'db.example.com', port: '5432', password: 's3cret' };
      const encryptedHost = {
        value: 'encHost',
        iv: 'iv1',
        authTag: 'tag1',
      };
      const encryptedPassword = {
        value: 'encPass',
        iv: 'iv2',
        authTag: 'tag2',
      };

      mockEncryptionService.encryptString
        .mockReturnValueOnce(encryptedHost)
        .mockReturnValueOnce(encryptedPassword);

      const result = await service.encryptFields(
        obj,
        ['host', 'password'],
        orgId,
      );

      expect(result.host).toBeNull();
      expect(result.password).toBeNull();
      expect(result.port).toBe('5432');
      expect((result as any).host_encrypted).toEqual({
        value: 'encHost',
        iv: 'iv1',
        authTag: 'tag1',
        version: 1,
      });
      expect((result as any).password_encrypted).toEqual({
        value: 'encPass',
        iv: 'iv2',
        authTag: 'tag2',
        version: 1,
      });
    });

    it('should set encrypted field to null for non-string values', async () => {
      const obj = { name: 'test', count: 42 as any };

      mockEncryptionService.encryptString.mockReturnValue({
        value: 'enc',
        iv: 'iv',
        authTag: 'tag',
      });

      const result = await service.encryptFields(obj, ['name', 'count'], orgId);

      expect(result.name).toBeNull();
      expect((result as any).name_encrypted).toBeDefined();
      expect((result as any).count_encrypted).toBeNull();
    });
  });

  describe('decryptFields', () => {
    it('should restore original field values from encrypted fields', async () => {
      const obj = {
        host: null,
        host_encrypted: {
          value: 'encHost',
          iv: 'iv1',
          authTag: 'tag1',
          version: 1,
        },
        password: null,
        password_encrypted: {
          value: 'encPass',
          iv: 'iv2',
          authTag: 'tag2',
          version: 1,
        },
      };

      mockEncryptionService.decryptString
        .mockReturnValueOnce('db.example.com')
        .mockReturnValueOnce('s3cret');

      const result = await service.decryptFields(
        obj,
        ['host', 'password'],
        orgId,
      );

      expect(result.host).toBe('db.example.com');
      expect(result.password).toBe('s3cret');
    });

    it('should fall back gracefully when decryption fails (legacy support)', async () => {
      const obj = {
        host: 'legacy-plaintext-host',
        host_encrypted: {
          value: 'corruptedData',
          iv: 'iv1',
          authTag: 'tag1',
          version: 1,
        },
      };

      mockEncryptionService.decryptString.mockImplementation(() => {
        throw new Error('Decryption failed');
      });

      const result = await service.decryptFields(obj, ['host'], orgId);

      expect(result.host).toBe('legacy-plaintext-host');
    });
  });

  describe('hasEncryptedField', () => {
    it('should return true when encrypted field exists with a value', () => {
      const obj = {
        password_encrypted: {
          value: 'encPass',
          iv: 'iv',
          authTag: 'tag',
          version: 1,
        },
      };

      expect(service.hasEncryptedField(obj, 'password')).toBe(true);
    });

    it('should return false when no encrypted field exists', () => {
      const obj = { password: 'plaintext' };

      expect(service.hasEncryptedField(obj, 'password')).toBe(false);
    });
  });

  describe('getFieldValue', () => {
    it('should prefer encrypted value over plaintext', async () => {
      const obj = {
        password: 'old-plaintext',
        password_encrypted: {
          value: 'encPass',
          iv: 'iv',
          authTag: 'tag',
          version: 1,
        },
      };

      mockEncryptionService.decryptString.mockReturnValue('decrypted-secret');

      const result = await service.getFieldValue(obj, 'password', orgId);

      expect(result).toBe('decrypted-secret');
    });

    it('should fall back to plaintext when decryption fails', async () => {
      const obj = {
        password: 'legacy-plaintext',
        password_encrypted: {
          value: 'corruptedData',
          iv: 'iv',
          authTag: 'tag',
          version: 1,
        },
      };

      mockEncryptionService.decryptString.mockImplementation(() => {
        throw new Error('Decryption failed');
      });

      const result = await service.getFieldValue(obj, 'password', orgId);

      expect(result).toBe('legacy-plaintext');
    });
  });

  describe('isEncryptionAvailable', () => {
    it('should delegate to keyManagementService', () => {
      mockKeyManagementService.isEncryptionAvailable.mockReturnValue(true);

      expect(service.isEncryptionAvailable()).toBe(true);
      expect(mockKeyManagementService.isEncryptionAvailable).toHaveBeenCalled();
    });
  });
});
