import { Types } from 'mongoose';
import * as crypto from 'crypto';
import { KeyManagementService } from './key-management.service';
import { DirectKeyProvider } from '../providers/direct-key.provider';
import {
  KeyRotationValidationError,
  KeyVersionNotFoundError,
  ByokRegistrationValidationError,
} from '../errors/key-rotation.errors';
import {
  KmsConfig,
  RotateByokOptions,
} from '../interfaces/encryption.interface';

const ORG_ID = '507f1f77bcf86cd799439011';

function makeKeyRecord(overrides: Record<string, any> = {}) {
  return {
    _id: new Types.ObjectId(),
    organization_id: new Types.ObjectId(ORG_ID),
    encrypted_key: 'wrapped-key-hex',
    salt: crypto.randomBytes(32).toString('hex'),
    version: 1,
    key_type: 'managed',
    kms_config: null,
    customer_key_hash: null,
    rotated_at: null,
    ...overrides,
  };
}

function validHexKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

describe('KeyManagementService', () => {
  let service: KeyManagementService;
  let mockConfigService: { get: jest.Mock };
  let mockManagedProvider: { wrap: jest.Mock; unwrap: jest.Mock };
  let mockDirectProvider: {
    wrap: jest.Mock;
    unwrap: jest.Mock;
    cacheCustomerKey: jest.Mock;
    evictCustomerKey: jest.Mock;
    hasCustomerKey: jest.Mock;
  };
  let mockAwsKmsProvider: { wrap: jest.Mock; unwrap: jest.Mock };
  let mockGcpKmsProvider: { wrap: jest.Mock; unwrap: jest.Mock };
  let mockAzureKmsProvider: { wrap: jest.Mock; unwrap: jest.Mock };
  let mockEncryptionService: {
    encryptString: jest.Mock;
    decryptString: jest.Mock;
  };
  let mockOrgKeyModel: {
    findOne: jest.Mock;
    create: jest.Mock;
    updateOne: jest.Mock;
    countDocuments: jest.Mock;
    deleteOne: jest.Mock;
  };

  beforeEach(() => {
    mockConfigService = { get: jest.fn() };
    mockManagedProvider = {
      wrap: jest.fn().mockResolvedValue('managed-wrapped-key'),
      unwrap: jest.fn().mockResolvedValue(crypto.randomBytes(32)),
    };
    mockDirectProvider = {
      wrap: jest.fn().mockResolvedValue('direct-wrapped-key'),
      unwrap: jest.fn().mockResolvedValue(crypto.randomBytes(32)),
      cacheCustomerKey: jest.fn(),
      evictCustomerKey: jest.fn(),
      hasCustomerKey: jest.fn(),
    };
    mockAwsKmsProvider = {
      wrap: jest.fn().mockResolvedValue('aws-wrapped-key'),
      unwrap: jest.fn().mockResolvedValue(crypto.randomBytes(32)),
    };
    mockGcpKmsProvider = {
      wrap: jest.fn().mockResolvedValue('gcp-wrapped-key'),
      unwrap: jest.fn().mockResolvedValue(crypto.randomBytes(32)),
    };
    mockAzureKmsProvider = {
      wrap: jest.fn().mockResolvedValue('azure-wrapped-key'),
      unwrap: jest.fn().mockResolvedValue(crypto.randomBytes(32)),
    };
    mockEncryptionService = {
      encryptString: jest.fn((value: string) => ({
        value: Buffer.from(value).toString('base64'),
        iv: '00'.repeat(16),
        authTag: '00'.repeat(16),
      })),
      decryptString: jest.fn((encryptedValue: string) =>
        Buffer.from(encryptedValue, 'base64').toString('utf-8'),
      ),
    };
    mockOrgKeyModel = {
      findOne: jest.fn(),
      create: jest.fn(),
      updateOne: jest.fn(),
      countDocuments: jest.fn(),
      deleteOne: jest.fn(),
    };

    service = new KeyManagementService(
      mockConfigService as any,
      mockManagedProvider as any,
      mockDirectProvider as any,
      mockAwsKmsProvider as any,
      mockGcpKmsProvider as any,
      mockAzureKmsProvider as any,
      mockEncryptionService as any,
      mockOrgKeyModel as any,
    );
  });

  // ---------------------------------------------------------------
  // onModuleInit / isEncryptionAvailable
  // ---------------------------------------------------------------

  describe('onModuleInit / isEncryptionAvailable', () => {
    it('should set masterKeyConfigured to true when a valid 64-char hex key is provided', () => {
      mockConfigService.get.mockReturnValue(validHexKey());

      service.onModuleInit();

      expect(service.isEncryptionAvailable()).toBe(true);
    });

    it('should set masterKeyConfigured to false when no key is provided', () => {
      mockConfigService.get.mockReturnValue(undefined);

      service.onModuleInit();

      expect(service.isEncryptionAvailable()).toBe(false);
    });

    it('should set masterKeyConfigured to false when key has wrong length', () => {
      mockConfigService.get.mockReturnValue('abcdef1234'); // too short

      service.onModuleInit();

      expect(service.isEncryptionAvailable()).toBe(false);
    });
  });

  // ---------------------------------------------------------------
  // getOrganizationKey
  // ---------------------------------------------------------------

  describe('getOrganizationKey', () => {
    it('should return the unwrapped key when an existing record is found', async () => {
      const record = makeKeyRecord();
      const unwrappedKey = crypto.randomBytes(32);
      mockOrgKeyModel.findOne.mockResolvedValue(record);
      mockManagedProvider.unwrap.mockResolvedValue(unwrappedKey);

      const result = await service.getOrganizationKey(ORG_ID);

      expect(result).toBe(unwrappedKey);
      expect(mockManagedProvider.unwrap).toHaveBeenCalledWith(
        record.encrypted_key,
        expect.objectContaining({ organizationId: ORG_ID }),
      );
    });

    it('should create a new managed key when no record exists and master key is configured', async () => {
      mockConfigService.get.mockReturnValue(validHexKey());
      service.onModuleInit();

      mockOrgKeyModel.findOne.mockResolvedValue(null);
      mockManagedProvider.wrap.mockResolvedValue('new-wrapped-key');
      mockOrgKeyModel.create.mockResolvedValue({});

      const result = await service.getOrganizationKey(ORG_ID);

      expect(result).toBeInstanceOf(Buffer);
      expect(result).toHaveLength(32);
      expect(mockManagedProvider.wrap).toHaveBeenCalled();
      expect(mockOrgKeyModel.create).toHaveBeenCalledWith(
        expect.objectContaining({
          key_type: 'managed',
          version: 1,
        }),
      );
    });

    it('should throw when no record exists and master key is not configured', async () => {
      mockConfigService.get.mockReturnValue(undefined);
      service.onModuleInit();
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      await expect(service.getOrganizationKey(ORG_ID)).rejects.toThrow(
        'Encryption master key not configured',
      );
    });
  });

  // ---------------------------------------------------------------
  // getKeyVersion
  // ---------------------------------------------------------------

  describe('getKeyVersion', () => {
    it('should return the version from the record', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(makeKeyRecord({ version: 3 }));

      const version = await service.getKeyVersion(ORG_ID);

      expect(version).toBe(3);
    });

    it('should return 1 as default when no record exists', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      const version = await service.getKeyVersion(ORG_ID);

      expect(version).toBe(1);
    });
  });

  // ---------------------------------------------------------------
  // getKeyType
  // ---------------------------------------------------------------

  describe('getKeyType', () => {
    it('should return the key_type from the record', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({ key_type: 'direct' }),
      );

      const keyType = await service.getKeyType(ORG_ID);

      expect(keyType).toBe('direct');
    });

    it('should return managed as default when no record exists', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      const keyType = await service.getKeyType(ORG_ID);

      expect(keyType).toBe('managed');
    });
  });

  // ---------------------------------------------------------------
  // registerByokKey
  // ---------------------------------------------------------------

  describe('registerByokKey', () => {
    // Post-BYOK-032: register flow now includes pre-commit validation via
    // validateKeyBuffer. Mocks must prime the provider so wrap/unwrap
    // return roundtrip-consistent bytes.
    const primeProviderRoundtrip = (provider: {
      wrap: jest.Mock;
      unwrap: jest.Mock;
    }) => {
      let captured: Buffer | null = null;
      provider.wrap.mockImplementation((orgKey: Buffer) => {
        captured = orgKey;
        return Promise.resolve('wrapped-label');
      });
      provider.unwrap.mockImplementation(() => Promise.resolve(captured!));
    };

    it('should register a direct BYOK key: validate, cache, wrap, and store', async () => {
      primeProviderRoundtrip(mockDirectProvider);
      const customerKey = validHexKey();
      mockOrgKeyModel.findOne.mockResolvedValue(null);
      mockOrgKeyModel.create.mockResolvedValue({});

      const result = await service.registerByokKey(ORG_ID, {
        key_type: 'direct',
        customer_key: customerKey,
      });

      expect(result).toEqual({ version: 1, key_type: 'direct' });
      expect(mockDirectProvider.cacheCustomerKey).toHaveBeenCalledWith(
        ORG_ID,
        customerKey,
      );
      expect(mockDirectProvider.wrap).toHaveBeenCalled();
      expect(mockOrgKeyModel.create).toHaveBeenCalledWith(
        expect.objectContaining({
          key_type: 'direct',
          version: 1,
          customer_key_hash: expect.any(String),
        }),
      );
    });

    it('should throw if customer_key is missing for direct type', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      await expect(
        service.registerByokKey(ORG_ID, { key_type: 'direct' }),
      ).rejects.toThrow('Customer key is required for direct BYOK');
    });

    it('should throw if customer_key is not 64 hex characters', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      await expect(
        service.registerByokKey(ORG_ID, {
          key_type: 'direct',
          customer_key: 'abcdef',
        }),
      ).rejects.toThrow('Customer key must be 64 hex characters');
    });

    it('should throw if customer_key is not valid hex', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      // 64 chars but not hex (contains 'g')
      const invalidHex = 'g'.repeat(64);
      await expect(
        service.registerByokKey(ORG_ID, {
          key_type: 'direct',
          customer_key: invalidHex,
        }),
      ).rejects.toThrow('Customer key must be a valid hex string');
    });

    it('should register an AWS KMS key with valid config', async () => {
      primeProviderRoundtrip(mockAwsKmsProvider);
      mockOrgKeyModel.findOne.mockResolvedValue(null);
      mockOrgKeyModel.create.mockResolvedValue({});

      const result = await service.registerByokKey(ORG_ID, {
        key_type: 'aws-kms',
        kms_config: {
          provider: 'aws',
          key_id: 'arn:aws:kms:us-east-1:123456789:key/abc-123',
          region: 'us-east-1',
        },
      });

      expect(result).toEqual({ version: 1, key_type: 'aws-kms' });
      expect(mockAwsKmsProvider.wrap).toHaveBeenCalled();
      expect(mockOrgKeyModel.create).toHaveBeenCalledWith(
        expect.objectContaining({
          key_type: 'aws-kms',
          kms_config: expect.objectContaining({ provider: 'aws' }),
        }),
      );
    });

    it('should throw if organization already has a key', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(makeKeyRecord());

      await expect(
        service.registerByokKey(ORG_ID, {
          key_type: 'direct',
          customer_key: validHexKey(),
        }),
      ).rejects.toThrow('Organization already has an encryption key');
    });

    it('should throw for managed key_type', async () => {
      await expect(
        service.registerByokKey(ORG_ID, { key_type: 'managed' }),
      ).rejects.toThrow('Use standard key creation for managed keys');
    });
  });

  // ---------------------------------------------------------------
  // rotateByokKey
  // ---------------------------------------------------------------

  describe('rotateByokKey', () => {
    // Helper: make the named provider wrap/unwrap pair succeed roundtrip,
    // so validateKeyBuffer returns ok. Captures the in-memory orgKey from the
    // wrap call and returns it on the matching unwrap call.
    const primeHappyPathProvider = (
      provider: { wrap: jest.Mock; unwrap: jest.Mock },
      wrappedLabel: string,
    ) => {
      let capturedOrgKey: Buffer | null = null;
      provider.wrap.mockImplementation((orgKey: Buffer) => {
        capturedOrgKey = orgKey;
        return Promise.resolve(wrappedLabel);
      });
      provider.unwrap.mockImplementation(() =>
        Promise.resolve(capturedOrgKey!),
      );
    };

    describe('direct BYOK rotation (legacy signature)', () => {
      it('increments version, validates pipeline, caches customer key, promotes new wrapping', async () => {
        primeHappyPathProvider(mockDirectProvider, 'direct-new-wrapped');
        const existingRecord = makeKeyRecord({
          key_type: 'direct',
          version: 2,
          customer_key_hash: 'old-hash',
        });
        mockOrgKeyModel.findOne.mockResolvedValue(existingRecord);
        mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

        const newCustomerKey = validHexKey();
        const newVersion = await service.rotateByokKey(ORG_ID, newCustomerKey);

        expect(newVersion).toBe(3);
        expect(mockDirectProvider.cacheCustomerKey).toHaveBeenCalledWith(
          ORG_ID,
          newCustomerKey,
        );
        expect(mockDirectProvider.wrap).toHaveBeenCalledTimes(1);
        expect(mockDirectProvider.unwrap).toHaveBeenCalledTimes(1); // validateKeyBuffer

        const updateCall = mockOrgKeyModel.updateOne.mock.calls[0][1];
        expect(updateCall.$set.version).toBe(3);
        expect(updateCall.$set.key_type).toBe('direct');
        expect(updateCall.$set.encrypted_key).toBe('direct-new-wrapped');
        expect(updateCall.$set.last_pipeline_validation).toEqual({
          validated_at: expect.any(Date),
          ok: true,
        });
      });

      it('evicts the new customer key cache and aborts DB update when validation fails', async () => {
        // Wrap succeeds but unwrap returns wrong bytes → validation fails.
        // DirectKeyProvider.wrap needs the customer key cached to derive the
        // KEK, so the cache IS populated during the wrap phase. The failure
        // path must evict it so the stale key does not linger in memory
        // against a stored hash it no longer matches.
        mockDirectProvider.wrap.mockResolvedValue('direct-new-wrapped');
        mockDirectProvider.unwrap.mockResolvedValue(crypto.randomBytes(32));
        mockOrgKeyModel.findOne.mockResolvedValue(
          makeKeyRecord({
            key_type: 'direct',
            version: 2,
            customer_key_hash: 'old-hash',
          }),
        );

        const newCustomerKey = validHexKey();

        await expect(
          service.rotateByokKey(ORG_ID, newCustomerKey),
        ).rejects.toBeInstanceOf(KeyRotationValidationError);

        expect(mockDirectProvider.cacheCustomerKey).toHaveBeenCalledWith(
          ORG_ID,
          newCustomerKey,
        );
        expect(mockDirectProvider.evictCustomerKey).toHaveBeenCalledWith(
          ORG_ID,
        );
        expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
      });

      it('throws if direct BYOK and no newCustomerKey provided', async () => {
        mockOrgKeyModel.findOne.mockResolvedValue(
          makeKeyRecord({ key_type: 'direct' }),
        );

        await expect(service.rotateByokKey(ORG_ID)).rejects.toThrow(
          'New customer key is required for direct BYOK rotation',
        );
      });

      it('throws if no existing record found', async () => {
        mockOrgKeyModel.findOne.mockResolvedValue(null);

        await expect(service.rotateByokKey(ORG_ID)).rejects.toThrow(
          `No encryption key found for organization: ${ORG_ID}`,
        );
      });
    });

    describe('aws-kms BYOK rotation (same provider)', () => {
      it('rotates in place, pushes prior version to key_history with aws-kms metadata', async () => {
        primeHappyPathProvider(mockAwsKmsProvider, 'aws-new-wrapped');
        const kmsConfig = {
          provider: 'aws',
          key_id: 'arn:aws:kms:us-east-1:123:key/abc',
          region: 'us-east-1',
        };
        const existingRecord = makeKeyRecord({
          key_type: 'aws-kms',
          version: 2,
          kms_config: kmsConfig,
        });
        mockOrgKeyModel.findOne.mockResolvedValue(existingRecord);
        mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

        const newVersion = await service.rotateByokKey(ORG_ID);

        expect(newVersion).toBe(3);

        const updateCall = mockOrgKeyModel.updateOne.mock.calls[0][1];
        expect(updateCall.$push.key_history.$each[0]).toEqual({
          version: 2,
          encrypted_key: existingRecord.encrypted_key,
          salt: existingRecord.salt,
          key_type: 'aws-kms',
          kms_config: kmsConfig,
          rotated_at: expect.any(Date),
        });
        expect(updateCall.$push.key_history.$slice).toBe(3);
        expect(updateCall.$push.key_history.$position).toBe(0);
        expect(updateCall.$set.key_type).toBe('aws-kms');
        expect(updateCall.$set.encrypted_key).toBe('aws-new-wrapped');
      });
    });

    describe('provider switch (aws-kms → gcp-kms style via options)', () => {
      beforeEach(() => {
        // Provide gcp-kms via a dedicated mock because the service's
        // getProvider switch for gcp-kms still throws today; BYOK-024 wires
        // it up. We sidestep that by injecting our mock at the Map level.
        const mockGcpProvider = {
          wrap: jest.fn(),
          unwrap: jest.fn(),
        };
        primeHappyPathProvider(mockGcpProvider as any, 'gcp-new-wrapped');

        // Override getProvider for this test block to return our mock for
        // gcp-kms. This is a test-only hack — BYOK-024 makes it unnecessary.
        const originalGetProvider = (service as any).getProvider.bind(service);
        jest
          .spyOn(service as any, 'getProvider')
          .mockImplementation((keyType: any) => {
            if (keyType === 'gcp-kms') return mockGcpProvider;
            return originalGetProvider(keyType);
          });
      });

      afterEach(() => {
        jest.restoreAllMocks();
      });

      it('accepts targetKeyType option and promotes the new provider while preserving old history', async () => {
        const oldKmsConfig: KmsConfig = {
          provider: 'aws',
          key_id: 'arn:aws:kms:us-east-1:123:key/abc',
          region: 'us-east-1',
        };
        const newKmsConfig: KmsConfig = {
          provider: 'gcp',
          key_id: 'projects/test/locations/us-east1/keyRings/r/cryptoKeys/k',
        };
        const existingRecord = makeKeyRecord({
          key_type: 'aws-kms',
          version: 2,
          kms_config: oldKmsConfig,
        });
        mockOrgKeyModel.findOne.mockResolvedValue(existingRecord);
        mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

        const switchOptions: RotateByokOptions = {
          targetKeyType: 'gcp-kms',
          targetKmsConfig: newKmsConfig,
        };
        const newVersion = await service.rotateByokKey(ORG_ID, switchOptions);

        expect(newVersion).toBe(3);

        const updateCall = mockOrgKeyModel.updateOne.mock.calls[0][1];
        // History preserves the OLD aws-kms config (BYOK-013 unwrap lookup)
        expect(updateCall.$push.key_history.$each[0]).toEqual({
          version: 2,
          encrypted_key: existingRecord.encrypted_key,
          salt: existingRecord.salt,
          key_type: 'aws-kms',
          kms_config: oldKmsConfig,
          rotated_at: expect.any(Date),
        });
        // Current state is promoted to gcp-kms
        expect(updateCall.$set.key_type).toBe('gcp-kms');
        expect(updateCall.$set.kms_config).toEqual(newKmsConfig);
        expect(updateCall.$set.encrypted_key).toBe('gcp-new-wrapped');
      });
    });

    describe('options validation', () => {
      it('throws if targetKeyType is a KMS type but targetKmsConfig is missing', async () => {
        mockOrgKeyModel.findOne.mockResolvedValue(
          makeKeyRecord({ key_type: 'aws-kms' }),
        );

        const opts: RotateByokOptions = { targetKeyType: 'azure-kms' };
        await expect(service.rotateByokKey(ORG_ID, opts)).rejects.toThrow(
          /KMS config is required/i,
        );

        expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
      });

      it('throws if targetKeyType is direct but newCustomerKey is missing', async () => {
        mockOrgKeyModel.findOne.mockResolvedValue(
          makeKeyRecord({ key_type: 'aws-kms' }),
        );

        const opts: RotateByokOptions = { targetKeyType: 'direct' };
        await expect(service.rotateByokKey(ORG_ID, opts)).rejects.toThrow(
          /customer key is required/i,
        );

        expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
      });
    });
  });

  // ---------------------------------------------------------------
  // revokeByokKey
  // ---------------------------------------------------------------

  describe('revokeByokKey', () => {
    it('should unwrap with current provider and re-wrap with managed provider', async () => {
      const orgKey = crypto.randomBytes(32);
      const existingRecord = makeKeyRecord({ key_type: 'direct', version: 2 });
      mockOrgKeyModel.findOne.mockResolvedValue(existingRecord);
      mockDirectProvider.unwrap.mockResolvedValue(orgKey);
      mockManagedProvider.wrap.mockResolvedValue('managed-re-wrapped');
      mockOrgKeyModel.updateOne.mockResolvedValue({});

      // Must configure master key for revoke to succeed
      mockConfigService.get.mockReturnValue(validHexKey());
      service.onModuleInit();

      await service.revokeByokKey(ORG_ID);

      expect(mockDirectProvider.unwrap).toHaveBeenCalledWith(
        existingRecord.encrypted_key,
        expect.objectContaining({ organizationId: ORG_ID }),
      );
      expect(mockManagedProvider.wrap).toHaveBeenCalledWith(
        orgKey,
        expect.objectContaining({ organizationId: ORG_ID }),
      );
      expect(mockOrgKeyModel.updateOne).toHaveBeenCalledWith(
        { _id: existingRecord._id },
        expect.objectContaining({
          key_type: 'managed',
          kms_config: null,
          customer_key_hash: null,
          version: 3,
        }),
      );
      expect(mockDirectProvider.evictCustomerKey).toHaveBeenCalledWith(ORG_ID);
    });

    it('should throw if the organization is already using managed encryption', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({ key_type: 'managed' }),
      );

      await expect(service.revokeByokKey(ORG_ID)).rejects.toThrow(
        'Organization is already using managed encryption',
      );
    });

    it('should throw if no record exists', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      await expect(service.revokeByokKey(ORG_ID)).rejects.toThrow(
        `No encryption key found for organization: ${ORG_ID}`,
      );
    });
  });

  // ---------------------------------------------------------------
  // validateCustomerKey
  // ---------------------------------------------------------------

  describe('validateCustomerKey', () => {
    it('should return true when the hash matches', async () => {
      const customerKey = validHexKey();
      const hash = DirectKeyProvider.hashCustomerKey(customerKey);
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          key_type: 'direct',
          customer_key_hash: hash,
        }),
      );

      const result = await service.validateCustomerKey(ORG_ID, customerKey);

      expect(result).toBe(true);
    });

    it('should return false when the hash does not match', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          key_type: 'direct',
          customer_key_hash: 'wrong-hash-value',
        }),
      );

      const result = await service.validateCustomerKey(ORG_ID, validHexKey());

      expect(result).toBe(false);
    });

    it('should return false when no record exists or type is not direct', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      expect(await service.validateCustomerKey(ORG_ID, validHexKey())).toBe(
        false,
      );

      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({ key_type: 'managed' }),
      );

      expect(await service.validateCustomerKey(ORG_ID, validHexKey())).toBe(
        false,
      );
    });
  });

  // ---------------------------------------------------------------
  // getProvider / getByokStatus
  // ---------------------------------------------------------------

  describe('getProvider / getByokStatus', () => {
    it('should return the correct provider for each supported key type', async () => {
      // Prime the AWS KMS provider for roundtrip so registerByokKey's
      // pre-commit validation succeeds.
      let captured: Buffer | null = null;
      mockAwsKmsProvider.wrap.mockImplementation((orgKey: Buffer) => {
        captured = orgKey;
        return Promise.resolve('aws-wrapped');
      });
      mockAwsKmsProvider.unwrap.mockImplementation(() =>
        Promise.resolve(captured!),
      );

      mockOrgKeyModel.findOne.mockResolvedValue(null);
      mockOrgKeyModel.create.mockResolvedValue({});

      await service.registerByokKey(ORG_ID, {
        key_type: 'aws-kms',
        kms_config: {
          provider: 'aws',
          key_id: 'arn:test',
          region: 'us-east-1',
        },
      });

      expect(mockAwsKmsProvider.wrap).toHaveBeenCalled();
      expect(mockDirectProvider.wrap).not.toHaveBeenCalled();
      expect(mockManagedProvider.wrap).not.toHaveBeenCalled();
    });

    it.skip('SKIPPED (BYOK-024): gcp-kms and azure-kms are now implemented', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      await expect(
        service.registerByokKey(ORG_ID, {
          key_type: 'gcp-kms',
          kms_config: { provider: 'gcp', key_id: 'projects/test' },
        }),
      ).rejects.toThrow('gcp-kms provider not yet implemented');

      await expect(
        service.registerByokKey(ORG_ID, {
          key_type: 'azure-kms',
          kms_config: { provider: 'azure', key_id: 'https://vault.test' },
        }),
      ).rejects.toThrow('azure-kms provider not yet implemented');
    });

    it('should return default ByokStatus when no record exists', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      const status = await service.getByokStatus(ORG_ID);

      expect(status).toEqual({
        key_type: 'managed',
        is_byok: false,
        key_version: 0,
      });
    });

    it('should return full ByokStatus when a BYOK record exists', async () => {
      const rotatedAt = new Date('2026-01-15');
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          key_type: 'direct',
          version: 3,
          customer_key_hash: 'abc123',
          rotated_at: rotatedAt,
        }),
      );

      const status = await service.getByokStatus(ORG_ID);

      expect(status).toEqual({
        key_type: 'direct',
        is_byok: true,
        kms_config: null,
        customer_key_hash: 'abc123',
        key_version: 3,
        rotated_at: rotatedAt,
      });
    });
  });

  // BYOK-030: validateKeyBuffer — pure in-memory key pipeline validation
  // used by two-phase rotation (BYOK-011, BYOK-012) and register rollback
  // (BYOK-032). Must never throw; always returns a structured result.
  describe('validateKeyBuffer', () => {
    const buildProvider = (unwrapReturn: Buffer | Error) => ({
      wrap: jest.fn(),
      unwrap:
        unwrapReturn instanceof Error
          ? jest.fn().mockRejectedValue(unwrapReturn)
          : jest.fn().mockResolvedValue(unwrapReturn),
    });

    const buildContext = () => ({
      organizationId: ORG_ID,
      salt: crypto.randomBytes(32),
    });

    it('returns ok:true on a successful wrap/unwrap + cipher roundtrip', async () => {
      const orgKey = crypto.randomBytes(32);
      // Provider unwrap returns the exact same buffer → match
      const provider = buildProvider(orgKey);

      const result = await service.validateKeyBuffer(
        orgKey,
        'wrapped-key',
        provider as any,
        buildContext() as any,
      );

      expect(result.ok).toBe(true);
      expect(result.error).toBeUndefined();
      expect(typeof result.duration_ms).toBe('number');
      expect(result.duration_ms).toBeGreaterThanOrEqual(0);
      expect(provider.unwrap).toHaveBeenCalledWith(
        'wrapped-key',
        expect.any(Object),
      );
    });

    it('returns ok:false with unwrap mismatch error when provider returns wrong bytes', async () => {
      const orgKey = crypto.randomBytes(32);
      const wrongKey = crypto.randomBytes(32);
      const provider = buildProvider(wrongKey);

      const result = await service.validateKeyBuffer(
        orgKey,
        'wrapped-key',
        provider as any,
        buildContext() as any,
      );

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/unwrap roundtrip mismatch/i);
      expect(typeof result.duration_ms).toBe('number');
    });

    it('returns ok:false when provider.unwrap throws', async () => {
      const orgKey = crypto.randomBytes(32);
      const provider = buildProvider(new Error('KMS unreachable'));

      const result = await service.validateKeyBuffer(
        orgKey,
        'wrapped-key',
        provider as any,
        buildContext() as any,
      );

      expect(result.ok).toBe(false);
      expect(result.error).toContain('KMS unreachable');
      expect(typeof result.duration_ms).toBe('number');
    });

    it('returns ok:false when cipher roundtrip fails (decrypt returns wrong bytes)', async () => {
      const orgKey = crypto.randomBytes(32);
      const provider = buildProvider(orgKey);

      mockEncryptionService.decryptString.mockReturnValueOnce('tampered');

      const result = await service.validateKeyBuffer(
        orgKey,
        'wrapped-key',
        provider as any,
        buildContext() as any,
      );

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/cipher roundtrip failed/i);
    });

    it('returns ok:false when encryptString throws', async () => {
      const orgKey = crypto.randomBytes(32);
      const provider = buildProvider(orgKey);

      mockEncryptionService.encryptString.mockImplementationOnce(() => {
        throw new Error('cipher error');
      });

      const result = await service.validateKeyBuffer(
        orgKey,
        'wrapped-key',
        provider as any,
        buildContext() as any,
      );

      expect(result.ok).toBe(false);
      expect(result.error).toContain('cipher error');
    });

    it('never reads from the database', async () => {
      const orgKey = crypto.randomBytes(32);
      const provider = buildProvider(orgKey);

      await service.validateKeyBuffer(
        orgKey,
        'wrapped-key',
        provider as any,
        buildContext() as any,
      );

      expect(mockOrgKeyModel.findOne).not.toHaveBeenCalled();
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
      expect(mockOrgKeyModel.create).not.toHaveBeenCalled();
    });

    it('passes the provided wrappedKey and context through to provider.unwrap', async () => {
      const orgKey = crypto.randomBytes(32);
      const provider = buildProvider(orgKey);
      const ctx = buildContext();

      await service.validateKeyBuffer(
        orgKey,
        'specific-wrapped-payload',
        provider as any,
        ctx as any,
      );

      expect(provider.unwrap).toHaveBeenCalledWith(
        'specific-wrapped-payload',
        ctx,
      );
    });
  });

  // BYOK-011: Two-phase commit for rotateOrganizationKey (managed keys).
  // Wrap → validateKeyBuffer → push current to key_history → promote.
  describe('rotateOrganizationKey (two-phase commit)', () => {
    // Make validateKeyBuffer succeed by having the managed provider's unwrap
    // return the exact bytes that were just wrapped.
    const setupHappyPathProvider = () => {
      let capturedOrgKey: Buffer | null = null;
      mockManagedProvider.wrap.mockImplementation((orgKey: Buffer) => {
        capturedOrgKey = orgKey;
        return Promise.resolve('new-managed-wrapped');
      });
      mockManagedProvider.unwrap.mockImplementation(() =>
        Promise.resolve(capturedOrgKey!),
      );
    };

    const existingManagedRecord = () =>
      makeKeyRecord({
        key_type: 'managed',
        version: 2,
        encrypted_key: 'old-wrapped',
        salt: 'old-salt',
        rotated_at: new Date('2026-01-01'),
      });

    beforeEach(() => {
      // Bypass master key config check (covered by dedicated tests elsewhere)
      (service as any).masterKeyConfigured = true;
    });

    it('rotates successfully with two-phase commit: wrap → validate → push history → promote', async () => {
      setupHappyPathProvider();
      mockOrgKeyModel.findOne.mockResolvedValue(existingManagedRecord());
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const newVersion = await service.rotateOrganizationKey(ORG_ID);

      expect(newVersion).toBe(3);
      expect(mockManagedProvider.wrap).toHaveBeenCalledTimes(1);
      expect(mockManagedProvider.unwrap).toHaveBeenCalledTimes(1); // validateKeyBuffer
      expect(mockOrgKeyModel.updateOne).toHaveBeenCalledTimes(1);
    });

    it('pushes the prior version to key_history with the correct shape', async () => {
      setupHappyPathProvider();
      const prior = existingManagedRecord();
      mockOrgKeyModel.findOne.mockResolvedValue(prior);
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      await service.rotateOrganizationKey(ORG_ID);

      const updateCall = mockOrgKeyModel.updateOne.mock.calls[0][1];
      expect(updateCall.$push).toBeDefined();
      expect(updateCall.$push.key_history).toBeDefined();
      expect(updateCall.$push.key_history.$each).toHaveLength(1);

      const historyEntry = updateCall.$push.key_history.$each[0];
      expect(historyEntry).toEqual({
        version: prior.version,
        encrypted_key: prior.encrypted_key,
        salt: prior.salt,
        key_type: prior.key_type,
        kms_config: prior.kms_config,
        rotated_at: expect.any(Date),
      });
    });

    it('trims key_history via $slice using BYOK_KEY_HISTORY_RETENTION (default 3)', async () => {
      setupHappyPathProvider();
      mockOrgKeyModel.findOne.mockResolvedValue(existingManagedRecord());
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      await service.rotateOrganizationKey(ORG_ID);

      const updateCall = mockOrgKeyModel.updateOne.mock.calls[0][1];
      expect(updateCall.$push.key_history.$slice).toBe(3);
      expect(updateCall.$push.key_history.$position).toBe(0);
    });

    it('respects BYOK_KEY_HISTORY_RETENTION env override', async () => {
      mockConfigService.get.mockImplementation(
        (key: string, defaultValue?: number) => {
          if (key === 'BYOK_KEY_HISTORY_RETENTION') return 5;
          return defaultValue;
        },
      );
      setupHappyPathProvider();
      mockOrgKeyModel.findOne.mockResolvedValue(existingManagedRecord());
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      await service.rotateOrganizationKey(ORG_ID);

      const updateCall = mockOrgKeyModel.updateOne.mock.calls[0][1];
      expect(updateCall.$push.key_history.$slice).toBe(5);
    });

    it('sets last_pipeline_validation and clears last_rotation_error on promote', async () => {
      setupHappyPathProvider();
      mockOrgKeyModel.findOne.mockResolvedValue(existingManagedRecord());
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      await service.rotateOrganizationKey(ORG_ID);

      const updateCall = mockOrgKeyModel.updateOne.mock.calls[0][1];
      expect(updateCall.$set.last_pipeline_validation).toEqual({
        validated_at: expect.any(Date),
        ok: true,
      });
      expect(updateCall.$set.last_rotation_error).toBeNull();
      expect(updateCall.$set.encrypted_key).toBe('new-managed-wrapped');
      expect(updateCall.$set.version).toBe(3);
    });

    it('aborts rotation and leaves DB untouched when validateKeyBuffer fails (unwrap mismatch)', async () => {
      // Wrap returns a new key, but unwrap returns DIFFERENT bytes → mismatch
      mockManagedProvider.wrap.mockResolvedValue('new-wrapped');
      mockManagedProvider.unwrap.mockResolvedValue(crypto.randomBytes(32));
      mockOrgKeyModel.findOne.mockResolvedValue(existingManagedRecord());

      await expect(
        service.rotateOrganizationKey(ORG_ID),
      ).rejects.toBeInstanceOf(KeyRotationValidationError);

      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });

    it('aborts rotation when the provider throws during wrap', async () => {
      mockManagedProvider.wrap.mockRejectedValue(new Error('KMS unreachable'));
      mockOrgKeyModel.findOne.mockResolvedValue(existingManagedRecord());

      await expect(service.rotateOrganizationKey(ORG_ID)).rejects.toThrow();
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });

    it('throws if no existing record is found', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      await expect(service.rotateOrganizationKey(ORG_ID)).rejects.toThrow(
        `No encryption key found for organization: ${ORG_ID}`,
      );
    });

    it('throws if key_type is not managed', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({ key_type: 'aws-kms' }),
      );

      await expect(service.rotateOrganizationKey(ORG_ID)).rejects.toThrow(
        'Use rotateByokKey for BYOK keys',
      );
    });

    it('throws if master key is not configured', async () => {
      (service as any).masterKeyConfigured = false;
      mockOrgKeyModel.findOne.mockResolvedValue(existingManagedRecord());

      await expect(service.rotateOrganizationKey(ORG_ID)).rejects.toThrow(
        'Encryption master key not configured',
      );
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });
  });

  // BYOK-013: Version-aware key lookup for restoring backups encrypted
  // with a prior key version.
  describe('getOrganizationKey with version parameter', () => {
    const currentOrgKey = crypto.randomBytes(32);
    const historicalOrgKey = crypto.randomBytes(32);

    const recordWithHistory = () => ({
      ...makeKeyRecord({
        key_type: 'managed',
        version: 4,
        encrypted_key: 'current-wrapped',
        salt: 'current-salt-hex',
        kms_config: null,
      }),
      key_history: [
        {
          version: 3,
          encrypted_key: 'v3-wrapped',
          salt: 'v3-salt-hex',
          key_type: 'managed',
          kms_config: null,
          rotated_at: new Date('2026-03-01'),
        },
        {
          version: 2,
          encrypted_key: 'v2-wrapped',
          salt: 'v2-salt-hex',
          key_type: 'aws-kms',
          kms_config: {
            provider: 'aws',
            key_id: 'arn:aws:kms:us-east-1:123:key/v2',
            region: 'us-east-1',
          },
          rotated_at: new Date('2026-02-01'),
        },
        {
          version: 1,
          encrypted_key: 'v1-wrapped',
          salt: 'v1-salt-hex',
          key_type: 'managed',
          kms_config: null,
          rotated_at: new Date('2026-01-01'),
        },
      ],
    });

    beforeEach(() => {
      (service as any).masterKeyConfigured = true;
    });

    it('returns the current key when no version is provided (backward compatible)', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());
      mockManagedProvider.unwrap.mockResolvedValue(currentOrgKey);

      const result = await service.getOrganizationKey(ORG_ID);

      expect(result.equals(currentOrgKey)).toBe(true);
      expect(mockManagedProvider.unwrap).toHaveBeenCalledWith(
        'current-wrapped',
        expect.objectContaining({
          organizationId: expect.any(String),
        }),
      );
    });

    it('returns the current key when version matches the current record version', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());
      mockManagedProvider.unwrap.mockResolvedValue(currentOrgKey);

      const result = await service.getOrganizationKey(ORG_ID, 4);

      expect(result.equals(currentOrgKey)).toBe(true);
      expect(mockManagedProvider.unwrap).toHaveBeenCalledWith(
        'current-wrapped',
        expect.any(Object),
      );
    });

    it('unwraps a managed historical version (v3) with its stored salt', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());
      mockManagedProvider.unwrap.mockResolvedValue(historicalOrgKey);

      const result = await service.getOrganizationKey(ORG_ID, 3);

      expect(result.equals(historicalOrgKey)).toBe(true);
      expect(mockManagedProvider.unwrap).toHaveBeenCalledWith(
        'v3-wrapped',
        expect.objectContaining({
          salt: Buffer.from('v3-salt-hex', 'hex'),
        }),
      );
    });

    it('unwraps an aws-kms historical version (v2) with its stored kms_config', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());
      mockAwsKmsProvider.unwrap.mockResolvedValue(historicalOrgKey);

      const result = await service.getOrganizationKey(ORG_ID, 2);

      expect(result.equals(historicalOrgKey)).toBe(true);
      expect(mockAwsKmsProvider.unwrap).toHaveBeenCalledWith(
        'v2-wrapped',
        expect.objectContaining({
          kmsConfig: {
            provider: 'aws',
            key_id: 'arn:aws:kms:us-east-1:123:key/v2',
            region: 'us-east-1',
          },
        }),
      );
      // The managed provider should NOT be invoked for an aws-kms historical entry
      expect(mockManagedProvider.unwrap).not.toHaveBeenCalled();
    });

    it('unwraps the oldest retained version (v1)', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());
      mockManagedProvider.unwrap.mockResolvedValue(historicalOrgKey);

      const result = await service.getOrganizationKey(ORG_ID, 1);

      expect(result.equals(historicalOrgKey)).toBe(true);
      expect(mockManagedProvider.unwrap).toHaveBeenCalledWith(
        'v1-wrapped',
        expect.any(Object),
      );
    });

    it('throws KeyVersionNotFoundError when the requested version is absent', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());

      await expect(
        service.getOrganizationKey(ORG_ID, 99),
      ).rejects.toBeInstanceOf(KeyVersionNotFoundError);
    });

    it('KeyVersionNotFoundError carries the available versions in the message', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());

      try {
        await service.getOrganizationKey(ORG_ID, 99);
        fail('expected throw');
      } catch (err) {
        expect(err).toBeInstanceOf(KeyVersionNotFoundError);
        const typed = err as KeyVersionNotFoundError;
        expect(typed.requestedVersion).toBe(99);
        expect(typed.availableVersions).toEqual(
          expect.arrayContaining([4, 3, 2, 1]),
        );
        expect(typed.message).toContain('99');
        expect(typed.message).toContain(ORG_ID);
      }
    });

    it('throws KeyVersionNotFoundError when requested version is older than oldest retained', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());

      await expect(
        service.getOrganizationKey(ORG_ID, 0),
      ).rejects.toBeInstanceOf(KeyVersionNotFoundError);
    });

    it('returns the current key when version is undefined explicitly', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(recordWithHistory());
      mockManagedProvider.unwrap.mockResolvedValue(currentOrgKey);

      const result = await service.getOrganizationKey(ORG_ID, undefined);

      expect(result.equals(currentOrgKey)).toBe(true);
    });
  });

  // BYOK-031: Public validatePipeline(orgId) — loads the current key
  // and delegates to validateKeyBuffer. Persists the result on the record.
  describe('validatePipeline (public entry point)', () => {
    const setupHappyPath = (orgKey: Buffer) => {
      mockManagedProvider.wrap.mockImplementation(() =>
        Promise.resolve('current-wrapped'),
      );
      // First call (inside getOrganizationKey) returns the orgKey, and
      // validateKeyBuffer's second call (in the helper) also returns the
      // orgKey to satisfy the unwrap-roundtrip equality check.
      mockManagedProvider.unwrap.mockResolvedValue(orgKey);
    };

    beforeEach(() => {
      (service as any).masterKeyConfigured = true;
    });

    it('returns ok:true and persists last_pipeline_validation on success', async () => {
      const orgKey = crypto.randomBytes(32);
      setupHappyPath(orgKey);
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          key_type: 'managed',
          encrypted_key: 'current-wrapped',
        }),
      );
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await service.validatePipeline(ORG_ID);

      expect(result.ok).toBe(true);
      expect(result.duration_ms).toBeGreaterThanOrEqual(0);
      // Persisted last_pipeline_validation on the record
      const persistCall = mockOrgKeyModel.updateOne.mock.calls.find(
        (c) => c[1]?.$set?.last_pipeline_validation,
      );
      expect(persistCall).toBeDefined();
      expect(persistCall![1].$set.last_pipeline_validation).toEqual({
        validated_at: expect.any(Date),
        ok: true,
      });
    });

    it('returns ok:false when the organization has no key record', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      const result = await service.validatePipeline(ORG_ID);

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/not found|no key/i);
      expect(result.duration_ms).toBe(0);
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });

    it('returns ok:false AND persists the failure when validateKeyBuffer fails', async () => {
      // Unwrap returns bytes that do not match what validateKeyBuffer
      // expects — simulates provider drift
      const orgKey = crypto.randomBytes(32);
      mockManagedProvider.unwrap
        .mockResolvedValueOnce(orgKey) // getOrganizationKey uses this
        .mockResolvedValueOnce(crypto.randomBytes(32)); // validateKeyBuffer
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          key_type: 'managed',
          encrypted_key: 'current-wrapped',
        }),
      );
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await service.validatePipeline(ORG_ID);

      expect(result.ok).toBe(false);
      expect(result.error).toMatch(/unwrap roundtrip mismatch/i);

      // Failure is persisted so the dashboard can display "last validated
      // X ago with error Y"
      const persistCall = mockOrgKeyModel.updateOne.mock.calls.find(
        (c) => c[1]?.$set?.last_pipeline_validation,
      );
      expect(persistCall).toBeDefined();
      expect(persistCall![1].$set.last_pipeline_validation.ok).toBe(false);
      expect(persistCall![1].$set.last_pipeline_validation.error).toMatch(
        /unwrap roundtrip mismatch/i,
      );
    });
  });

  // BYOK-032: registerByokKey performs pre-commit pipeline validation via
  // validateKeyBuffer (in-memory, no DB read). Failure aborts BEFORE the
  // create() call so there's nothing to roll back — the test asserts that
  // create is NEVER called on the failure path.
  describe('registerByokKey pre-commit validation', () => {
    beforeEach(() => {
      (service as any).masterKeyConfigured = true;
    });

    it('aborts registration and never calls create when validation fails (KMS)', async () => {
      // Wrap returns a label, but unwrap returns bytes that do NOT match
      // the orgKey just generated → validateKeyBuffer returns ok: false
      mockOrgKeyModel.findOne.mockResolvedValue(null);
      mockAwsKmsProvider.wrap.mockResolvedValue('aws-wrapped');
      mockAwsKmsProvider.unwrap.mockResolvedValue(crypto.randomBytes(32));

      await expect(
        service.registerByokKey(ORG_ID, {
          key_type: 'aws-kms',
          kms_config: {
            provider: 'aws',
            key_id: 'arn:aws:kms:us-east-1:123:key/abc',
            region: 'us-east-1',
          },
        }),
      ).rejects.toBeInstanceOf(ByokRegistrationValidationError);

      expect(mockOrgKeyModel.create).not.toHaveBeenCalled();
      expect(mockOrgKeyModel.deleteOne).not.toHaveBeenCalled();
    });

    it('evicts cached customer key on validation failure for direct type', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);
      mockDirectProvider.wrap.mockResolvedValue('direct-wrapped');
      mockDirectProvider.unwrap.mockResolvedValue(crypto.randomBytes(32));

      const customerKey = validHexKey();

      await expect(
        service.registerByokKey(ORG_ID, {
          key_type: 'direct',
          customer_key: customerKey,
        }),
      ).rejects.toBeInstanceOf(ByokRegistrationValidationError);

      // Cache was populated (required for wrap), then evicted on failure
      expect(mockDirectProvider.cacheCustomerKey).toHaveBeenCalledWith(
        ORG_ID,
        customerKey,
      );
      expect(mockDirectProvider.evictCustomerKey).toHaveBeenCalledWith(ORG_ID);
      expect(mockOrgKeyModel.create).not.toHaveBeenCalled();
    });

    it('succeeds and persists last_pipeline_validation on the created document', async () => {
      // Prime the provider for a valid roundtrip
      let capturedKey: Buffer | null = null;
      mockAwsKmsProvider.wrap.mockImplementation((orgKey: Buffer) => {
        capturedKey = orgKey;
        return Promise.resolve('aws-wrapped');
      });
      mockAwsKmsProvider.unwrap.mockImplementation(() =>
        Promise.resolve(capturedKey!),
      );
      mockOrgKeyModel.findOne.mockResolvedValue(null);
      mockOrgKeyModel.create.mockResolvedValue({} as any);

      const result = await service.registerByokKey(ORG_ID, {
        key_type: 'aws-kms',
        kms_config: {
          provider: 'aws',
          key_id: 'arn:aws:kms:us-east-1:123:key/abc',
          region: 'us-east-1',
        },
      });

      expect(result).toEqual({ version: 1, key_type: 'aws-kms' });
      expect(mockOrgKeyModel.create).toHaveBeenCalledWith(
        expect.objectContaining({
          key_type: 'aws-kms',
          last_pipeline_validation: expect.objectContaining({
            ok: true,
            validated_at: expect.any(Date),
          }),
        }),
      );
      expect(mockOrgKeyModel.deleteOne).not.toHaveBeenCalled();
    });
  });

  // BYOK-070: rotation policy read/write
  describe('getRotationPolicy', () => {
    it('returns null when the org has no encryption key', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      const result = await service.getRotationPolicy(ORG_ID);
      expect(result).toBeNull();
    });

    it('returns the full policy snapshot with computed next_rotation_at', async () => {
      const rotatedAt = new Date('2026-01-01T00:00:00Z');
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          auto_rotate: true,
          rotation_interval_days: 90,
          restore_drill_enabled: false,
          rotated_at: rotatedAt,
          last_rotation_error: null,
        }),
      );

      const result = await service.getRotationPolicy(ORG_ID);

      expect(result).not.toBeNull();
      expect(result!.auto_rotate).toBe(true);
      expect(result!.rotation_interval_days).toBe(90);
      expect(result!.restore_drill_enabled).toBe(false);

      const expectedNext = new Date(
        rotatedAt.getTime() + 90 * 24 * 60 * 60 * 1000,
      );
      expect(result!.next_rotation_at?.getTime()).toBe(expectedNext.getTime());
    });

    it('falls back to createdAt when rotated_at is null', async () => {
      const createdAt = new Date('2026-02-15T00:00:00Z');
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotated_at: null,
          createdAt,
          rotation_interval_days: 60,
        }),
      );

      const result = await service.getRotationPolicy(ORG_ID);
      const expected = new Date(createdAt.getTime() + 60 * 24 * 60 * 60 * 1000);
      expect(result!.next_rotation_at?.getTime()).toBe(expected.getTime());
    });

    it('surfaces last_rotation_error when present', async () => {
      const err = {
        attempted_at: new Date(),
        error: 'KMS unreachable',
        attempts: 2,
      };
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotated_at: new Date(),
          last_rotation_error: err,
        }),
      );

      const result = await service.getRotationPolicy(ORG_ID);
      expect(result!.last_rotation_error).toEqual(err);
    });

    it('defaults rotation_interval_days to 90 when missing', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotation_interval_days: 0,
          rotated_at: new Date(),
        }),
      );

      const result = await service.getRotationPolicy(ORG_ID);
      expect(result!.rotation_interval_days).toBe(90);
    });

    it('defaults restore_drill_enabled to true when undefined', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          restore_drill_enabled: undefined,
          rotated_at: new Date(),
        }),
      );

      const result = await service.getRotationPolicy(ORG_ID);
      expect(result!.restore_drill_enabled).toBe(true);
    });
  });

  describe('updateRotationPolicy', () => {
    it('applies a partial patch via $set', async () => {
      mockOrgKeyModel.updateOne.mockResolvedValue({ matchedCount: 1 });

      await service.updateRotationPolicy(ORG_ID, {
        auto_rotate: true,
        rotation_interval_days: 60,
      });

      const call = mockOrgKeyModel.updateOne.mock.calls[0];
      expect(call[1]).toEqual({
        $set: {
          auto_rotate: true,
          rotation_interval_days: 60,
        },
      });
    });

    it('accepts restore_drill_enabled toggle', async () => {
      mockOrgKeyModel.updateOne.mockResolvedValue({ matchedCount: 1 });

      await service.updateRotationPolicy(ORG_ID, {
        restore_drill_enabled: false,
      });

      const call = mockOrgKeyModel.updateOne.mock.calls[0];
      expect(call[1]).toEqual({ $set: { restore_drill_enabled: false } });
    });

    it('is a no-op when the patch is empty', async () => {
      await service.updateRotationPolicy(ORG_ID, {});
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });

    it('throws for rotation_interval_days below 7', async () => {
      await expect(
        service.updateRotationPolicy(ORG_ID, {
          rotation_interval_days: 3,
        }),
      ).rejects.toThrow(/between 7 and 365/);
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });

    it('throws for rotation_interval_days above 365', async () => {
      await expect(
        service.updateRotationPolicy(ORG_ID, {
          rotation_interval_days: 400,
        }),
      ).rejects.toThrow(/between 7 and 365/);
    });

    it('throws for non-finite rotation_interval_days', async () => {
      await expect(
        service.updateRotationPolicy(ORG_ID, {
          rotation_interval_days: Infinity,
        }),
      ).rejects.toThrow(/between 7 and 365/);
    });

    it('throws when the org has no encryption key', async () => {
      mockOrgKeyModel.updateOne.mockResolvedValue({ matchedCount: 0 });

      await expect(
        service.updateRotationPolicy(ORG_ID, { auto_rotate: false }),
      ).rejects.toThrow(/No encryption key found/);
    });

    it('accepts exactly 7 and exactly 365 (inclusive bounds)', async () => {
      mockOrgKeyModel.updateOne.mockResolvedValue({ matchedCount: 1 });

      await service.updateRotationPolicy(ORG_ID, {
        rotation_interval_days: 7,
      });
      await service.updateRotationPolicy(ORG_ID, {
        rotation_interval_days: 365,
      });

      expect(mockOrgKeyModel.updateOne).toHaveBeenCalledTimes(2);
    });
  });

  // BYOK-046: acknowledgeRotationOverdue — admin "remind me later" window
  describe('acknowledgeRotationOverdue', () => {
    const daysAgo = (n: number) => {
      const d = new Date();
      d.setDate(d.getDate() - n);
      return d;
    };

    it('sets acknowledged_until to now + windowDays when key is overdue', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotated_at: daysAgo(100),
          rotation_interval_days: 90,
        }),
      );
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await service.acknowledgeRotationOverdue(ORG_ID, 30);

      expect(result.acknowledged_until).toBeInstanceOf(Date);
      const nowPlus30 = Date.now() + 30 * 24 * 60 * 60 * 1000;
      const delta = Math.abs(result.acknowledged_until.getTime() - nowPlus30);
      expect(delta).toBeLessThan(1000);

      expect(mockOrgKeyModel.updateOne).toHaveBeenCalledWith(
        expect.any(Object),
        {
          $set: expect.objectContaining({
            acknowledged_until: result.acknowledged_until,
          }),
        },
      );
    });

    it('defaults windowDays to 30 when not specified', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotated_at: daysAgo(100),
          rotation_interval_days: 90,
        }),
      );
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await service.acknowledgeRotationOverdue(ORG_ID);

      const nowPlus30 = Date.now() + 30 * 24 * 60 * 60 * 1000;
      const delta = Math.abs(result.acknowledged_until.getTime() - nowPlus30);
      expect(delta).toBeLessThan(1000);
    });

    it('throws when the organization has no encryption key', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);

      await expect(service.acknowledgeRotationOverdue(ORG_ID)).rejects.toThrow(
        'No encryption key found',
      );
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });

    it('throws when the key is not overdue (healthy state)', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotated_at: daysAgo(30),
          rotation_interval_days: 90,
        }),
      );

      await expect(service.acknowledgeRotationOverdue(ORG_ID)).rejects.toThrow(
        /Cannot acknowledge.*healthy/,
      );
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });

    it('allows acknowledgment when key is past critical threshold', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotated_at: daysAgo(91),
          rotation_interval_days: 90,
        }),
      );
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await service.acknowledgeRotationOverdue(ORG_ID);
      expect(result.acknowledged_until).toBeInstanceOf(Date);
    });

    it('allows acknowledgment when key is in escalated state (past grace)', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotated_at: daysAgo(200),
          rotation_interval_days: 90,
        }),
      );
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await service.acknowledgeRotationOverdue(ORG_ID);
      expect(result.acknowledged_until).toBeInstanceOf(Date);
    });

    it('uses createdAt as fallback when rotated_at is null', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          rotated_at: null,
          createdAt: daysAgo(100),
          rotation_interval_days: 90,
        }),
      );
      mockOrgKeyModel.updateOne.mockResolvedValue({ modifiedCount: 1 });

      const result = await service.acknowledgeRotationOverdue(ORG_ID);
      expect(result.acknowledged_until).toBeInstanceOf(Date);
    });
  });

  // ---------------------------------------------------------------
  // BYOK-080: getAgentEncryptionConfig raw-key branch
  // ---------------------------------------------------------------

  describe('getAgentEncryptionConfig (BYOK-080)', () => {
    const rawKeyBytes = Buffer.from(
      '1122334455667788990011223344556677889900112233445566778899001122',
      'hex',
    );

    beforeEach(() => {
      mockConfigService.get.mockReturnValue(validHexKey());
      service.onModuleInit();
    });

    it('returns null when the organization has no key record', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(null);
      const result = await service.getAgentEncryptionConfig(ORG_ID);
      expect(result).toBeNull();
    });

    it('returns wrapped_key (NOT raw_org_key) for direct type', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({ key_type: 'direct', version: 3 }),
      );

      const result = await service.getAgentEncryptionConfig(ORG_ID);

      expect(result).toEqual(
        expect.objectContaining({
          enabled: true,
          key_type: 'direct',
          wrapped_key: 'wrapped-key-hex',
          key_version: 3,
        }),
      );
      expect(result).not.toHaveProperty('raw_org_key');
      // direct type must NOT call unwrap on the server
      expect(mockDirectProvider.unwrap).not.toHaveBeenCalled();
    });

    it('returns raw_org_key (NOT wrapped_key) for managed type', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({ key_type: 'managed', version: 2 }),
      );
      mockManagedProvider.unwrap.mockResolvedValue(rawKeyBytes);

      const result = await service.getAgentEncryptionConfig(ORG_ID);

      expect(result).toEqual(
        expect.objectContaining({
          enabled: true,
          key_type: 'managed',
          raw_org_key: rawKeyBytes.toString('hex'),
          key_version: 2,
        }),
      );
      expect(result).not.toHaveProperty('wrapped_key');
      expect(mockManagedProvider.unwrap).toHaveBeenCalled();
    });

    it('returns raw_org_key for aws-kms type', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          key_type: 'aws-kms',
          kms_config: {
            provider: 'aws-kms',
            key_id: 'arn:aws:kms:us-east-1:1:key/abc',
          },
        }),
      );
      mockAwsKmsProvider.unwrap.mockResolvedValue(rawKeyBytes);

      const result = await service.getAgentEncryptionConfig(ORG_ID);

      expect(result?.key_type).toBe('aws-kms');
      expect(result?.raw_org_key).toBe(rawKeyBytes.toString('hex'));
      expect(result).not.toHaveProperty('wrapped_key');
      expect(mockAwsKmsProvider.unwrap).toHaveBeenCalled();
    });

    it('returns raw_org_key for gcp-kms type', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          key_type: 'gcp-kms',
          kms_config: {
            provider: 'gcp-kms',
            key_id: 'projects/p/locations/l/keyRings/r/cryptoKeys/k',
          },
        }),
      );
      mockGcpKmsProvider.unwrap.mockResolvedValue(rawKeyBytes);

      const result = await service.getAgentEncryptionConfig(ORG_ID);

      expect(result?.key_type).toBe('gcp-kms');
      expect(result?.raw_org_key).toBe(rawKeyBytes.toString('hex'));
      expect(mockGcpKmsProvider.unwrap).toHaveBeenCalled();
    });

    it('returns raw_org_key for azure-kms type', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({
          key_type: 'azure-kms',
          kms_config: {
            provider: 'azure-kms',
            key_id: 'https://v.vault.azure.net/keys/k',
          },
        }),
      );
      mockAzureKmsProvider.unwrap.mockResolvedValue(rawKeyBytes);

      const result = await service.getAgentEncryptionConfig(ORG_ID);

      expect(result?.key_type).toBe('azure-kms');
      expect(result?.raw_org_key).toBe(rawKeyBytes.toString('hex'));
      expect(mockAzureKmsProvider.unwrap).toHaveBeenCalled();
    });

    it('never emits raw_org_key in logger output (security)', async () => {
      mockOrgKeyModel.findOne.mockResolvedValue(
        makeKeyRecord({ key_type: 'managed', version: 4 }),
      );
      mockManagedProvider.unwrap.mockResolvedValue(rawKeyBytes);

      const logSpy = jest.spyOn((service as any).logger, 'log');
      const warnSpy = jest.spyOn((service as any).logger, 'warn');
      const errorSpy = jest.spyOn((service as any).logger, 'error');

      await service.getAgentEncryptionConfig(ORG_ID);

      const allLogs = [
        ...logSpy.mock.calls.flat(),
        ...warnSpy.mock.calls.flat(),
        ...errorSpy.mock.calls.flat(),
      ].map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg)));
      const joined = allLogs.join(' ');

      expect(joined).not.toContain(rawKeyBytes.toString('hex'));
      expect(joined).not.toContain('raw_org_key');

      logSpy.mockRestore();
      warnSpy.mockRestore();
      errorSpy.mockRestore();
    });
  });
});
