import * as crypto from 'crypto';
import { Types } from 'mongoose';
import { KeyRotationService } from './key-rotation.service';
import { KeyRotationValidationError } from '../errors/key-rotation.errors';

describe('KeyRotationService', () => {
  let service: KeyRotationService;
  let mockOrgKeyModel: {
    find: jest.Mock;
    findOne: jest.Mock;
    updateOne: jest.Mock;
  };
  let mockKeyManagementService: {
    rotateOrganizationKey: jest.Mock;
    rotateByokKey: jest.Mock;
  };
  let mockConfigService: { get: jest.Mock };
  let mockCronRunLogModel: { create: jest.Mock };

  const orgId = '507f1f77bcf86cd799439011';

  const makeKeyRecord = (overrides: Record<string, unknown> = {}) => ({
    _id: new Types.ObjectId(),
    organization_id: new Types.ObjectId(orgId),
    encrypted_key: 'wrapped-key',
    salt: crypto.randomBytes(32).toString('hex'),
    version: 1,
    key_type: 'managed',
    kms_config: null,
    customer_key_hash: null,
    rotated_at: new Date('2025-12-01'),
    auto_rotate: true,
    rotation_interval_days: 90,
    createdAt: new Date('2025-12-01'),
    updatedAt: new Date('2025-12-01'),
    last_rotation_error: null,
    ...overrides,
  });

  beforeEach(() => {
    mockOrgKeyModel = {
      find: jest.fn().mockResolvedValue([]),
      findOne: jest.fn().mockResolvedValue(null),
      updateOne: jest.fn().mockResolvedValue({ modifiedCount: 1 }),
    };
    mockKeyManagementService = {
      rotateOrganizationKey: jest.fn().mockResolvedValue(2),
      rotateByokKey: jest.fn().mockResolvedValue(2),
    };
    mockConfigService = {
      get: jest.fn().mockReturnValue(undefined),
    };
    mockCronRunLogModel = { create: jest.fn().mockResolvedValue({}) };

    service = new KeyRotationService(
      mockOrgKeyModel as any,
      mockKeyManagementService as any,
      mockConfigService as any,
      mockCronRunLogModel as any,
    );
  });

  describe('handleAutoRotation (BYOK-050 dispatch)', () => {
    it('rotates managed keys via rotateOrganizationKey', async () => {
      mockOrgKeyModel.find.mockResolvedValue([makeKeyRecord()]);

      const results = await service.handleAutoRotation();

      expect(
        mockKeyManagementService.rotateOrganizationKey,
      ).toHaveBeenCalledWith(orgId);
      expect(results.rotated).toBe(1);
      expect(results.errors).toBe(0);
      expect(results.deferred).toBe(0);
    });

    it('rotates aws-kms keys via rotateByokKey', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'aws-kms',
          kms_config: { provider: 'aws', key_id: 'arn:aws:kms:...' },
        }),
      ]);

      const results = await service.handleAutoRotation();

      expect(mockKeyManagementService.rotateByokKey).toHaveBeenCalledWith(
        orgId,
      );
      expect(results.rotated).toBe(1);
    });

    it('rotates gcp-kms keys via rotateByokKey', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'gcp-kms',
          kms_config: {
            provider: 'gcp',
            key_id: 'projects/p/locations/l/keyRings/r/cryptoKeys/k',
          },
        }),
      ]);

      const results = await service.handleAutoRotation();

      expect(mockKeyManagementService.rotateByokKey).toHaveBeenCalledWith(
        orgId,
      );
      expect(results.rotated).toBe(1);
    });

    it('rotates azure-kms keys via rotateByokKey', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'azure-kms',
          kms_config: {
            provider: 'azure',
            key_id: 'https://vault.vault.azure.net/keys/k/v',
          },
        }),
      ]);

      const results = await service.handleAutoRotation();

      expect(mockKeyManagementService.rotateByokKey).toHaveBeenCalledWith(
        orgId,
      );
      expect(results.rotated).toBe(1);
    });

    it('skips direct BYOK keys (customer key required)', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ key_type: 'direct' }),
      ]);

      const results = await service.handleAutoRotation();

      expect(
        mockKeyManagementService.rotateOrganizationKey,
      ).not.toHaveBeenCalled();
      expect(mockKeyManagementService.rotateByokKey).not.toHaveBeenCalled();
      expect(results.skipped).toBe(1);
    });

    it('processes a mixed provider batch without cross-contamination', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ key_type: 'managed' }),
        makeKeyRecord({
          key_type: 'gcp-kms',
          kms_config: { provider: 'gcp', key_id: 'projects/...' },
        }),
        makeKeyRecord({ key_type: 'direct' }),
        makeKeyRecord({
          key_type: 'azure-kms',
          kms_config: { provider: 'azure', key_id: 'https://...' },
        }),
      ]);

      const results = await service.handleAutoRotation();

      expect(
        mockKeyManagementService.rotateOrganizationKey,
      ).toHaveBeenCalledTimes(1);
      expect(mockKeyManagementService.rotateByokKey).toHaveBeenCalledTimes(2);
      expect(results.rotated).toBe(3);
      expect(results.skipped).toBe(1); // direct
    });

    it('skips keys that are not due for rotation', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: new Date() }),
      ]);

      const results = await service.handleAutoRotation();

      expect(
        mockKeyManagementService.rotateOrganizationKey,
      ).not.toHaveBeenCalled();
      expect(results.skipped).toBe(1);
    });

    it('uses createdAt as fallback when rotated_at is null', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: null,
          createdAt: new Date('2025-12-01'),
        }),
      ]);

      const results = await service.handleAutoRotation();

      expect(mockKeyManagementService.rotateOrganizationKey).toHaveBeenCalled();
      expect(results.rotated).toBe(1);
    });

    it('only queries keys with auto_rotate=true', async () => {
      await service.handleAutoRotation();
      expect(mockOrgKeyModel.find).toHaveBeenCalledWith({ auto_rotate: true });
    });
  });

  describe('BYOK-051 bounded retry + error tracking', () => {
    it('retries transient failures once in the same run and succeeds', async () => {
      const record = makeKeyRecord();
      mockOrgKeyModel.find.mockResolvedValue([record]);
      mockKeyManagementService.rotateOrganizationKey
        .mockRejectedValueOnce(new Error('transient KMS blip'))
        .mockResolvedValueOnce(2);

      const results = await service.handleAutoRotation();

      expect(
        mockKeyManagementService.rotateOrganizationKey,
      ).toHaveBeenCalledTimes(2);
      expect(results.rotated).toBe(1);
      expect(results.errors).toBe(0);
    });

    it('does NOT retry KeyRotationValidationError', async () => {
      const record = makeKeyRecord();
      mockOrgKeyModel.find.mockResolvedValue([record]);
      mockKeyManagementService.rotateOrganizationKey.mockRejectedValue(
        new KeyRotationValidationError(orgId, 'unwrap roundtrip mismatch'),
      );

      const results = await service.handleAutoRotation();

      expect(
        mockKeyManagementService.rotateOrganizationKey,
      ).toHaveBeenCalledTimes(1);
      expect(results.errors).toBe(1);
    });

    it('persists last_rotation_error with incrementing attempts across runs', async () => {
      const record = makeKeyRecord({ last_rotation_error: null });
      mockOrgKeyModel.find.mockResolvedValue([record]);
      mockOrgKeyModel.findOne.mockResolvedValue({
        ...record,
        last_rotation_error: {
          attempted_at: new Date(),
          error: 'old',
          attempts: 2,
        },
      });
      mockKeyManagementService.rotateOrganizationKey.mockRejectedValue(
        new Error('persistent failure'),
      );

      await service.handleAutoRotation();

      // On failure (after retry), updateOne is called with last_rotation_error
      // where attempts = 2 (prior) + 1 = 3
      const errorUpdateCall = mockOrgKeyModel.updateOne.mock.calls.find(
        (c) => c[1]?.$set?.last_rotation_error != null,
      );
      expect(errorUpdateCall).toBeDefined();
      expect(errorUpdateCall![1].$set.last_rotation_error.attempts).toBe(3);
      expect(errorUpdateCall![1].$set.last_rotation_error.error).toContain(
        'persistent failure',
      );
    });

    it('clears last_rotation_error on successful rotation', async () => {
      mockOrgKeyModel.find.mockResolvedValue([makeKeyRecord()]);

      await service.handleAutoRotation();

      const clearCall = mockOrgKeyModel.updateOne.mock.calls.find(
        (c) => c[1]?.$set?.last_rotation_error === null,
      );
      expect(clearCall).toBeDefined();
    });

    it('sets attempts=1 when no prior error exists', async () => {
      const record = makeKeyRecord();
      mockOrgKeyModel.find.mockResolvedValue([record]);
      mockOrgKeyModel.findOne.mockResolvedValue({
        ...record,
        last_rotation_error: null,
      });
      mockKeyManagementService.rotateOrganizationKey.mockRejectedValue(
        new Error('first failure'),
      );

      await service.handleAutoRotation();

      const errorUpdateCall = mockOrgKeyModel.updateOne.mock.calls.find(
        (c) => c[1]?.$set?.last_rotation_error != null,
      );
      expect(errorUpdateCall![1].$set.last_rotation_error.attempts).toBe(1);
    });
  });

  describe('BYOK-091 cron metric emission', () => {
    it('emits a cron metric via handleAutoRotationCron on success', async () => {
      mockOrgKeyModel.find.mockResolvedValue([makeKeyRecord()]);

      await service.handleAutoRotationCron();

      expect(mockCronRunLogModel.create).toHaveBeenCalledTimes(1);
      const metric = mockCronRunLogModel.create.mock.calls[0][0];
      expect(metric.subsystem).toBe('byok');
      expect(metric.job).toBe('key_rotation');
      expect(metric.succeeded).toBe(1);
      expect(metric.failed).toBe(0);
      expect(metric.processed).toBe(1);
      expect(metric.failures).toEqual([]);
    });

    it('emits a cron metric with failure details when rotation fails', async () => {
      mockOrgKeyModel.find.mockResolvedValue([makeKeyRecord()]);
      mockKeyManagementService.rotateOrganizationKey.mockRejectedValue(
        new Error('persistent KMS failure'),
      );

      await service.handleAutoRotationCron();

      const metric = mockCronRunLogModel.create.mock.calls[0][0];
      expect(metric.failed).toBe(1);
      expect(metric.succeeded).toBe(0);
      expect(metric.failures).toHaveLength(1);
      expect(metric.failures[0].organization_id).toBe(orgId);
      expect(metric.failures[0].error).toContain('persistent KMS failure');
    });

    it('still emits a cron metric when handleAutoRotation itself throws', async () => {
      mockOrgKeyModel.find.mockRejectedValue(new Error('db unreachable'));

      await service.handleAutoRotationCron();

      expect(mockCronRunLogModel.create).toHaveBeenCalledTimes(1);
      const metric = mockCronRunLogModel.create.mock.calls[0][0];
      expect(metric.failed).toBeGreaterThanOrEqual(1);
      expect(metric.failures[0].organization_id).toBe('__cron__');
      expect(metric.failures[0].error).toContain('db unreachable');
    });
  });

  describe('BYOK-051 per-run cap', () => {
    it('defers organizations exceeding BYOK_AUTO_ROTATION_MAX_PER_RUN', async () => {
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'BYOK_AUTO_ROTATION_MAX_PER_RUN') return 2;
        return undefined;
      });

      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord(),
        makeKeyRecord(),
        makeKeyRecord(),
        makeKeyRecord(),
        makeKeyRecord(),
      ]);

      const results = await service.handleAutoRotation();

      expect(results.rotated).toBe(2);
      expect(results.deferred).toBe(3);
      expect(
        mockKeyManagementService.rotateOrganizationKey,
      ).toHaveBeenCalledTimes(2);
    });

    it('defaults to 100 when env var is not set', async () => {
      // Build 101 records
      const records = Array.from({ length: 101 }, () => makeKeyRecord());
      mockOrgKeyModel.find.mockResolvedValue(records);

      const results = await service.handleAutoRotation();

      expect(results.rotated).toBe(100);
      expect(results.deferred).toBe(1);
    });

    it('deferred is 0 when all records fit within the cap', async () => {
      mockOrgKeyModel.find.mockResolvedValue([makeKeyRecord()]);

      const results = await service.handleAutoRotation();

      expect(results.deferred).toBe(0);
    });
  });
});
