import {
  ByokBackfillService,
  isFreePlan,
  BackfillLogger,
} from './byok-backfill';

describe('isFreePlan', () => {
  it('returns true when plan is null/undefined', () => {
    expect(isFreePlan(null)).toBe(true);
    expect(isFreePlan(undefined)).toBe(true);
  });

  it('returns true when plan price is 0', () => {
    expect(isFreePlan({ slug: 'starter', price: 0 })).toBe(true);
  });

  it('returns true when plan slug is "free"', () => {
    expect(isFreePlan({ slug: 'free', price: 100 })).toBe(true);
  });

  it('returns false for paid plans with price > 0 and non-free slug', () => {
    expect(isFreePlan({ slug: 'pro', price: 49.9 })).toBe(false);
    expect(isFreePlan({ slug: 'enterprise', price: 499 })).toBe(false);
  });
});

describe('ByokBackfillService', () => {
  let mockOrgKeyModel: {
    find: jest.Mock;
    updateOne: jest.Mock;
  };
  let mockSubscriptionModel: { find: jest.Mock };
  let mockPlanModel: { find: jest.Mock };
  let mockLogger: BackfillLogger & {
    log: jest.Mock;
    warn: jest.Mock;
    error: jest.Mock;
  };
  let service: ByokBackfillService;

  // Helpers to build query result promises that also expose .lean()
  const leanQuery = <T>(data: T[]) => {
    const promise: Promise<T[]> & { lean?: () => Promise<T[]> } =
      Promise.resolve(data) as any;
    promise.lean = () => Promise.resolve(data);
    return promise;
  };

  beforeEach(() => {
    mockOrgKeyModel = {
      find: jest.fn(),
      updateOne: jest.fn().mockResolvedValue({ modifiedCount: 1 }),
    };
    mockSubscriptionModel = { find: jest.fn() };
    mockPlanModel = { find: jest.fn() };
    mockLogger = {
      log: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };

    service = new ByokBackfillService(
      mockOrgKeyModel as any,
      mockSubscriptionModel as any,
      mockPlanModel as any,
      mockLogger,
    );
  });

  describe('empty database', () => {
    it('returns zero counters when there are no organization keys', async () => {
      mockOrgKeyModel.find.mockReturnValue(leanQuery([]));

      const result = await service.run();

      expect(result.scanned).toBe(0);
      expect(result.updated).toBe(0);
      expect(result.skipped).toBe(0);
      expect(mockSubscriptionModel.find).not.toHaveBeenCalled();
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });
  });

  describe('legacy documents with no new fields', () => {
    it('updates all missing fields with the correct plan-aware defaults', async () => {
      const orgId1 = '507f1f77bcf86cd799439011';
      const orgId2 = '507f1f77bcf86cd799439012';

      mockOrgKeyModel.find.mockReturnValue(
        leanQuery([
          { _id: 'k1', organization_id: orgId1 },
          { _id: 'k2', organization_id: orgId2 },
        ]),
      );
      mockSubscriptionModel.find.mockReturnValue(
        leanQuery([
          { organization_id: orgId1, plan_id: 'p-free', status: 'authorized' },
          { organization_id: orgId2, plan_id: 'p-pro', status: 'authorized' },
        ]),
      );
      mockPlanModel.find.mockReturnValue(
        leanQuery([
          { _id: 'p-free', slug: 'free', price: 0 },
          { _id: 'p-pro', slug: 'pro', price: 49.9 },
        ]),
      );

      const result = await service.run();

      expect(result.scanned).toBe(2);
      expect(result.updated).toBe(2);
      expect(result.skipped).toBe(0);
      expect(result.planBreakdown.free).toBe(1);
      expect(result.planBreakdown.paid).toBe(1);
      expect(result.planBreakdown.noSubscription).toBe(0);

      // Free-tier key should get restore_drill_enabled: false
      const freeCall = mockOrgKeyModel.updateOne.mock.calls.find(
        (c) => c[0]._id === 'k1',
      );
      expect(freeCall[1].$set.restore_drill_enabled).toBe(false);
      expect(freeCall[1].$set.key_history).toEqual([]);
      expect(freeCall[1].$set.last_rotation_error).toBeNull();
      expect(freeCall[1].$set.last_pipeline_validation).toBeNull();
      expect(freeCall[1].$set.acknowledged_until).toBeNull();

      // Paid-tier key should get restore_drill_enabled: true
      const paidCall = mockOrgKeyModel.updateOne.mock.calls.find(
        (c) => c[0]._id === 'k2',
      );
      expect(paidCall[1].$set.restore_drill_enabled).toBe(true);
    });
  });

  describe('already-migrated documents', () => {
    it('skips documents that already have all new fields (idempotency)', async () => {
      mockOrgKeyModel.find.mockReturnValue(
        leanQuery([
          {
            _id: 'k1',
            organization_id: '507f1f77bcf86cd799439011',
            key_history: [],
            last_rotation_error: null,
            last_pipeline_validation: null,
            acknowledged_until: null,
            restore_drill_enabled: true,
          },
        ]),
      );
      mockSubscriptionModel.find.mockReturnValue(leanQuery([]));
      mockPlanModel.find.mockReturnValue(leanQuery([]));

      const result = await service.run();

      expect(result.scanned).toBe(1);
      expect(result.updated).toBe(0);
      expect(result.skipped).toBe(1);
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });
  });

  describe('partial migration (some fields already set)', () => {
    it('fills only the missing fields and preserves existing values', async () => {
      mockOrgKeyModel.find.mockReturnValue(
        leanQuery([
          {
            _id: 'k1',
            organization_id: '507f1f77bcf86cd799439011',
            key_history: [
              {
                version: 1,
                encrypted_key: 'x',
                salt: 'y',
                key_type: 'managed',
                kms_config: null,
                rotated_at: new Date(),
              },
            ],
            // last_rotation_error, last_pipeline_validation, acknowledged_until,
            // restore_drill_enabled all undefined
          },
        ]),
      );
      mockSubscriptionModel.find.mockReturnValue(
        leanQuery([
          {
            organization_id: '507f1f77bcf86cd799439011',
            plan_id: 'p-pro',
            status: 'authorized',
          },
        ]),
      );
      mockPlanModel.find.mockReturnValue(
        leanQuery([{ _id: 'p-pro', slug: 'pro', price: 49.9 }]),
      );

      const result = await service.run();

      expect(result.updated).toBe(1);
      const call = mockOrgKeyModel.updateOne.mock.calls[0];
      // key_history is preserved (not in $set)
      expect(call[1].$set.key_history).toBeUndefined();
      // Missing fields are filled
      expect(call[1].$set.last_rotation_error).toBeNull();
      expect(call[1].$set.last_pipeline_validation).toBeNull();
      expect(call[1].$set.acknowledged_until).toBeNull();
      expect(call[1].$set.restore_drill_enabled).toBe(true);
    });
  });

  describe('orgs without an active subscription', () => {
    it('treats no-subscription as free tier', async () => {
      mockOrgKeyModel.find.mockReturnValue(
        leanQuery([{ _id: 'k1', organization_id: 'orphan-org' }]),
      );
      mockSubscriptionModel.find.mockReturnValue(leanQuery([]));
      mockPlanModel.find.mockReturnValue(leanQuery([]));

      const result = await service.run();

      expect(result.planBreakdown.noSubscription).toBe(1);
      const call = mockOrgKeyModel.updateOne.mock.calls[0];
      expect(call[1].$set.restore_drill_enabled).toBe(false);
    });
  });

  describe('dry run mode', () => {
    it('reports what would change without writing', async () => {
      mockOrgKeyModel.find.mockReturnValue(
        leanQuery([{ _id: 'k1', organization_id: '507f1f77bcf86cd799439011' }]),
      );
      mockSubscriptionModel.find.mockReturnValue(leanQuery([]));
      mockPlanModel.find.mockReturnValue(leanQuery([]));

      const result = await service.run({ dryRun: true });

      expect(result.dryRun).toBe(true);
      expect(result.updated).toBe(1);
      expect(mockOrgKeyModel.updateOne).not.toHaveBeenCalled();
    });
  });

  describe('second run is a no-op', () => {
    it('running twice on the same freshly-migrated dataset produces zero updates on the second pass', async () => {
      const firstRunData = [
        { _id: 'k1', organization_id: '507f1f77bcf86cd799439011' },
      ];
      const secondRunData = [
        {
          _id: 'k1',
          organization_id: '507f1f77bcf86cd799439011',
          key_history: [],
          last_rotation_error: null,
          last_pipeline_validation: null,
          acknowledged_until: null,
          restore_drill_enabled: true,
        },
      ];

      mockOrgKeyModel.find
        .mockReturnValueOnce(leanQuery(firstRunData))
        .mockReturnValueOnce(leanQuery(secondRunData));
      mockSubscriptionModel.find.mockReturnValue(
        leanQuery([
          {
            organization_id: '507f1f77bcf86cd799439011',
            plan_id: 'p-pro',
            status: 'authorized',
          },
        ]),
      );
      mockPlanModel.find.mockReturnValue(
        leanQuery([{ _id: 'p-pro', slug: 'pro', price: 49.9 }]),
      );

      const first = await service.run();
      const second = await service.run();

      expect(first.updated).toBe(1);
      expect(second.updated).toBe(0);
      expect(second.skipped).toBe(1);
    });
  });
});
