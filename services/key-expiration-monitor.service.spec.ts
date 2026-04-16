import * as crypto from 'crypto';
import { Types } from 'mongoose';
import { KeyExpirationMonitorService } from './key-expiration-monitor.service';

describe('KeyExpirationMonitorService', () => {
  let service: KeyExpirationMonitorService;
  let mockOrgKeyModel: any;
  let mockCronRunLogModel: { create: jest.Mock };
  let mockKeyAlertHistoryModel: { create: jest.Mock };
  let mockOrganizationModel: { findOne: jest.Mock };
  let mockOrganizationMemberModel: { find: jest.Mock };
  let mockEmailService: {
    sendByokRotationReminder: jest.Mock;
    sendByokRotationWarning: jest.Mock;
    sendByokRotationCritical: jest.Mock;
    sendByokDirectRotationWarning: jest.Mock;
    sendByokDirectRotationCritical: jest.Mock;
  };
  let mockConfigService: { get: jest.Mock };

  const orgId = '507f1f77bcf86cd799439011';

  const makeKeyRecord = (overrides: any = {}) => ({
    _id: new Types.ObjectId(),
    organization_id: new Types.ObjectId(orgId),
    encrypted_key: 'wrapped-key',
    salt: crypto.randomBytes(32).toString('hex'),
    version: 1,
    key_type: 'managed',
    kms_config: null,
    customer_key_hash: null,
    rotated_at: null,
    auto_rotate: false,
    rotation_interval_days: 90,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  });

  beforeEach(() => {
    mockOrgKeyModel = {
      find: jest.fn(),
      findOne: jest.fn().mockResolvedValue({ rotation_interval_days: 90 }),
    };
    mockCronRunLogModel = { create: jest.fn().mockResolvedValue({}) };
    mockKeyAlertHistoryModel = {
      create: jest.fn().mockResolvedValue({}),
    };
    mockOrganizationModel = {
      findOne: jest.fn().mockResolvedValue({ name: 'Acme Inc' }),
    };
    // .populate returns a thenable — we mimic via chained resolvedValue
    const memberQueryMock = {
      populate: jest.fn().mockResolvedValue([
        {
          user_id: { email: 'owner@example.com', name: 'Carlos' },
        },
      ]),
    };
    mockOrganizationMemberModel = {
      find: jest.fn().mockReturnValue(memberQueryMock),
    };
    mockEmailService = {
      sendByokRotationReminder: jest.fn().mockResolvedValue(true),
      sendByokRotationWarning: jest.fn().mockResolvedValue(true),
      sendByokRotationCritical: jest.fn().mockResolvedValue(true),
      sendByokDirectRotationWarning: jest.fn().mockResolvedValue(true),
      sendByokDirectRotationCritical: jest.fn().mockResolvedValue(true),
    };
    mockConfigService = {
      get: jest.fn().mockReturnValue(undefined),
    };

    service = new KeyExpirationMonitorService(
      mockOrgKeyModel,
      mockCronRunLogModel as any,
      mockKeyAlertHistoryModel as any,
      mockOrganizationModel as any,
      mockOrganizationMemberModel as any,
      mockEmailService as any,
      mockConfigService as any,
    );
  });

  describe('BYOK-091 cron metric emission', () => {
    it('emits a cron metric via handleExpirationCheckCron', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 95);
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: oldDate }),
        makeKeyRecord({ rotated_at: new Date() }),
      ]);

      await service.handleExpirationCheckCron();

      expect(mockCronRunLogModel.create).toHaveBeenCalledTimes(1);
      const metric = mockCronRunLogModel.create.mock.calls[0][0];
      expect(metric.subsystem).toBe('byok');
      expect(metric.job).toBe('key_expiration_monitor');
      expect(metric.succeeded).toBe(1); // 1 healthy
      expect(metric.failed).toBe(1); // 1 critical folded in
      expect(metric.processed).toBe(2);
    });

    it('emits a cron metric even when checkKeyAges throws', async () => {
      mockOrgKeyModel.find.mockRejectedValue(new Error('db unreachable'));

      await service.handleExpirationCheckCron();

      expect(mockCronRunLogModel.create).toHaveBeenCalledTimes(1);
      const metric = mockCronRunLogModel.create.mock.calls[0][0];
      expect(metric.failures).toHaveLength(1);
      expect(metric.failures[0].organization_id).toBe('__cron__');
      expect(metric.failures[0].error).toContain('db unreachable');
    });
  });

  describe('checkKeyAges', () => {
    it('should return warning for keys aged 83+ days', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 85);
      const record = makeKeyRecord({
        rotated_at: oldDate,
      });
      mockOrgKeyModel.find.mockResolvedValue([record]);

      const results = await service.checkKeyAges();

      expect(results.warnings.length).toBe(1);
      expect(results.warnings[0].organizationId).toBe(orgId);
      expect(results.warnings[0].ageDays).toBeGreaterThanOrEqual(85);
      expect(results.critical.length).toBe(0);
    });

    it('should return critical for keys aged 90+ days', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 95);
      const record = makeKeyRecord({
        rotated_at: oldDate,
      });
      mockOrgKeyModel.find.mockResolvedValue([record]);

      const results = await service.checkKeyAges();

      expect(results.critical.length).toBe(1);
      expect(results.critical[0].organizationId).toBe(orgId);
      expect(results.critical[0].ageDays).toBeGreaterThanOrEqual(95);
    });

    it('should return healthy for keys aged less than 83 days', async () => {
      const recentDate = new Date();
      recentDate.setDate(recentDate.getDate() - 30);
      const record = makeKeyRecord({
        rotated_at: recentDate,
      });
      mockOrgKeyModel.find.mockResolvedValue([record]);

      const results = await service.checkKeyAges();

      expect(results.warnings.length).toBe(0);
      expect(results.critical.length).toBe(0);
      expect(results.healthy).toBe(1);
    });

    it('should use createdAt when rotated_at is null', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 91);
      const record = makeKeyRecord({
        rotated_at: null,
        createdAt: oldDate,
      });
      mockOrgKeyModel.find.mockResolvedValue([record]);

      const results = await service.checkKeyAges();

      expect(results.critical.length).toBe(1);
    });

    it('should handle empty key list', async () => {
      mockOrgKeyModel.find.mockResolvedValue([]);

      const results = await service.checkKeyAges();

      expect(results.warnings.length).toBe(0);
      expect(results.critical.length).toBe(0);
      expect(results.healthy).toBe(0);
    });

    it('should categorize multiple keys correctly', async () => {
      const now = new Date();
      const days30Ago = new Date(now);
      days30Ago.setDate(now.getDate() - 30);
      const days85Ago = new Date(now);
      days85Ago.setDate(now.getDate() - 85);
      const days95Ago = new Date(now);
      days95Ago.setDate(now.getDate() - 95);

      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: days30Ago,
          organization_id: new Types.ObjectId(),
        }),
        makeKeyRecord({
          rotated_at: days85Ago,
          organization_id: new Types.ObjectId(),
        }),
        makeKeyRecord({
          rotated_at: days95Ago,
          organization_id: new Types.ObjectId(),
        }),
      ]);

      const results = await service.checkKeyAges();

      expect(results.healthy).toBe(1);
      expect(results.warnings.length).toBe(1);
      expect(results.critical.length).toBe(1);
    });
  });

  describe('BYOK-043 percentage-based thresholds', () => {
    const daysAgo = (n: number) => {
      const d = new Date();
      d.setDate(d.getDate() - n);
      return d;
    };

    it('puts a key at 76% of its 100-day interval into reminders', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(76),
          rotation_interval_days: 100,
        }),
      ]);

      const results = await service.checkKeyAges();

      expect(results.reminders).toHaveLength(1);
      expect(results.warnings).toHaveLength(0);
      expect(results.critical).toHaveLength(0);
    });

    it('puts a key at 91% of its 100-day interval into warnings', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(91),
          rotation_interval_days: 100,
        }),
      ]);

      const results = await service.checkKeyAges();

      expect(results.reminders).toHaveLength(0);
      expect(results.warnings).toHaveLength(1);
      expect(results.critical).toHaveLength(0);
    });

    it('puts a key at 100% of its 100-day interval into critical', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(100),
          rotation_interval_days: 100,
        }),
      ]);

      const results = await service.checkKeyAges();

      expect(results.critical).toHaveLength(1);
    });

    it('scales correctly for a custom 180-day interval (140 days → reminder)', async () => {
      // 140 / 180 ≈ 77.8% → reminder (>= 75%)
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(140),
          rotation_interval_days: 180,
        }),
      ]);

      const results = await service.checkKeyAges();

      expect(results.reminders).toHaveLength(1);
      expect(results.warnings).toHaveLength(0);
    });

    it('scales correctly for a short 30-day interval (23 days → reminder)', async () => {
      // 23 / 30 ≈ 76.7% → reminder
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(23),
          rotation_interval_days: 30,
        }),
      ]);

      const results = await service.checkKeyAges();

      expect(results.reminders).toHaveLength(1);
    });

    it('respects custom env var thresholds (50/80/100)', async () => {
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'BYOK_ROTATION_REMINDER_PCT') return 50;
        if (key === 'BYOK_ROTATION_WARNING_PCT') return 80;
        if (key === 'BYOK_ROTATION_CRITICAL_PCT') return 100;
        return undefined;
      });

      // 60 / 90 ≈ 66.7% → reminder under custom 50% threshold,
      // would be healthy under default 75% threshold
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: daysAgo(60) }),
      ]);

      const results = await service.checkKeyAges();

      expect(results.reminders).toHaveLength(1);
    });

    it('returns healthy for keys below the reminder threshold', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: daysAgo(50) }), // 55% of 90d
      ]);

      const results = await service.checkKeyAges();

      expect(results.healthy).toBe(1);
      expect(results.reminders).toHaveLength(0);
      expect(results.warnings).toHaveLength(0);
      expect(results.critical).toHaveLength(0);
    });

    it('never double-counts a key across thresholds (highest severity wins)', async () => {
      // Exactly at 100% — matches critical AND warning AND reminder
      // mathematically but should be reported only in critical.
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(90),
          rotation_interval_days: 90,
        }),
      ]);

      const results = await service.checkKeyAges();

      expect(results.critical).toHaveLength(1);
      expect(results.warnings).toHaveLength(0);
      expect(results.reminders).toHaveLength(0);
    });
  });

  describe('BYOK-044 alert dispatch with idempotency', () => {
    const daysAgo = (n: number) => {
      const d = new Date();
      d.setDate(d.getDate() - n);
      return d;
    };

    const stubResults = (type: 'reminder' | 'warning' | 'critical') => ({
      healthy: 0,
      reminders:
        type === 'reminder'
          ? [
              {
                organizationId: orgId,
                keyType: 'managed',
                ageDays: 76,
                version: 1,
              },
            ]
          : [],
      warnings:
        type === 'warning'
          ? [
              {
                organizationId: orgId,
                keyType: 'managed',
                ageDays: 82,
                version: 1,
              },
            ]
          : [],
      critical:
        type === 'critical'
          ? [
              {
                organizationId: orgId,
                keyType: 'managed',
                ageDays: 90,
                version: 1,
              },
            ]
          : [],
    });

    beforeEach(() => {
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'BYOK_ALERTING_ENABLED') return true;
        return undefined;
      });
    });

    it('does NOT dispatch any emails or create history rows when BYOK_ALERTING_ENABLED=false', async () => {
      mockConfigService.get.mockReturnValue(undefined); // flag off
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: daysAgo(76) }),
      ]);

      await service.handleExpirationCheckCron();

      expect(mockKeyAlertHistoryModel.create).not.toHaveBeenCalled();
      expect(mockEmailService.sendByokRotationReminder).not.toHaveBeenCalled();
    });

    it('reserves a history row and sends the reminder email when alerting is on', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: daysAgo(76) }),
      ]);

      await service.handleExpirationCheckCron();

      expect(mockKeyAlertHistoryModel.create).toHaveBeenCalledTimes(1);
      const historyCall = mockKeyAlertHistoryModel.create.mock.calls[0][0];
      expect(historyCall.key_version).toBe(1);
      expect(historyCall.threshold).toBe('reminder');
      // BYOK-045: reminder uses stable version-based date_key
      expect(historyCall.date_key).toBe('v1');

      expect(mockEmailService.sendByokRotationReminder).toHaveBeenCalledTimes(
        1,
      );
      const emailCall = mockEmailService.sendByokRotationReminder.mock.calls[0];
      expect(emailCall[0]).toEqual(['owner@example.com']);
      expect(emailCall[1].orgName).toBe('Acme Inc');
    });

    it('dispatches warning via sendByokRotationWarning for managed keys at 90%+', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: daysAgo(82) }),
      ]);

      await service.handleExpirationCheckCron();

      expect(mockEmailService.sendByokRotationWarning).toHaveBeenCalledTimes(1);
      expect(mockEmailService.sendByokRotationReminder).not.toHaveBeenCalled();
    });

    it('dispatches critical via sendByokRotationCritical for managed keys at 100%+', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: daysAgo(90) }),
      ]);

      await service.handleExpirationCheckCron();

      expect(mockEmailService.sendByokRotationCritical).toHaveBeenCalledTimes(
        1,
      );
    });

    it('dispatches direct-warning for direct keys crossing warning threshold', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(82),
          key_type: 'direct',
        }),
      ]);

      await service.handleExpirationCheckCron();

      expect(
        mockEmailService.sendByokDirectRotationWarning,
      ).toHaveBeenCalledTimes(1);
      expect(mockEmailService.sendByokRotationWarning).not.toHaveBeenCalled();
    });

    it('dispatches direct-critical for direct keys crossing critical threshold', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(90),
          key_type: 'direct',
        }),
      ]);

      await service.handleExpirationCheckCron();

      expect(
        mockEmailService.sendByokDirectRotationCritical,
      ).toHaveBeenCalledTimes(1);
    });

    it('skips silently when KeyAlertHistory insert hits a duplicate key error (11000)', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: daysAgo(76) }),
      ]);
      const dupErr = { code: 11000, name: 'MongoServerError' };
      mockKeyAlertHistoryModel.create.mockRejectedValue(dupErr);

      await service.handleExpirationCheckCron();

      // Attempted to insert but email was never sent
      expect(mockKeyAlertHistoryModel.create).toHaveBeenCalledTimes(1);
      expect(mockEmailService.sendByokRotationReminder).not.toHaveBeenCalled();
    });

    it('does not send email when org has no owner recipients', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({ rotated_at: daysAgo(76) }),
      ]);
      mockOrganizationMemberModel.find.mockReturnValue({
        populate: jest.fn().mockResolvedValue([]),
      });

      await service.handleExpirationCheckCron();

      expect(mockKeyAlertHistoryModel.create).toHaveBeenCalledTimes(1);
      expect(mockEmailService.sendByokRotationReminder).not.toHaveBeenCalled();
    });

    it('continues processing other alerts when EmailService throws', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          rotated_at: daysAgo(90), // critical
          organization_id: new Types.ObjectId(orgId),
        }),
        makeKeyRecord({
          rotated_at: daysAgo(82), // warning
          organization_id: new Types.ObjectId('507f1f77bcf86cd799439012'),
        }),
      ]);
      mockEmailService.sendByokRotationCritical.mockRejectedValue(
        new Error('mail provider down'),
      );

      await service.handleExpirationCheckCron();

      // Both alerts reserved in history
      expect(mockKeyAlertHistoryModel.create).toHaveBeenCalledTimes(2);
      // Warning still dispatched despite critical failure
      expect(mockEmailService.sendByokRotationWarning).toHaveBeenCalledTimes(1);
    });
  });

  describe('BYOK-045 direct key hybrid lifecycle', () => {
    const daysAgo = (n: number) => {
      const d = new Date();
      d.setDate(d.getDate() - n);
      return d;
    };

    beforeEach(() => {
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'BYOK_ALERTING_ENABLED') return true;
        return undefined;
      });
    });

    it('sends a critical email daily for direct keys inside the grace window', async () => {
      // Direct key at 100 days (10 days into 30-day grace)
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'direct',
          rotated_at: daysAgo(100),
        }),
      ]);
      mockOrgKeyModel.findOne.mockResolvedValue({
        rotation_interval_days: 90,
        acknowledged_until: null,
      });

      await service.handleExpirationCheckCron();

      const historyCall = mockKeyAlertHistoryModel.create.mock.calls[0][0];
      expect(historyCall.threshold).toBe('critical');
      // BYOK-045: direct critical uses today's date_key for daily re-send
      expect(historyCall.date_key).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(
        mockEmailService.sendByokDirectRotationCritical,
      ).toHaveBeenCalledTimes(1);
    });

    it('fires escalated state (no email, audit row only) past the grace period', async () => {
      // Direct key at 180 days — far past 90 + 30 = 120
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'direct',
          rotated_at: daysAgo(180),
        }),
      ]);
      mockOrgKeyModel.findOne.mockResolvedValue({
        rotation_interval_days: 90,
        acknowledged_until: null,
      });

      await service.handleExpirationCheckCron();

      const historyCall = mockKeyAlertHistoryModel.create.mock.calls[0][0];
      expect(historyCall.threshold).toBe('escalated');
      // BYOK-045: escalated uses stable version-based date_key (once per version)
      expect(historyCall.date_key).toBe('v1');
      // NO email sent — alert fatigue prevention
      expect(
        mockEmailService.sendByokDirectRotationCritical,
      ).not.toHaveBeenCalled();
      expect(mockEmailService.sendByokRotationReminder).not.toHaveBeenCalled();
    });

    it('does not send any email when acknowledged_until is in the future', async () => {
      // Direct key at 100 days, but admin acknowledged
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'direct',
          rotated_at: daysAgo(100),
        }),
      ]);
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 15);
      mockOrgKeyModel.findOne.mockResolvedValue({
        rotation_interval_days: 90,
        acknowledged_until: futureDate,
      });

      await service.handleExpirationCheckCron();

      expect(mockKeyAlertHistoryModel.create).not.toHaveBeenCalled();
      expect(
        mockEmailService.sendByokDirectRotationCritical,
      ).not.toHaveBeenCalled();
    });

    it('respects expired acknowledgment windows and resumes dispatch', async () => {
      // Direct key at 100 days, ack expired yesterday
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'direct',
          rotated_at: daysAgo(100),
        }),
      ]);
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 1);
      mockOrgKeyModel.findOne.mockResolvedValue({
        rotation_interval_days: 90,
        acknowledged_until: pastDate,
      });

      await service.handleExpirationCheckCron();

      // Normal dispatch flow resumes
      expect(mockKeyAlertHistoryModel.create).toHaveBeenCalledTimes(1);
      expect(
        mockEmailService.sendByokDirectRotationCritical,
      ).toHaveBeenCalledTimes(1);
    });

    it('still suppresses direct reminder when ack window is active', async () => {
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'direct',
          rotated_at: daysAgo(76),
        }),
      ]);
      const future = new Date();
      future.setDate(future.getDate() + 10);
      mockOrgKeyModel.findOne.mockResolvedValue({
        rotation_interval_days: 90,
        acknowledged_until: future,
      });

      await service.handleExpirationCheckCron();

      expect(mockKeyAlertHistoryModel.create).not.toHaveBeenCalled();
    });

    it('respects custom grace period from BYOK_ROTATION_GRACE_DAYS', async () => {
      // 7-day grace window + 90-day interval = escalated at day 97+
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'BYOK_ALERTING_ENABLED') return true;
        if (key === 'BYOK_ROTATION_GRACE_DAYS') return 7;
        return undefined;
      });
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'direct',
          rotated_at: daysAgo(100), // past 90+7
        }),
      ]);
      mockOrgKeyModel.findOne.mockResolvedValue({
        rotation_interval_days: 90,
        acknowledged_until: null,
      });

      await service.handleExpirationCheckCron();

      const historyCall = mockKeyAlertHistoryModel.create.mock.calls[0][0];
      expect(historyCall.threshold).toBe('escalated');
    });

    it('routes direct warning via direct template, not escalated', async () => {
      // 85 days out of 90 = 94% → warning (not yet critical)
      mockOrgKeyModel.find.mockResolvedValue([
        makeKeyRecord({
          key_type: 'direct',
          rotated_at: daysAgo(85),
        }),
      ]);
      mockOrgKeyModel.findOne.mockResolvedValue({
        rotation_interval_days: 90,
        acknowledged_until: null,
      });

      await service.handleExpirationCheckCron();

      expect(
        mockEmailService.sendByokDirectRotationWarning,
      ).toHaveBeenCalledTimes(1);
      const historyCall = mockKeyAlertHistoryModel.create.mock.calls[0][0];
      expect(historyCall.threshold).toBe('warning');
      // BYOK-045: warning uses stable v-key
      expect(historyCall.date_key).toBe('v1');
    });
  });

  describe('getKeyAgeDays', () => {
    it('should calculate correct age in days', () => {
      const fiveDaysAgo = new Date();
      fiveDaysAgo.setDate(fiveDaysAgo.getDate() - 5);
      const record = makeKeyRecord({ rotated_at: fiveDaysAgo });

      const ageDays = service.getKeyAgeDays(record);

      expect(ageDays).toBeGreaterThanOrEqual(5);
      expect(ageDays).toBeLessThan(6);
    });
  });
});
