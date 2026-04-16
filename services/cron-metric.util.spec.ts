import {
  emitCronMetric,
  CronMetricParams,
  CronMetricModel,
  CronMetricLogger,
} from './cron-metric.util';

describe('emitCronMetric', () => {
  let mockModel: { create: jest.Mock };
  let mockLogger: { log: jest.Mock; warn: jest.Mock };

  const baseParams = (): CronMetricParams => ({
    subsystem: 'byok',
    job: 'key_rotation',
    started_at: new Date('2026-04-11T03:00:00.000Z'),
    finished_at: new Date('2026-04-11T03:02:14.000Z'),
    processed: 42,
    succeeded: 40,
    skipped: 1,
    failed: 1,
    failures: [{ organization_id: 'org-xyz', error: 'KMS unreachable' }],
  });

  beforeEach(() => {
    mockModel = { create: jest.fn().mockResolvedValue({}) };
    mockLogger = { log: jest.fn(), warn: jest.fn() };
  });

  it('computes duration_ms from the timestamps', async () => {
    const duration = await emitCronMetric(
      baseParams(),
      mockModel as CronMetricModel,
      mockLogger as CronMetricLogger,
    );

    // 2 minutes 14 seconds = 134_000 ms
    expect(duration).toBe(134_000);
  });

  it('logs a structured JSON line to the provided logger', async () => {
    await emitCronMetric(
      baseParams(),
      mockModel as CronMetricModel,
      mockLogger as CronMetricLogger,
    );

    expect(mockLogger.log).toHaveBeenCalledTimes(1);
    const logLine = mockLogger.log.mock.calls[0][0] as string;
    expect(logLine).toContain('[cron-metric]');

    // Parse the JSON portion
    const jsonStr = logLine.replace(/^\[cron-metric\]\s*/, '');
    const parsed = JSON.parse(jsonStr);

    expect(parsed.subsystem).toBe('byok');
    expect(parsed.job).toBe('key_rotation');
    expect(parsed.duration_ms).toBe(134_000);
    expect(parsed.processed).toBe(42);
    expect(parsed.succeeded).toBe(40);
    expect(parsed.skipped).toBe(1);
    expect(parsed.failed).toBe(1);
    expect(parsed.failures).toEqual([
      { organization_id: 'org-xyz', error: 'KMS unreachable' },
    ]);
  });

  it('persists a document to the cron_run_log model', async () => {
    await emitCronMetric(
      baseParams(),
      mockModel as CronMetricModel,
      mockLogger as CronMetricLogger,
    );

    expect(mockModel.create).toHaveBeenCalledTimes(1);
    const doc = mockModel.create.mock.calls[0][0];

    expect(doc.subsystem).toBe('byok');
    expect(doc.job).toBe('key_rotation');
    expect(doc.duration_ms).toBe(134_000);
    expect(doc.processed).toBe(42);
    expect(doc.succeeded).toBe(40);
    expect(doc.failures).toHaveLength(1);
  });

  it('defaults failures to an empty array when omitted', async () => {
    const params = baseParams();
    delete params.failures;

    await emitCronMetric(
      params,
      mockModel as CronMetricModel,
      mockLogger as CronMetricLogger,
    );

    const doc = mockModel.create.mock.calls[0][0];
    expect(doc.failures).toEqual([]);

    const logLine = mockLogger.log.mock.calls[0][0] as string;
    const parsed = JSON.parse(logLine.replace(/^\[cron-metric\]\s*/, ''));
    expect(parsed.failures).toEqual([]);
  });

  it('does not throw when the model.create call fails', async () => {
    mockModel.create.mockRejectedValue(new Error('mongodb unavailable'));

    await expect(
      emitCronMetric(
        baseParams(),
        mockModel as CronMetricModel,
        mockLogger as CronMetricLogger,
      ),
    ).resolves.toBe(134_000);

    // Warning is logged but the error is swallowed
    expect(mockLogger.warn).toHaveBeenCalled();
    const warning = mockLogger.warn.mock.calls[0][0] as string;
    expect(warning).toContain('Failed to persist');
    expect(warning).toContain('mongodb unavailable');
  });

  it('handles each of the three BYOK jobs without special casing', async () => {
    for (const job of [
      'key_rotation',
      'key_expiration_monitor',
      'restore_drill',
    ] as const) {
      const params = baseParams();
      params.job = job;

      await emitCronMetric(
        params,
        mockModel as CronMetricModel,
        mockLogger as CronMetricLogger,
      );
    }

    expect(mockModel.create).toHaveBeenCalledTimes(3);
    expect(mockModel.create.mock.calls[0][0].job).toBe('key_rotation');
    expect(mockModel.create.mock.calls[1][0].job).toBe(
      'key_expiration_monitor',
    );
    expect(mockModel.create.mock.calls[2][0].job).toBe('restore_drill');
  });

  it('produces a valid ISO-8601 string in the log payload', async () => {
    await emitCronMetric(
      baseParams(),
      mockModel as CronMetricModel,
      mockLogger as CronMetricLogger,
    );

    const logLine = mockLogger.log.mock.calls[0][0] as string;
    const parsed = JSON.parse(logLine.replace(/^\[cron-metric\]\s*/, ''));

    expect(parsed.started_at).toBe('2026-04-11T03:00:00.000Z');
    expect(parsed.finished_at).toBe('2026-04-11T03:02:14.000Z');
  });
});
