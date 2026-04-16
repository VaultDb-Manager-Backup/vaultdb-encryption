/**
 * BYOK-090 / §15.1: Shared cron metric emitter for the BYOK subsystem.
 *
 * Produces two outputs per invocation:
 *   1. A structured JSON log line via the passed logger, so tail-based
 *      log aggregation can index and query runs without touching the
 *      database.
 *   2. A document in the `cron_run_log` capped collection so the admin
 *      dashboard (BYOK-092) and DevOps alerts (BYOK-093) have a
 *      persistent, queryable source of truth.
 *
 * Kept as a pure async function (no NestJS decorators) so it is trivially
 * unit-testable. Callers inject their own logger and model — matching the
 * pattern of restore-key-resolver (BYOK-014) and byok-backfill (BYOK-015).
 *
 * Design: the helper never throws. A failure to persist the metric is
 * logged as a warning and swallowed so it cannot break the calling cron
 * flow. Observability should not become a reliability risk.
 */

import { Model } from 'mongoose';
import { CronRunLog, CronFailureEntry } from '../schemas/cron-run-log.schema';

export interface CronMetricParams {
  subsystem: 'byok';
  job: 'key_rotation' | 'key_expiration_monitor' | 'restore_drill';
  started_at: Date;
  finished_at: Date;
  processed: number;
  succeeded: number;
  skipped: number;
  failed: number;
  failures?: CronFailureEntry[];
}

export interface CronMetricLogger {
  log(message: string): void;
  warn(message: string): void;
}

export type CronMetricModel = Pick<Model<CronRunLog>, 'create'>;

/**
 * Emits a cron metric. Returns the computed `duration_ms` so callers
 * can log it directly if they want, but the primary output is the
 * stdout log line + persisted document.
 */
export async function emitCronMetric(
  params: CronMetricParams,
  model: CronMetricModel,
  logger: CronMetricLogger,
): Promise<number> {
  const duration_ms =
    params.finished_at.getTime() - params.started_at.getTime();

  const payload = {
    subsystem: params.subsystem,
    job: params.job,
    started_at: params.started_at.toISOString(),
    finished_at: params.finished_at.toISOString(),
    duration_ms,
    processed: params.processed,
    succeeded: params.succeeded,
    skipped: params.skipped,
    failed: params.failed,
    failures: params.failures ?? [],
  };

  // 1. Structured log line — tail-based aggregation path
  logger.log(`[cron-metric] ${JSON.stringify(payload)}`);

  // 2. Persistent record — dashboard / alerting path
  try {
    await model.create({
      subsystem: params.subsystem,
      job: params.job,
      started_at: params.started_at,
      finished_at: params.finished_at,
      duration_ms,
      processed: params.processed,
      succeeded: params.succeeded,
      skipped: params.skipped,
      failed: params.failed,
      failures: params.failures ?? [],
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.warn(
      `[cron-metric] Failed to persist cron_run_log entry for ${params.subsystem}.${params.job}: ${message}`,
    );
  }

  return duration_ms;
}
