import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument } from 'mongoose';

export type CronRunLogDocument = HydratedDocument<CronRunLog>;

export interface CronFailureEntry {
  organization_id: string;
  error: string;
}

/**
 * BYOK-090 / §15.1: Structured cron run metrics for the BYOK subsystem.
 *
 * Persisted to a MongoDB capped collection (default 10 MB) so the most
 * recent N runs are retained without unbounded growth. Capped collections
 * evict oldest entries automatically when the size limit is reached.
 *
 * Consumed by:
 *   - BYOK-092 admin dashboard widget (aggregates last 24h)
 *   - BYOK-093 DevOps alert routing (watches for consecutive failures)
 *   - Operators tailing logs for live visibility
 *
 * The schema is intentionally flat — no nested subdocuments beyond the
 * failures array — so capped collection size accounting is predictable.
 */
@Schema({
  timestamps: false,
  collection: 'cron_run_log',
  capped: { size: 10 * 1024 * 1024, max: 10000 },
})
export class CronRunLog {
  @Prop({ type: String, required: true, index: true })
  subsystem: string;

  @Prop({ type: String, required: true, index: true })
  job: string;

  @Prop({ type: Date, required: true })
  started_at: Date;

  @Prop({ type: Date, required: true })
  finished_at: Date;

  @Prop({ type: Number, required: true })
  duration_ms: number;

  @Prop({ type: Number, required: true, default: 0 })
  processed: number;

  @Prop({ type: Number, required: true, default: 0 })
  succeeded: number;

  @Prop({ type: Number, required: true, default: 0 })
  skipped: number;

  @Prop({ type: Number, required: true, default: 0 })
  failed: number;

  @Prop({
    type: [
      {
        organization_id: String,
        error: String,
        _id: false,
      },
    ],
    default: [],
  })
  failures: CronFailureEntry[];
}

export const CronRunLogSchema = SchemaFactory.createForClass(CronRunLog);

// Compound index for the dashboard query: most recent runs by job.
CronRunLogSchema.index({ subsystem: 1, job: 1, started_at: -1 });
