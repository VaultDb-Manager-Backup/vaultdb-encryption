import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type KeyAlertHistoryDocument = HydratedDocument<KeyAlertHistory>;

export type KeyAlertThreshold =
  | 'reminder'
  | 'warning'
  | 'critical'
  | 'escalated';

/**
 * BYOK-040 / FR-05: Persistent record of alerts already sent for a given
 * (organization, key version, threshold) tuple. The unique compound index
 * enforces idempotency so a cron run that revisits the same threshold
 * cannot send duplicate emails.
 *
 * Consumed by:
 *   - BYOK-044 KeyExpirationMonitorService (check before sending, persist
 *     after sending via a single insert — duplicate key error means
 *     "another run already sent this alert", skip)
 *   - BYOK-045 direct-key hybrid lifecycle (uses `date_key` for daily
 *     critical-email dedup during the grace period)
 *   - BYOK-073 dashboard (lists recent alerts for operator visibility)
 *
 * `date_key` is the YYYY-MM-DD UTC date the alert was sent, used to
 * allow daily re-alerts for the direct-key critical state without
 * losing the overall idempotency contract for reminder/warning/escalated.
 *
 * `escalated` is sticky — one row per (org, version), matching the
 * FR-06 lifecycle state where emails stop but the audit event needs
 * to persist.
 */
@Schema({
  timestamps: true,
  collection: 'key_alert_history',
})
export class KeyAlertHistory {
  @Prop({
    type: Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true,
  })
  organization_id: Types.ObjectId;

  @Prop({ type: Number, required: true })
  key_version: number;

  @Prop({
    type: String,
    enum: ['reminder', 'warning', 'critical', 'escalated'],
    required: true,
  })
  threshold: KeyAlertThreshold;

  /**
   * UTC date string in YYYY-MM-DD format. For threshold values other
   * than `critical`, callers should use a single stable date_key per
   * key version (e.g. the date the threshold was first crossed) so the
   * compound index dedupes correctly. For `critical` direct-key alerts
   * during the grace period, each daily run uses the current UTC date
   * so one email per day is allowed.
   */
  @Prop({ type: String, required: true })
  date_key: string;

  @Prop({ type: Date, default: Date.now })
  sent_at: Date;

  createdAt: Date;
  updatedAt: Date;
}

export const KeyAlertHistorySchema =
  SchemaFactory.createForClass(KeyAlertHistory);

// Idempotency index — the core invariant of this collection.
// Insertion of a duplicate tuple throws a MongoServerError with code 11000
// which callers catch to detect "alert already sent, skip".
KeyAlertHistorySchema.index(
  { organization_id: 1, key_version: 1, threshold: 1, date_key: 1 },
  { unique: true },
);
