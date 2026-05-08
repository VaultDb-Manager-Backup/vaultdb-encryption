import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import {
  OrganizationKey,
  OrganizationKeyDocument,
} from '../schemas/organization-key.schema';
import {
  CronRunLog,
  CronRunLogDocument,
  CronFailureEntry,
} from '../schemas/cron-run-log.schema';
import {
  KeyAlertHistory,
  KeyAlertHistoryDocument,
  KeyAlertThreshold,
} from '../schemas/key-alert-history.schema';
import { emitCronMetric } from './cron-metric.util';
import { EmailService, BYOKRotationAlertData } from '@app/email';
import {
  Organization,
  OrganizationDocument,
  OrganizationMember,
  OrganizationMemberDocument,
  CronJobCategory,
} from '@app/database';
import { CronRegistryService } from '@app/cron-registry';

// BYOK-043: Thresholds expressed as percentages of each org's
// rotation_interval_days. A customer who shortens their interval to
// 30 days gets reminders at 22 / 27 / 30 days, not at the old
// hardcoded 83 / 90 day marks.
const DEFAULT_REMINDER_PCT = 75;
const DEFAULT_WARNING_PCT = 90;
const DEFAULT_CRITICAL_PCT = 100;

// BYOK-045: Grace period (in days) past 100% before a direct BYOK key
// transitions from `critical` to `escalated`. During grace, daily
// critical emails re-send; past grace, emails stop and the dashboard
// shows a sticky banner until admin acks or customer rotates.
const DEFAULT_ROTATION_GRACE_DAYS = 30;

/**
 * BYOK-045: Direct BYOK key lifecycle state machine.
 *
 * Non-direct keys use the simpler 3-bucket classification
 * (reminder/warning/critical) from `checkKeyAges`. Direct keys have
 * additional semantics: a grace period of daily critical re-sends
 * followed by a sticky `escalated` state where emails stop entirely
 * but the audit row and dashboard banner persist.
 */
type DirectKeyLifecycleState =
  | 'healthy'
  | 'reminder'
  | 'warning'
  | 'critical'
  | 'escalated';

export interface KeyAgeAlert {
  organizationId: string;
  keyType: string;
  ageDays: number;
  version: number;
}

export interface KeyAgeCheckResult {
  healthy: number;
  reminders: KeyAgeAlert[];
  warnings: KeyAgeAlert[];
  critical: KeyAgeAlert[];
}

interface ThresholdPercentages {
  reminderPct: number;
  warningPct: number;
  criticalPct: number;
}

@Injectable()
export class KeyExpirationMonitorService implements OnModuleInit {
  private readonly logger = new Logger(KeyExpirationMonitorService.name);

  constructor(
    @InjectModel(OrganizationKey.name)
    private readonly organizationKeyModel: Model<OrganizationKeyDocument>,
    @InjectModel(CronRunLog.name)
    private readonly cronRunLogModel: Model<CronRunLogDocument>,
    @InjectModel(KeyAlertHistory.name)
    private readonly keyAlertHistoryModel: Model<KeyAlertHistoryDocument>,
    @InjectModel(Organization.name)
    private readonly organizationModel: Model<OrganizationDocument>,
    @InjectModel(OrganizationMember.name)
    private readonly organizationMemberModel: Model<OrganizationMemberDocument>,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
    private readonly cronRegistry: CronRegistryService,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.cronRegistry.register({
      name: 'byok-key-expiration-monitor',
      displayName: 'BYOK Key Expiration Monitor',
      description:
        'Monitora chaves BYOK próximas do fim do intervalo de rotação e envia alertas (reminder/warning/critical). Runs diariamente às 08:00 UTC.',
      schedule: '0 8 * * *',
      category: CronJobCategory.ENCRYPTION,
      handler: () => this.handleExpirationCheckCron(),
    });
  }

  /**
   * BYOK-043: Read thresholds from env once per cron run. Env miss falls
   * back to CON-03 default values (75 / 90 / 100 %).
   */
  private readThresholds(): ThresholdPercentages {
    return {
      reminderPct:
        this.configService.get<number>('BYOK_ROTATION_REMINDER_PCT') ??
        DEFAULT_REMINDER_PCT,
      warningPct:
        this.configService.get<number>('BYOK_ROTATION_WARNING_PCT') ??
        DEFAULT_WARNING_PCT,
      criticalPct:
        this.configService.get<number>('BYOK_ROTATION_CRITICAL_PCT') ??
        DEFAULT_CRITICAL_PCT,
    };
  }

  /**
   * BYOK-045: Compute the direct key lifecycle state from age + config.
   * Pure function — used by dispatchAlerts to decide whether to send
   * a daily critical, fire an escalation, or suppress emails.
   */
  private computeDirectLifecycleState(
    ageDays: number,
    intervalDays: number,
  ): DirectKeyLifecycleState {
    const { reminderPct, warningPct, criticalPct } = this.readThresholds();
    const graceDays =
      this.configService.get<number>('BYOK_ROTATION_GRACE_DAYS') ??
      DEFAULT_ROTATION_GRACE_DAYS;

    const agePct = (ageDays / intervalDays) * 100;
    const graceThresholdDays = intervalDays + graceDays;

    if (ageDays >= graceThresholdDays) return 'escalated';
    if (agePct >= criticalPct) return 'critical';
    if (agePct >= warningPct) return 'warning';
    if (agePct >= reminderPct) return 'reminder';
    return 'healthy';
  }

  async handleExpirationCheckCron(): Promise<void> {
    this.logger.log('Starting scheduled key expiration check');

    // BYOK-091: Structured cron metrics on every run including the
    // exception path. Healthy keys map to `succeeded`, reminder/warning/
    // critical fold into `failed` for dashboard "attention required"
    // visibility.
    const startedAt = new Date();
    let healthy = 0;
    let reminders = 0;
    let warnings = 0;
    let critical = 0;
    const failures: CronFailureEntry[] = [];

    try {
      const results = await this.checkKeyAges();
      healthy = results.healthy;
      reminders = results.reminders.length;
      warnings = results.warnings.length;
      critical = results.critical.length;

      this.logger.log(
        `Key age check complete: ${healthy} healthy, ${reminders} reminders, ${warnings} warnings, ${critical} critical`,
      );

      for (const alert of results.critical) {
        this.logger.error(
          `CRITICAL: Key for organization ${alert.organizationId} is ${alert.ageDays} days old (type: ${alert.keyType}, version: ${alert.version})`,
        );
      }

      for (const alert of results.warnings) {
        this.logger.warn(
          `WARNING: Key for organization ${alert.organizationId} is ${alert.ageDays} days old (type: ${alert.keyType}, version: ${alert.version})`,
        );
      }

      for (const alert of results.reminders) {
        this.logger.log(
          `REMINDER: Key for organization ${alert.organizationId} is ${alert.ageDays} days old (type: ${alert.keyType}, version: ${alert.version})`,
        );
      }

      // BYOK-044: dispatch email alerts with idempotency via KeyAlertHistory
      await this.dispatchAlerts(results);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.error(`Expiration check cron crashed: ${message}`);
      failures.push({ organization_id: '__cron__', error: message });
    } finally {
      // BYOK-091 refinement: reminders/warnings/critical are NOT cron
      // failures. They are operator-attention signals (keys nearing
      // rotation). Folding them into `failed` made the BYOK health
      // dashboard report FALHOU on every healthy run that found a
      // single key in the warning window. We keep `failed` strictly
      // for exceptions and surface attention items in their own
      // counter for the dashboard.
      await emitCronMetric(
        {
          subsystem: 'byok',
          job: 'key_expiration_monitor',
          started_at: startedAt,
          finished_at: new Date(),
          processed:
            healthy + reminders + warnings + critical + failures.length,
          succeeded: healthy,
          skipped: 0,
          attention: reminders + warnings + critical,
          failed: failures.length,
          failures,
        },
        this.cronRunLogModel,
        this.logger,
      );
    }
  }

  async checkKeyAges(): Promise<KeyAgeCheckResult> {
    // Managed keys are VaultDB-internal infra. Customers never configured
    // them, so reminding them to "rotate the key" is noise — and worse,
    // the rotate-now button leads them to a settings page that does not
    // apply. The auto-rotation cron handles managed keys silently.
    const keys = await this.organizationKeyModel.find({
      key_type: { $ne: 'managed' },
    });
    const { reminderPct, warningPct, criticalPct } = this.readThresholds();

    let healthy = 0;
    const reminders: KeyAgeAlert[] = [];
    const warnings: KeyAgeAlert[] = [];
    const critical: KeyAgeAlert[] = [];

    for (const record of keys) {
      const ageDays = this.getKeyAgeDays(record);
      const intervalDays = record.rotation_interval_days || 90;
      const agePct = (ageDays / intervalDays) * 100;

      const alert: KeyAgeAlert = {
        organizationId: record.organization_id.toString(),
        keyType: record.key_type,
        ageDays,
        version: record.version,
      };

      // Highest-severity match wins — check critical first, then warning,
      // then reminder. A key at 100% of a 90-day interval matches all
      // three buckets mathematically but should only be reported once.
      if (agePct >= criticalPct) {
        critical.push(alert);
      } else if (agePct >= warningPct) {
        warnings.push(alert);
      } else if (agePct >= reminderPct) {
        reminders.push(alert);
      } else {
        healthy++;
      }
    }

    return { healthy, reminders, warnings, critical };
  }

  getKeyAgeDays(record: OrganizationKeyDocument): number {
    const lastRotation = record.rotated_at || record.createdAt;
    const now = new Date();
    return (
      (now.getTime() - new Date(lastRotation).getTime()) / (1000 * 60 * 60 * 24)
    );
  }

  /**
   * BYOK-044: Dispatch email alerts for each threshold crossing with
   * idempotency via KeyAlertHistory.
   *
   * Guard: BYOK_ALERTING_ENABLED env flag. When false, logs each would-be
   * alert and returns without touching KeyAlertHistory — flipping the flag
   * later lets the first batch of alerts flow naturally on the next run.
   *
   * Idempotency pattern: for each alert, try to insert a KeyAlertHistory
   * row first. On duplicate-key error (11000), another run already claimed
   * the slot — skip silently. On any other error, log and skip this alert
   * but continue processing the rest. On successful insert, send the
   * email via EmailService.
   *
   * Email send failures are logged but never block the cron — observability
   * must not become a reliability risk.
   */
  async dispatchAlerts(results: KeyAgeCheckResult): Promise<void> {
    const enabled =
      this.configService.get<boolean>('BYOK_ALERTING_ENABLED') ?? false;

    const allAlerts: Array<{
      alert: KeyAgeAlert;
      threshold: KeyAlertThreshold;
    }> = [
      ...results.critical.map((alert) => ({
        alert,
        threshold: 'critical' as KeyAlertThreshold,
      })),
      ...results.warnings.map((alert) => ({
        alert,
        threshold: 'warning' as KeyAlertThreshold,
      })),
      ...results.reminders.map((alert) => ({
        alert,
        threshold: 'reminder' as KeyAlertThreshold,
      })),
    ];

    if (!enabled) {
      if (allAlerts.length > 0) {
        this.logger.log(
          `BYOK_ALERTING_ENABLED=false — would have dispatched ${allAlerts.length} alert(s) but emails are gated off`,
        );
      }
      return;
    }

    const dateKey = new Date().toISOString().split('T')[0];

    for (const { alert, threshold } of allAlerts) {
      await this.processAlert(alert, threshold, dateKey);
    }
  }

  private async processAlert(
    alert: KeyAgeAlert,
    initialThreshold: KeyAlertThreshold,
    todayDateKey: string,
  ): Promise<void> {
    // Load the record upfront — we need key_type, acknowledged_until,
    // rotation_interval_days for both threshold resolution and email data
    const record = await this.organizationKeyModel.findOne({
      organization_id: new Types.ObjectId(alert.organizationId),
    });

    if (!record) {
      this.logger.warn(
        `Record vanished between checkKeyAges and dispatch for org ${alert.organizationId} — skipping`,
      );
      return;
    }

    // BYOK-045: Admin acknowledgment window suppresses all email dispatch
    // for this record. The lifecycle state machine still operates — we
    // just don't send anything while ack is active. When ack expires,
    // the next cron run processes naturally.
    const ackUntil = record.acknowledged_until;
    if (ackUntil && ackUntil.getTime() > Date.now()) {
      this.logger.log(
        `Alerts suppressed for org ${alert.organizationId} until ${ackUntil.toISOString()} (admin acknowledged)`,
      );
      return;
    }

    const isDirect = alert.keyType === 'direct';
    const intervalDays = record.rotation_interval_days || 90;

    // BYOK-045: For direct keys, compute the lifecycle state which may
    // override `critical` → `escalated` based on grace period, or
    // `critical` → `healthy` if something weird happens.
    const lifecycleState: DirectKeyLifecycleState = isDirect
      ? this.computeDirectLifecycleState(alert.ageDays, intervalDays)
      : initialThreshold;

    // Healthy after lifecycle check means nothing to do. The `healthy`
    // variant is only reachable from the direct-key path.
    if (lifecycleState === 'healthy') return;

    const effectiveThreshold: KeyAlertThreshold = lifecycleState;

    // BYOK-045: date_key scheme
    //   - direct + critical during grace → today (daily re-send)
    //   - everything else → 'v{version}' (once per version)
    // This lets escalated/reminder/warning fire exactly once per version
    // while direct critical keeps pinging during the grace window.
    const dateKey =
      isDirect && effectiveThreshold === 'critical'
        ? todayDateKey
        : `v${alert.version}`;

    // Step 1: reserve the idempotency slot via a unique-index insert
    try {
      await this.keyAlertHistoryModel.create({
        organization_id: new Types.ObjectId(alert.organizationId),
        key_version: alert.version,
        threshold: effectiveThreshold,
        date_key: dateKey,
      });
    } catch (err) {
      if (this.isDuplicateKeyError(err)) {
        // Another run already sent this alert — skip silently
        return;
      }
      this.logger.warn(
        `Failed to persist KeyAlertHistory for org ${alert.organizationId}, threshold=${effectiveThreshold}: ${(err as Error).message}`,
      );
      return;
    }

    // BYOK-045: `escalated` state reserves the audit row but does NOT
    // send an email. The dashboard banner (BYOK-073) reads this row to
    // know the escalation fired. Alert fatigue prevention — past grace,
    // re-sending daily emails erodes trust without helping.
    if (effectiveThreshold === 'escalated') {
      this.logger.warn(
        `DIRECT BYOK key escalated for org ${alert.organizationId} (age ${alert.ageDays}d past grace period) — banner sticky, no further emails`,
      );
      return;
    }

    // Step 2: load recipient context
    const context = await this.loadAlertContext(alert.organizationId);
    if (!context || context.recipients.length === 0) {
      this.logger.warn(
        `No owner recipients for org ${alert.organizationId} — alert slot reserved but no email sent`,
      );
      return;
    }

    // Step 3: build template data
    const percentage = (alert.ageDays / intervalDays) * 100;
    const emailData: BYOKRotationAlertData = {
      userName: context.primaryUserName,
      orgName: context.orgName,
      ageDays: alert.ageDays,
      intervalDays,
      percentage,
    };

    // Step 4: dispatch via EmailService based on key type + threshold
    try {
      if (isDirect) {
        await this.sendDirectAlert(
          context.recipients,
          effectiveThreshold,
          emailData,
        );
      } else {
        await this.sendStandardAlert(
          context.recipients,
          effectiveThreshold,
          emailData,
        );
      }
      this.logger.log(
        `Sent ${effectiveThreshold} alert to ${context.recipients.length} recipient(s) for org ${alert.organizationId}`,
      );
    } catch (sendErr) {
      // Email failures MUST NOT break the cron. The history row remains
      // to prevent retry spam.
      this.logger.error(
        `Failed to send ${effectiveThreshold} alert for org ${alert.organizationId}: ${(sendErr as Error).message}`,
      );
    }
  }

  private async sendStandardAlert(
    recipients: string[],
    threshold: KeyAlertThreshold,
    data: BYOKRotationAlertData,
  ): Promise<void> {
    switch (threshold) {
      case 'reminder':
        await this.emailService.sendByokRotationReminder(recipients, data);
        return;
      case 'warning':
        await this.emailService.sendByokRotationWarning(recipients, data);
        return;
      case 'critical':
        await this.emailService.sendByokRotationCritical(recipients, data);
        return;
      case 'escalated':
        // escalated is handled by BYOK-045 direct lifecycle — no-op here
        return;
    }
  }

  private async sendDirectAlert(
    recipients: string[],
    threshold: KeyAlertThreshold,
    data: BYOKRotationAlertData,
  ): Promise<void> {
    switch (threshold) {
      case 'reminder':
        // BYOK-044 scope: reuse the generic reminder template for direct
        // reminders. BYOK-045 adds a direct-specific reminder template.
        await this.emailService.sendByokRotationReminder(recipients, data);
        return;
      case 'warning':
        await this.emailService.sendByokDirectRotationWarning(recipients, data);
        return;
      case 'critical':
        await this.emailService.sendByokDirectRotationCritical(
          recipients,
          data,
        );
        return;
      case 'escalated':
        return;
    }
  }

  /**
   * Load the organization name and owner email addresses for an alert.
   * Returns null if the organization no longer exists (e.g. deleted
   * between checkKeyAges and dispatch).
   */
  private async loadAlertContext(orgIdStr: string): Promise<{
    orgName: string;
    recipients: string[];
    primaryUserName: string;
  } | null> {
    try {
      const orgId = new Types.ObjectId(orgIdStr);
      const org = await this.organizationModel.findOne({ _id: orgId });
      if (!org) return null;

      const members = await this.organizationMemberModel
        .find({ organization_id: orgId, role: 'owner' })
        .populate<{ user_id: { email: string; name?: string } }>('user_id');

      const recipients: string[] = [];
      let primaryUserName = 'Admin';
      for (const member of members) {
        const user = member.user_id as unknown as {
          email?: string;
          name?: string;
        };
        if (user?.email) {
          recipients.push(user.email);
          if (primaryUserName === 'Admin' && user.name) {
            primaryUserName = user.name;
          }
        }
      }

      return {
        orgName: (org as unknown as { name?: string }).name ?? 'Organization',
        recipients,
        primaryUserName,
      };
    } catch (err) {
      this.logger.warn(
        `Failed to load alert context for org ${orgIdStr}: ${(err as Error).message}`,
      );
      return null;
    }
  }

  private isDuplicateKeyError(err: unknown): boolean {
    const e = err as { code?: number; name?: string } | null;
    return e?.code === 11000 || e?.name === 'MongoServerError';
  }
}
