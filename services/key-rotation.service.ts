import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CronJobCategory } from '@app/database';
import { CronRegistryService } from '@app/cron-registry';
import {
  OrganizationKey,
  OrganizationKeyDocument,
} from '../schemas/organization-key.schema';
import {
  CronRunLog,
  CronRunLogDocument,
  CronFailureEntry,
} from '../schemas/cron-run-log.schema';
import { KeyManagementService } from './key-management.service';
import { KeyRotationValidationError } from '../errors/key-rotation.errors';
import { emitCronMetric } from './cron-metric.util';

const DEFAULT_MAX_PER_RUN = 100;

export interface AutoRotationResult {
  rotated: number;
  skipped: number;
  errors: number;
  deferred: number;
  failures: CronFailureEntry[];
}

@Injectable()
export class KeyRotationService implements OnModuleInit {
  private readonly logger = new Logger(KeyRotationService.name);

  constructor(
    @InjectModel(OrganizationKey.name)
    private readonly organizationKeyModel: Model<OrganizationKeyDocument>,
    private readonly keyManagementService: KeyManagementService,
    private readonly configService: ConfigService,
    @InjectModel(CronRunLog.name)
    private readonly cronRunLogModel: Model<CronRunLogDocument>,
    private readonly cronRegistry: CronRegistryService,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.cronRegistry.register({
      name: 'byok-key-rotation',
      displayName: 'BYOK Auto Key Rotation',
      description:
        'Rotaciona automaticamente chaves BYOK que atingiram o intervalo configurado. Runs diariamente às 03:00 UTC.',
      schedule: '0 3 * * *',
      category: CronJobCategory.ENCRYPTION,
      handler: () => this.handleAutoRotationCron(),
    });
  }

  async handleAutoRotationCron(): Promise<void> {
    this.logger.log('Starting scheduled auto-rotation check');

    // BYOK-091: Emit structured cron metrics on every run, even when
    // handleAutoRotation throws. The finally block captures whatever
    // state we accumulated before the failure and persists it for the
    // dashboard and alert routing.
    const startedAt = new Date();
    let results: AutoRotationResult = {
      rotated: 0,
      skipped: 0,
      errors: 0,
      deferred: 0,
      failures: [],
    };

    try {
      results = await this.handleAutoRotation();
      this.logger.log(
        `Auto-rotation complete: ${results.rotated} rotated, ${results.skipped} skipped, ${results.errors} errors, ${results.deferred} deferred`,
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.logger.error(`Auto-rotation cron crashed: ${message}`);
      results.errors++;
      results.failures.push({ organization_id: '__cron__', error: message });
    } finally {
      await emitCronMetric(
        {
          subsystem: 'byok',
          job: 'key_rotation',
          started_at: startedAt,
          finished_at: new Date(),
          processed: results.rotated + results.skipped + results.errors,
          succeeded: results.rotated,
          skipped: results.skipped,
          failed: results.errors,
          failures: results.failures,
        },
        this.cronRunLogModel,
        this.logger,
      );
    }
  }

  /**
   * BYOK-050/051: Daily auto-rotation loop.
   *
   * Iterates organizations with auto_rotate=true, rotates due keys via
   * the appropriate method on KeyManagementService (two-phase commit
   * with validation from BYOK-011/012), and tracks failures on the
   * OrganizationKey document so subsequent runs can back off.
   *
   * Safety guards:
   *   - `direct` keys are skipped (customer holds the key, cannot rotate)
   *   - `gcp-kms`/`azure-kms` now route through rotateByokKey along with
   *     `aws-kms` — providers are wired in BYOK-024
   *   - Per-run cap (`BYOK_AUTO_ROTATION_MAX_PER_RUN`, default 100)
   *     prevents runaway processing; remaining orgs are counted as
   *     `deferred` and processed in the next cron run
   *   - Transient failures retry ONCE in-loop; KeyRotationValidationError
   *     is treated as permanent for this run (the candidate key is
   *     definitively broken, retrying cannot help)
   *   - On persistent failure, last_rotation_error.attempts is
   *     incremented cumulatively across cron runs — the dashboard uses
   *     this counter to surface orgs that need manual intervention
   *   - On success, last_rotation_error is cleared
   */
  async handleAutoRotation(): Promise<AutoRotationResult> {
    const maxPerRun =
      this.configService.get<number>('BYOK_AUTO_ROTATION_MAX_PER_RUN') ??
      DEFAULT_MAX_PER_RUN;

    const allKeys = await this.organizationKeyModel.find({ auto_rotate: true });
    const keys = allKeys.slice(0, maxPerRun);
    const deferred = allKeys.length - keys.length;

    if (deferred > 0) {
      this.logger.warn(
        `Per-run cap reached (${maxPerRun}). Deferring ${deferred} organizations to next run.`,
      );
    }

    let rotated = 0;
    let skipped = 0;
    let errors = 0;
    const failures: CronFailureEntry[] = [];

    for (const record of keys) {
      const keyType = record.key_type;

      // Direct BYOK keys cannot be auto-rotated (require customer key)
      if (keyType === 'direct') {
        this.logger.warn(
          `Skipping auto-rotation for direct BYOK key (org: ${record.organization_id}). Customer key required.`,
        );
        skipped++;
        continue;
      }

      // Check if rotation is due
      if (!this.isRotationDue(record)) {
        skipped++;
        continue;
      }

      const orgId = record.organization_id.toString();

      try {
        await this.rotateWithRetry(keyType, orgId);
        rotated++;
        this.logger.log(
          `Auto-rotated ${keyType} key for organization: ${record.organization_id}`,
        );
        await this.clearRotationError(record._id);
      } catch (err) {
        errors++;
        const message = err instanceof Error ? err.message : String(err);
        this.logger.error(
          `Failed to auto-rotate key for organization ${record.organization_id}: ${message}`,
        );
        failures.push({ organization_id: orgId, error: message });
        await this.recordRotationError(record._id, message);
      }
    }

    return { rotated, skipped, errors, deferred, failures };
  }

  /**
   * BYOK-051: Per-org retry envelope. Retries transient failures ONCE
   * inside the same cron run. Does NOT retry KeyRotationValidationError
   * because a failed pipeline validation means the candidate key is
   * definitively broken — retrying generates new random keys with the
   * same broken provider, wasting KMS operations. Such cases should
   * surface in last_rotation_error.attempts and be investigated manually.
   */
  private async rotateWithRetry(keyType: string, orgId: string): Promise<void> {
    try {
      await this.dispatchRotation(keyType, orgId);
      return;
    } catch (err) {
      if (err instanceof KeyRotationValidationError) {
        // Validation failures are permanent — do not retry
        throw err;
      }
      this.logger.warn(
        `Transient rotation failure for org ${orgId} — retrying once: ${(err as Error).message}`,
      );
      // Single in-loop retry; any subsequent failure bubbles up
      await this.dispatchRotation(keyType, orgId);
    }
  }

  /**
   * BYOK-050: Routes to the correct KeyManagementService method based on
   * key type. `managed` uses rotateOrganizationKey; all BYOK types
   * (aws-kms, gcp-kms, azure-kms) share rotateByokKey which dispatches
   * internally via getProvider() (BYOK-024).
   */
  private async dispatchRotation(
    keyType: string,
    orgId: string,
  ): Promise<void> {
    if (keyType === 'managed') {
      await this.keyManagementService.rotateOrganizationKey(orgId);
      return;
    }

    if (
      keyType === 'aws-kms' ||
      keyType === 'gcp-kms' ||
      keyType === 'azure-kms'
    ) {
      await this.keyManagementService.rotateByokKey(orgId);
      return;
    }

    throw new Error(`Unsupported key type for auto-rotation: ${keyType}`);
  }

  private async recordRotationError(
    recordId: OrganizationKeyDocument['_id'],
    message: string,
  ): Promise<void> {
    try {
      // Use a two-stage approach since $inc on a nested object that may
      // not exist yet requires careful handling. We read the current
      // value and rewrite the whole structure.
      const current = await this.organizationKeyModel.findOne({
        _id: recordId,
      });
      const priorAttempts = current?.last_rotation_error?.attempts ?? 0;

      await this.organizationKeyModel.updateOne(
        { _id: recordId },
        {
          $set: {
            last_rotation_error: {
              attempted_at: new Date(),
              error: message,
              attempts: priorAttempts + 1,
            },
          },
        },
      );
    } catch (writeErr) {
      const writeMessage =
        writeErr instanceof Error ? writeErr.message : String(writeErr);
      this.logger.warn(
        `Failed to persist last_rotation_error on ${String(recordId)}: ${writeMessage}`,
      );
    }
  }

  private async clearRotationError(
    recordId: OrganizationKeyDocument['_id'],
  ): Promise<void> {
    try {
      await this.organizationKeyModel.updateOne(
        { _id: recordId },
        { $set: { last_rotation_error: null } },
      );
    } catch (writeErr) {
      const writeMessage =
        writeErr instanceof Error ? writeErr.message : String(writeErr);
      this.logger.warn(
        `Failed to clear last_rotation_error on ${String(recordId)}: ${writeMessage}`,
      );
    }
  }

  private isRotationDue(record: OrganizationKeyDocument): boolean {
    const lastRotation = record.rotated_at || record.createdAt;
    const intervalDays = record.rotation_interval_days || 90;
    const now = new Date();
    const daysSinceRotation =
      (now.getTime() - new Date(lastRotation).getTime()) /
      (1000 * 60 * 60 * 24);

    return daysSinceRotation >= intervalDays;
  }
}
