/**
 * BYOK-015: Idempotent backfill for OrganizationKey new fields.
 *
 * Runs once (or many times — it is idempotent) against an existing database
 * to initialize the fields added in BYOK-010 on documents that predate the
 * schema change. Mongoose's lazy defaults mean legacy documents "behave"
 * correctly at read time even without a backfill, but explicit initialization
 * produces deterministic query behavior and lets the plan-based
 * restore_drill_enabled default take effect before any read path exercises it.
 *
 * Fields initialized:
 *   - key_history: []
 *   - last_rotation_error: null
 *   - last_pipeline_validation: null
 *   - acknowledged_until: null
 *   - restore_drill_enabled: plan-dependent (free → false, paid/no-sub → false
 *     per CON-03 cost control, but users may opt in via dashboard)
 *
 * The logic is extracted as a pure class so it can be unit-tested without
 * spinning up a NestJS application. The thin bootstrap in
 * `scripts/backfill-byok-key-history.ts` wires this class to real models.
 */

import { Model } from 'mongoose';

export interface BackfillOptions {
  dryRun?: boolean;
}

export interface BackfillResult {
  scanned: number;
  updated: number;
  skipped: number;
  planBreakdown: {
    free: number;
    paid: number;
    noSubscription: number;
  };
  dryRun: boolean;
}

export interface BackfillLogger {
  log(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

type KeyDocShape = {
  _id: unknown;
  organization_id: unknown;
  key_history?: unknown[];
  last_rotation_error?: unknown;
  last_pipeline_validation?: unknown;
  acknowledged_until?: unknown;
  restore_drill_enabled?: unknown;
};

type SubscriptionShape = {
  organization_id: unknown;
  plan_id: unknown;
  status: string;
};

type PlanShape = {
  _id: unknown;
  slug: string;
  price: number;
};

/**
 * Determines whether a plan should receive the free-tier default for
 * `restore_drill_enabled`. Mirrors the CON-03 cost-control rule: free plans
 * default off, paid plans default on, orgs without an active subscription
 * are treated as free.
 */
export function isFreePlan(
  plan: Pick<PlanShape, 'slug' | 'price'> | null | undefined,
): boolean {
  if (!plan) return true;
  return plan.slug === 'free' || plan.price === 0;
}

const ACTIVE_SUBSCRIPTION_STATUSES = ['authorized', 'pending'];

export class ByokBackfillService {
  constructor(
    private readonly organizationKeyModel: Pick<
      Model<KeyDocShape>,
      'find' | 'updateOne'
    >,
    private readonly subscriptionModel: Pick<Model<SubscriptionShape>, 'find'>,
    private readonly planModel: Pick<Model<PlanShape>, 'find'>,
    private readonly logger: BackfillLogger = {
      log: (msg) => console.log(msg),
      warn: (msg) => console.warn(msg),
      error: (msg) => console.error(msg),
    },
  ) {}

  async run(options: BackfillOptions = {}): Promise<BackfillResult> {
    const dryRun = options.dryRun ?? false;

    const keys = await this.loadAllOrganizationKeys();
    this.logger.log(
      `[BYOK-backfill] Found ${keys.length} organization key documents`,
    );

    const orgIds = keys.map((k) => String(k.organization_id));
    const planMap = await this.buildPlanMap(orgIds);

    const result: BackfillResult = {
      scanned: keys.length,
      updated: 0,
      skipped: 0,
      planBreakdown: { free: 0, paid: 0, noSubscription: 0 },
      dryRun,
    };

    for (const key of keys) {
      const orgIdStr = String(key.organization_id);
      const plan = planMap.get(orgIdStr);

      if (!plan) {
        result.planBreakdown.noSubscription++;
      } else if (isFreePlan(plan)) {
        result.planBreakdown.free++;
      } else {
        result.planBreakdown.paid++;
      }

      const updates = this.computeUpdates(key, plan);

      if (Object.keys(updates).length === 0) {
        result.skipped++;
        continue;
      }

      if (!dryRun) {
        await this.organizationKeyModel.updateOne(
          { _id: key._id },
          { $set: updates },
        );
      }

      result.updated++;
    }

    this.logger.log(
      `[BYOK-backfill] ${dryRun ? 'DRY RUN — ' : ''}scanned=${result.scanned} updated=${result.updated} skipped=${result.skipped} free=${result.planBreakdown.free} paid=${result.planBreakdown.paid} no_subscription=${result.planBreakdown.noSubscription}`,
    );

    return result;
  }

  /**
   * Compute the $set update object for one document. Only populates fields
   * that are missing — already-backfilled docs produce an empty object and
   * are counted as skipped, preserving idempotency on repeat runs.
   */
  private computeUpdates(
    key: KeyDocShape,
    plan: PlanShape | undefined,
  ): Record<string, unknown> {
    const updates: Record<string, unknown> = {};

    if (key.key_history === undefined) {
      updates.key_history = [];
    }
    if (key.last_rotation_error === undefined) {
      updates.last_rotation_error = null;
    }
    if (key.last_pipeline_validation === undefined) {
      updates.last_pipeline_validation = null;
    }
    if (key.acknowledged_until === undefined) {
      updates.acknowledged_until = null;
    }
    if (key.restore_drill_enabled === undefined) {
      updates.restore_drill_enabled = !isFreePlan(plan);
    }

    return updates;
  }

  private async loadAllOrganizationKeys(): Promise<KeyDocShape[]> {
    const query = this.organizationKeyModel.find({});
    // .lean() is desirable for performance but not required for correctness;
    // the caller may inject a mock that doesn't implement lean.
    const leanOp = (query as unknown as { lean?: () => unknown }).lean;
    if (typeof leanOp === 'function') {
      return (await leanOp.call(query)) as KeyDocShape[];
    }
    return await (query as unknown as Promise<KeyDocShape[]>);
  }

  private async buildPlanMap(
    orgIds: string[],
  ): Promise<Map<string, PlanShape | undefined>> {
    const map = new Map<string, PlanShape | undefined>();

    if (orgIds.length === 0) return map;

    // Find active subscriptions for these orgs
    const subs = await this.findSubscriptions(orgIds);

    if (subs.length === 0) {
      return map; // every org will resolve to undefined (treated as free)
    }

    const planIds = Array.from(new Set(subs.map((s) => String(s.plan_id))));

    const plans = await this.findPlans(planIds);
    const planById = new Map<string, PlanShape>(
      plans.map((p) => [String(p._id), p]),
    );

    for (const sub of subs) {
      const plan = planById.get(String(sub.plan_id));
      if (plan) {
        map.set(String(sub.organization_id), plan);
      }
    }

    return map;
  }

  private async findSubscriptions(
    orgIds: string[],
  ): Promise<SubscriptionShape[]> {
    const query = this.subscriptionModel.find({
      organization_id: { $in: orgIds },
      status: { $in: ACTIVE_SUBSCRIPTION_STATUSES },
    });
    const leanOp = (query as unknown as { lean?: () => unknown }).lean;
    if (typeof leanOp === 'function') {
      return (await leanOp.call(query)) as SubscriptionShape[];
    }
    return await (query as unknown as Promise<SubscriptionShape[]>);
  }

  private async findPlans(planIds: string[]): Promise<PlanShape[]> {
    const query = this.planModel.find({ _id: { $in: planIds } });
    const leanOp = (query as unknown as { lean?: () => unknown }).lean;
    if (typeof leanOp === 'function') {
      return (await leanOp.call(query)) as PlanShape[];
    }
    return await (query as unknown as Promise<PlanShape[]>);
  }
}
