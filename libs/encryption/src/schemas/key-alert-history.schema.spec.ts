import * as mongoose from 'mongoose';
import {
  KeyAlertHistory,
  KeyAlertHistorySchema,
} from './key-alert-history.schema';

describe('KeyAlertHistorySchema', () => {
  const modelName = `KeyAlertHistory_${Date.now()}_${Math.random()}`;
  const Model = mongoose.model<KeyAlertHistory>(
    modelName,
    KeyAlertHistorySchema,
  );

  const buildDoc = (overrides: Partial<KeyAlertHistory> = {}) =>
    new Model({
      organization_id: new mongoose.Types.ObjectId(),
      key_version: 1,
      threshold: 'reminder',
      date_key: '2026-04-11',
      ...overrides,
    });

  describe('shape and defaults', () => {
    it('constructs a document with all required fields', () => {
      const orgId = new mongoose.Types.ObjectId();
      const doc = buildDoc({
        organization_id: orgId,
        key_version: 2,
        threshold: 'warning',
        date_key: '2026-03-15',
      });

      expect(doc.organization_id).toEqual(orgId);
      expect(doc.key_version).toBe(2);
      expect(doc.threshold).toBe('warning');
      expect(doc.date_key).toBe('2026-03-15');
    });

    it('defaults sent_at to the current time on construction', () => {
      const before = Date.now();
      const doc = buildDoc();
      const after = Date.now();

      expect(doc.sent_at).toBeInstanceOf(Date);
      expect(doc.sent_at.getTime()).toBeGreaterThanOrEqual(before);
      expect(doc.sent_at.getTime()).toBeLessThanOrEqual(after);
    });

    it('rejects invalid threshold values at Mongoose validation time', async () => {
      const doc = buildDoc({
        threshold: 'bogus' as any,
      });

      const validationError = doc.validateSync();
      expect(validationError).toBeDefined();
      expect(validationError!.errors.threshold).toBeDefined();
    });

    it('accepts each of the four valid threshold enum values', () => {
      const thresholds: Array<
        'reminder' | 'warning' | 'critical' | 'escalated'
      > = ['reminder', 'warning', 'critical', 'escalated'];

      for (const threshold of thresholds) {
        const doc = buildDoc({ threshold });
        const err = doc.validateSync();
        expect(err).toBeUndefined();
      }
    });

    it('requires organization_id, key_version, threshold, and date_key', () => {
      const doc = new Model({});
      const err = doc.validateSync();
      expect(err).toBeDefined();
      expect(err!.errors.organization_id).toBeDefined();
      expect(err!.errors.key_version).toBeDefined();
      expect(err!.errors.threshold).toBeDefined();
      expect(err!.errors.date_key).toBeDefined();
    });
  });

  describe('idempotency index', () => {
    it('declares a unique compound index on (organization_id, key_version, threshold, date_key)', () => {
      const indexes = KeyAlertHistorySchema.indexes();

      // Find the idempotency index among the declared indexes
      const idempotencyIndex = indexes.find(([fields]) => {
        const keys = Object.keys(fields);
        return (
          keys.length === 4 &&
          keys.includes('organization_id') &&
          keys.includes('key_version') &&
          keys.includes('threshold') &&
          keys.includes('date_key')
        );
      });

      expect(idempotencyIndex).toBeDefined();

      const [fields, options] = idempotencyIndex!;
      expect(fields.organization_id).toBe(1);
      expect(fields.key_version).toBe(1);
      expect(fields.threshold).toBe(1);
      expect(fields.date_key).toBe(1);
      expect(options?.unique).toBe(true);
    });

    it('declares a standalone index on organization_id for org lookups', () => {
      const indexes = KeyAlertHistorySchema.indexes();

      const orgOnlyIndex = indexes.find(([fields]) => {
        const keys = Object.keys(fields);
        return keys.length === 1 && keys[0] === 'organization_id';
      });

      expect(orgOnlyIndex).toBeDefined();
    });
  });
});
