import * as mongoose from 'mongoose';
import {
  OrganizationKey,
  OrganizationKeySchema,
} from './organization-key.schema';

describe('OrganizationKeySchema', () => {
  const modelName = `OrganizationKey_${Date.now()}_${Math.random()}`;
  const Model = mongoose.model<OrganizationKey>(
    modelName,
    OrganizationKeySchema,
  );

  const buildDoc = (overrides: Partial<OrganizationKey> = {}) =>
    new Model({
      organization_id: new mongoose.Types.ObjectId(),
      encrypted_key: 'wrapped-key-placeholder',
      salt: 'salt-placeholder',
      ...overrides,
    });

  describe('new document defaults', () => {
    it('defaults key_history to an empty array', () => {
      const doc = buildDoc();
      expect(doc.key_history).toEqual([]);
    });

    it('defaults last_rotation_error to null', () => {
      const doc = buildDoc();
      expect(doc.last_rotation_error).toBeNull();
    });

    it('defaults last_pipeline_validation to null', () => {
      const doc = buildDoc();
      expect(doc.last_pipeline_validation).toBeNull();
    });

    it('defaults acknowledged_until to null', () => {
      const doc = buildDoc();
      expect(doc.acknowledged_until).toBeNull();
    });

    it('defaults restore_drill_enabled to true', () => {
      const doc = buildDoc();
      expect(doc.restore_drill_enabled).toBe(true);
    });

    it('preserves existing defaults (version, key_type, auto_rotate, rotation_interval_days)', () => {
      const doc = buildDoc();
      expect(doc.version).toBe(1);
      expect(doc.key_type).toBe('managed');
      expect(doc.auto_rotate).toBe(false);
      expect(doc.rotation_interval_days).toBe(90);
    });
  });

  describe('key_history entries', () => {
    it('accepts a fully-populated history entry', () => {
      const rotatedAt = new Date();
      const doc = buildDoc({
        key_history: [
          {
            version: 1,
            encrypted_key: 'old-wrapped',
            salt: 'old-salt',
            key_type: 'aws-kms',
            kms_config: {
              provider: 'aws',
              key_id: 'arn:aws:kms:us-east-1:123:key/abc',
              region: 'us-east-1',
            },
            rotated_at: rotatedAt,
          },
        ],
      });

      expect(doc.key_history).toHaveLength(1);
      const entry = doc.key_history[0];
      expect(entry.version).toBe(1);
      expect(entry.encrypted_key).toBe('old-wrapped');
      expect(entry.salt).toBe('old-salt');
      expect(entry.key_type).toBe('aws-kms');
      expect(entry.kms_config).toEqual({
        provider: 'aws',
        key_id: 'arn:aws:kms:us-east-1:123:key/abc',
        region: 'us-east-1',
      });
      expect(entry.rotated_at).toEqual(rotatedAt);
    });

    it('accepts history entries with null kms_config (managed and direct types)', () => {
      const doc = buildDoc({
        key_history: [
          {
            version: 1,
            encrypted_key: 'wrapped-managed',
            salt: 'salt1',
            key_type: 'managed',
            kms_config: null,
            rotated_at: new Date(),
          },
        ],
      });

      expect(doc.key_history[0].kms_config).toBeNull();
    });

    it('supports multiple history entries preserving order', () => {
      const doc = buildDoc({
        key_history: [
          {
            version: 1,
            encrypted_key: 'v1',
            salt: 's1',
            key_type: 'managed',
            kms_config: null,
            rotated_at: new Date('2026-01-01'),
          },
          {
            version: 2,
            encrypted_key: 'v2',
            salt: 's2',
            key_type: 'aws-kms',
            kms_config: { provider: 'aws', key_id: 'arn:...' },
            rotated_at: new Date('2026-02-01'),
          },
        ],
      });

      expect(doc.key_history).toHaveLength(2);
      expect(doc.key_history[0].version).toBe(1);
      expect(doc.key_history[1].version).toBe(2);
    });
  });

  describe('rotation error tracking', () => {
    it('accepts last_rotation_error with attempted_at, error, attempts', () => {
      const attemptedAt = new Date();
      const doc = buildDoc({
        last_rotation_error: {
          attempted_at: attemptedAt,
          error: 'KMS unavailable',
          attempts: 2,
        },
      });

      expect(doc.last_rotation_error).not.toBeNull();
      expect(doc.last_rotation_error?.attempted_at).toEqual(attemptedAt);
      expect(doc.last_rotation_error?.error).toBe('KMS unavailable');
      expect(doc.last_rotation_error?.attempts).toBe(2);
    });
  });

  describe('pipeline validation tracking', () => {
    it('accepts last_pipeline_validation with ok=true', () => {
      const validatedAt = new Date();
      const doc = buildDoc({
        last_pipeline_validation: {
          validated_at: validatedAt,
          ok: true,
        },
      });

      expect(doc.last_pipeline_validation?.validated_at).toEqual(validatedAt);
      expect(doc.last_pipeline_validation?.ok).toBe(true);
    });

    it('accepts last_pipeline_validation with ok=false and error message', () => {
      const doc = buildDoc({
        last_pipeline_validation: {
          validated_at: new Date(),
          ok: false,
          error: 'unwrap roundtrip mismatch',
        },
      });

      expect(doc.last_pipeline_validation?.ok).toBe(false);
      expect(doc.last_pipeline_validation?.error).toBe(
        'unwrap roundtrip mismatch',
      );
    });
  });

  describe('acknowledged_until field', () => {
    it('accepts a future date for admin acknowledgment window', () => {
      const future = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const doc = buildDoc({ acknowledged_until: future });
      expect(doc.acknowledged_until).toEqual(future);
    });
  });

  describe('restore_drill_enabled field', () => {
    it('allows explicit false override', () => {
      const doc = buildDoc({ restore_drill_enabled: false });
      expect(doc.restore_drill_enabled).toBe(false);
    });
  });
});
