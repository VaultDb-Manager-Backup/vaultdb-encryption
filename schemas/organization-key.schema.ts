import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type OrganizationKeyDocument = HydratedDocument<OrganizationKey>;

export interface KeyHistoryEntry {
  version: number;
  encrypted_key: string;
  salt: string;
  key_type: string;
  kms_config: {
    provider: string;
    key_id: string;
    region?: string;
  } | null;
  rotated_at: Date;
}

export interface LastRotationError {
  attempted_at: Date;
  error: string;
  attempts: number;
}

export interface LastPipelineValidation {
  validated_at: Date;
  ok: boolean;
  error?: string;
}

@Schema({
  timestamps: true,
  collection: 'organization_keys',
})
export class OrganizationKey {
  _id: Types.ObjectId;

  @Prop({
    type: Types.ObjectId,
    ref: 'Organization',
    required: true,
    unique: true,
    index: true,
  })
  organization_id: Types.ObjectId;

  @Prop({ required: true })
  encrypted_key: string;

  @Prop({ required: true })
  salt: string;

  @Prop({ type: Number, default: 1 })
  version: number;

  @Prop({
    type: String,
    enum: ['managed', 'direct', 'aws-kms', 'gcp-kms', 'azure-kms'],
    default: 'managed',
  })
  key_type: string;

  @Prop({ type: Object, default: null })
  kms_config: {
    provider: string;
    key_id: string;
    region?: string;
  } | null;

  @Prop({ type: String, default: null })
  customer_key_hash: string | null;

  @Prop({ type: Date, default: null })
  rotated_at: Date | null;

  @Prop({ type: Boolean, default: false })
  auto_rotate: boolean;

  @Prop({ type: Number, default: 90 })
  rotation_interval_days: number;

  // BYOK-010: Foundation fields for two-phase rotation commit, pipeline
  // validation tracking, and hybrid direct-key lifecycle. Mongoose applies
  // defaults lazily on existing documents; BYOK-015 provides the explicit
  // idempotent backfill script for production data alignment.

  @Prop({
    type: [
      {
        version: Number,
        encrypted_key: String,
        salt: String,
        key_type: String,
        kms_config: { type: Object, default: null },
        rotated_at: Date,
        _id: false,
      },
    ],
    default: [],
  })
  key_history: KeyHistoryEntry[];

  @Prop({
    type: {
      attempted_at: Date,
      error: String,
      attempts: Number,
      _id: false,
    },
    default: null,
  })
  last_rotation_error: LastRotationError | null;

  @Prop({
    type: {
      validated_at: Date,
      ok: Boolean,
      error: String,
      _id: false,
    },
    default: null,
  })
  last_pipeline_validation: LastPipelineValidation | null;

  @Prop({ type: Date, default: null })
  acknowledged_until: Date | null;

  @Prop({ type: Boolean, default: true })
  restore_drill_enabled: boolean;

  createdAt: Date;
  updatedAt: Date;
}

export const OrganizationKeySchema =
  SchemaFactory.createForClass(OrganizationKey);
