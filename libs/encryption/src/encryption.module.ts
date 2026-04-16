import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { EmailModule } from '@app/email';
import { CronRegistryModule } from '@app/cron-registry';
import {
  Organization,
  OrganizationSchema,
  OrganizationMember,
  OrganizationMemberSchema,
} from '@app/database';
import { EncryptionService } from './services/encryption.service';
import { KeyManagementService } from './services/key-management.service';
import { FieldEncryptionService } from './services/field-encryption.service';
import { KeyRotationService } from './services/key-rotation.service';
import { KeyExpirationMonitorService } from './services/key-expiration-monitor.service';
import {
  OrganizationKey,
  OrganizationKeySchema,
} from './schemas/organization-key.schema';
import { CronRunLog, CronRunLogSchema } from './schemas/cron-run-log.schema';
import {
  KeyAlertHistory,
  KeyAlertHistorySchema,
} from './schemas/key-alert-history.schema';
import { ManagedKeyProvider } from './providers/managed-key.provider';
import { DirectKeyProvider } from './providers/direct-key.provider';
import { AwsKmsProvider } from './providers/aws-kms.provider';
import { GcpKmsProvider } from './providers/gcp-kms.provider';
import { AzureKeyVaultProvider } from './providers/azure-kms.provider';

@Global()
@Module({
  imports: [
    ConfigModule,
    EmailModule,
    // CronRegistryModule is @Global, but libs/encryption is imported by
    // api/admin/worker — making the dependency explicit here avoids
    // UnknownDependenciesException when any app bootstraps without
    // importing CronRegistryModule directly.
    CronRegistryModule,
    MongooseModule.forFeature([
      { name: OrganizationKey.name, schema: OrganizationKeySchema },
      { name: CronRunLog.name, schema: CronRunLogSchema },
      { name: KeyAlertHistory.name, schema: KeyAlertHistorySchema },
      { name: Organization.name, schema: OrganizationSchema },
      { name: OrganizationMember.name, schema: OrganizationMemberSchema },
    ]),
  ],
  providers: [
    EncryptionService,
    ManagedKeyProvider,
    DirectKeyProvider,
    AwsKmsProvider,
    GcpKmsProvider,
    AzureKeyVaultProvider,
    KeyManagementService,
    FieldEncryptionService,
    KeyRotationService,
    KeyExpirationMonitorService,
  ],
  exports: [
    EncryptionService,
    ManagedKeyProvider,
    DirectKeyProvider,
    AwsKmsProvider,
    GcpKmsProvider,
    AzureKeyVaultProvider,
    KeyManagementService,
    FieldEncryptionService,
    KeyRotationService,
    KeyExpirationMonitorService,
  ],
})
export class EncryptionModule {}
