import { Injectable, Logger } from '@nestjs/common';
import {
  KeyProvider,
  KeyProviderContext,
} from '../interfaces/encryption.interface';

@Injectable()
export class AwsKmsProvider implements KeyProvider {
  private readonly logger = new Logger(AwsKmsProvider.name);

  async wrap(orgKey: Buffer, context: KeyProviderContext): Promise<string> {
    if (!context.kmsConfig || context.kmsConfig.provider !== 'aws') {
      throw new Error('AWS KMS config is required for AWS KMS provider');
    }

    const { KMSClient, EncryptCommand } = await import('@aws-sdk/client-kms');

    const client = new KMSClient({
      region: context.kmsConfig.region || process.env.AWS_REGION || 'us-east-1',
    });

    const command = new EncryptCommand({
      KeyId: context.kmsConfig.key_id,
      Plaintext: orgKey,
      EncryptionContext: {
        organizationId: context.organizationId,
      },
    });

    const response = await client.send(command);

    if (!response.CiphertextBlob) {
      throw new Error('AWS KMS encrypt returned empty ciphertext');
    }

    const wrapped = Buffer.from(response.CiphertextBlob).toString('base64');

    this.logger.log(
      `Wrapped key via AWS KMS for organization: ${context.organizationId}`,
    );

    return wrapped;
  }

  async unwrap(
    wrappedKey: string,
    context: KeyProviderContext,
  ): Promise<Buffer> {
    if (!context.kmsConfig || context.kmsConfig.provider !== 'aws') {
      throw new Error('AWS KMS config is required for AWS KMS provider');
    }

    const { KMSClient, DecryptCommand } = await import('@aws-sdk/client-kms');

    const client = new KMSClient({
      region: context.kmsConfig.region || process.env.AWS_REGION || 'us-east-1',
    });

    const command = new DecryptCommand({
      KeyId: context.kmsConfig.key_id,
      CiphertextBlob: Buffer.from(wrappedKey, 'base64'),
      EncryptionContext: {
        organizationId: context.organizationId,
      },
    });

    const response = await client.send(command);

    if (!response.Plaintext) {
      throw new Error('AWS KMS decrypt returned empty plaintext');
    }

    this.logger.log(
      `Unwrapped key via AWS KMS for organization: ${context.organizationId}`,
    );

    return Buffer.from(response.Plaintext);
  }
}
