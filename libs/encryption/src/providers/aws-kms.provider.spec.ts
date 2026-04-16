import { AwsKmsProvider } from './aws-kms.provider';
import { KeyProviderContext } from '../interfaces/encryption.interface';

// Import the mock module — moduleNameMapper redirects to __mocks__/@aws-sdk/client-kms.ts
const kmsMock = require('@aws-sdk/client-kms');
const {
  KMSClient,
  EncryptCommand,
  DecryptCommand,
  __setMockSend,
  __resetMockSend,
  __getMockSend,
} = kmsMock;

describe('AwsKmsProvider', () => {
  let provider: AwsKmsProvider;

  const orgKey = Buffer.from('a'.repeat(64), 'hex'); // 32 bytes
  const validContext: KeyProviderContext = {
    organizationId: 'org-123',
    salt: Buffer.from('test-salt'),
    kmsConfig: {
      provider: 'aws',
      key_id: 'arn:aws:kms:us-east-1:123456789:key/test-key-id',
      region: 'us-west-2',
    },
  };

  beforeEach(() => {
    __resetMockSend();
    KMSClient.clearInstances();
    provider = new AwsKmsProvider();
  });

  describe('wrap', () => {
    it('should call send with EncryptCommand and return base64 ciphertext', async () => {
      const ciphertext = Buffer.from('encrypted-data');
      __setMockSend(
        jest.fn().mockResolvedValue({ CiphertextBlob: ciphertext }),
      );

      const result = await provider.wrap(orgKey, validContext);

      expect(result).toBe(ciphertext.toString('base64'));

      const mockSend = __getMockSend();
      expect(mockSend).toHaveBeenCalledTimes(1);

      const command = mockSend.mock.calls[0][0];
      expect(command).toBeInstanceOf(EncryptCommand);
      expect(command.input.KeyId).toBe(validContext.kmsConfig!.key_id);
      expect(command.input.Plaintext).toEqual(orgKey);
      expect(command.input.EncryptionContext).toEqual({
        organizationId: validContext.organizationId,
      });
    });

    it('should use the correct region from kmsConfig', async () => {
      __setMockSend(
        jest.fn().mockResolvedValue({ CiphertextBlob: Buffer.from('enc') }),
      );

      await provider.wrap(orgKey, validContext);

      const instances = KMSClient.instances;
      expect(instances.length).toBe(1);
      expect(instances[0].config.region).toBe('us-west-2');
    });

    it('should throw when kmsConfig is missing', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-123',
        salt: Buffer.from('test-salt'),
      };

      await expect(provider.wrap(orgKey, ctx)).rejects.toThrow(
        'AWS KMS config is required for AWS KMS provider',
      );
    });

    it('should throw when kmsConfig.provider is not aws', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-123',
        salt: Buffer.from('test-salt'),
        kmsConfig: { provider: 'gcp', key_id: 'some-key' },
      };

      await expect(provider.wrap(orgKey, ctx)).rejects.toThrow(
        'AWS KMS config is required for AWS KMS provider',
      );
    });

    it('should throw when KMS returns empty CiphertextBlob', async () => {
      __setMockSend(jest.fn().mockResolvedValue({ CiphertextBlob: undefined }));

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        'AWS KMS encrypt returned empty ciphertext',
      );
    });
  });

  describe('unwrap', () => {
    const wrappedKey = Buffer.from('encrypted-data').toString('base64');

    it('should call send with DecryptCommand and return Buffer', async () => {
      const plaintext = Buffer.from('decrypted-org-key');
      __setMockSend(jest.fn().mockResolvedValue({ Plaintext: plaintext }));

      const result = await provider.unwrap(wrappedKey, validContext);

      expect(Buffer.isBuffer(result)).toBe(true);
      expect(result).toEqual(Buffer.from(plaintext));

      const mockSend = __getMockSend();
      const command = mockSend.mock.calls[0][0];
      expect(command).toBeInstanceOf(DecryptCommand);
      expect(command.input.KeyId).toBe(validContext.kmsConfig!.key_id);
      expect(command.input.CiphertextBlob).toEqual(
        Buffer.from(wrappedKey, 'base64'),
      );
      expect(command.input.EncryptionContext).toEqual({
        organizationId: validContext.organizationId,
      });
    });

    it('should throw when kmsConfig is missing', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-123',
        salt: Buffer.from('test-salt'),
      };

      await expect(provider.unwrap(wrappedKey, ctx)).rejects.toThrow(
        'AWS KMS config is required for AWS KMS provider',
      );
    });

    it('should throw when kmsConfig.provider is not aws', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-123',
        salt: Buffer.from('test-salt'),
        kmsConfig: { provider: 'azure', key_id: 'some-key' },
      };

      await expect(provider.unwrap(wrappedKey, ctx)).rejects.toThrow(
        'AWS KMS config is required for AWS KMS provider',
      );
    });

    it('should throw when KMS returns empty Plaintext', async () => {
      __setMockSend(jest.fn().mockResolvedValue({ Plaintext: undefined }));

      await expect(provider.unwrap(wrappedKey, validContext)).rejects.toThrow(
        'AWS KMS decrypt returned empty plaintext',
      );
    });
  });

  describe('round-trip', () => {
    it('should wrap and unwrap back to the original key', async () => {
      const originalKey = Buffer.from('b'.repeat(64), 'hex');
      const simulatedCiphertext = Buffer.from('simulated-kms-ciphertext');

      __setMockSend(
        jest.fn().mockImplementation((command: any) => {
          if (command instanceof EncryptCommand) {
            return Promise.resolve({ CiphertextBlob: simulatedCiphertext });
          }
          if (command instanceof DecryptCommand) {
            return Promise.resolve({ Plaintext: originalKey });
          }
        }),
      );

      const wrapped = await provider.wrap(originalKey, validContext);
      const unwrapped = await provider.unwrap(wrapped, validContext);

      expect(unwrapped).toEqual(originalKey);
    });
  });
});
