import { GcpKmsProvider } from './gcp-kms.provider';
import { KeyProviderContext } from '../interfaces/encryption.interface';

// The moduleNameMapper in jest.config.ts redirects @google-cloud/kms to
// __mocks__/@google-cloud/kms.ts. We require it here so we can configure
// the mock encrypt/decrypt implementations per test.
const gcpMock = require('@google-cloud/kms');
const {
  KeyManagementServiceClient,
  __setMockEncrypt,
  __setMockDecrypt,
  __resetMockGcpKms,
} = gcpMock;

describe('GcpKmsProvider', () => {
  let provider: GcpKmsProvider;

  const orgKey = Buffer.from('b'.repeat(64), 'hex'); // 32 bytes
  const validContext: KeyProviderContext = {
    organizationId: 'org-abc',
    salt: Buffer.from('salt-bytes'),
    kmsConfig: {
      provider: 'gcp',
      key_id:
        'projects/vaultdb-test/locations/us-east1/keyRings/byok/cryptoKeys/key',
    },
  };

  beforeEach(() => {
    __resetMockGcpKms();
    KeyManagementServiceClient.clearInstances();
    provider = new GcpKmsProvider();
  });

  describe('wrap', () => {
    it('calls encrypt with the correct resource name, plaintext, and AAD', async () => {
      const ciphertextBytes = new Uint8Array(Buffer.from('encrypted-data'));
      __setMockEncrypt(
        jest.fn().mockResolvedValue([{ ciphertext: ciphertextBytes }]),
      );

      const result = await provider.wrap(orgKey, validContext);

      expect(result).toBe(Buffer.from(ciphertextBytes).toString('base64'));

      const mockEncrypt = gcpMock.__getMockEncrypt();
      expect(mockEncrypt).toHaveBeenCalledTimes(1);

      const request = mockEncrypt.mock.calls[0][0];
      expect(request.name).toBe(validContext.kmsConfig!.key_id);
      expect(request.plaintext).toEqual(orgKey);
      expect(request.additionalAuthenticatedData).toEqual(
        Buffer.from(validContext.organizationId),
      );
    });

    it('throws when kmsConfig is missing', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-abc',
        salt: Buffer.from('salt'),
      };

      await expect(provider.wrap(orgKey, ctx)).rejects.toThrow(
        'GCP KMS config is required for GCP KMS provider',
      );
    });

    it('throws when kmsConfig.provider is not gcp', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-abc',
        salt: Buffer.from('salt'),
        kmsConfig: { provider: 'aws', key_id: 'arn:...' },
      };

      await expect(provider.wrap(orgKey, ctx)).rejects.toThrow(
        'GCP KMS config is required for GCP KMS provider',
      );
    });

    it('throws when GCP returns null ciphertext', async () => {
      __setMockEncrypt(jest.fn().mockResolvedValue([{ ciphertext: null }]));

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        'GCP KMS encrypt returned empty ciphertext',
      );
    });

    it('translates NOT_FOUND (code 5) to a clean message', async () => {
      __setMockEncrypt(
        jest.fn().mockRejectedValue({ code: 5, message: 'grpc error' }),
      );

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        /GCP KMS key not found/,
      );
    });

    it('translates PERMISSION_DENIED (code 7)', async () => {
      __setMockEncrypt(jest.fn().mockRejectedValue({ code: 7 }));

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        /GCP KMS permission denied/,
      );
    });

    it('translates UNAVAILABLE (code 14)', async () => {
      __setMockEncrypt(jest.fn().mockRejectedValue({ code: 14 }));

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        /GCP KMS unavailable, retry later/,
      );
    });

    it('accepts string error codes (NOT_FOUND) as well as numeric', async () => {
      __setMockEncrypt(jest.fn().mockRejectedValue({ code: 'NOT_FOUND' }));

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        /GCP KMS key not found/,
      );
    });
  });

  describe('unwrap', () => {
    const wrappedKey = Buffer.from('encrypted-data').toString('base64');

    it('calls decrypt with the correct resource name, ciphertext, and AAD', async () => {
      const plaintextBytes = new Uint8Array(Buffer.from('decrypted-org-key'));
      __setMockDecrypt(
        jest.fn().mockResolvedValue([{ plaintext: plaintextBytes }]),
      );

      const result = await provider.unwrap(wrappedKey, validContext);

      expect(Buffer.isBuffer(result)).toBe(true);
      expect(result).toEqual(Buffer.from(plaintextBytes));

      const mockDecrypt = gcpMock.__getMockDecrypt();
      const request = mockDecrypt.mock.calls[0][0];
      expect(request.name).toBe(validContext.kmsConfig!.key_id);
      expect(request.ciphertext).toEqual(Buffer.from(wrappedKey, 'base64'));
      expect(request.additionalAuthenticatedData).toEqual(
        Buffer.from(validContext.organizationId),
      );
    });

    it('throws when kmsConfig is missing', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-abc',
        salt: Buffer.from('salt'),
      };

      await expect(provider.unwrap(wrappedKey, ctx)).rejects.toThrow(
        'GCP KMS config is required for GCP KMS provider',
      );
    });

    it('throws when GCP returns null plaintext', async () => {
      __setMockDecrypt(jest.fn().mockResolvedValue([{ plaintext: null }]));

      await expect(provider.unwrap(wrappedKey, validContext)).rejects.toThrow(
        'GCP KMS decrypt returned empty plaintext',
      );
    });

    it('translates NOT_FOUND on decrypt', async () => {
      __setMockDecrypt(jest.fn().mockRejectedValue({ code: 5 }));

      await expect(provider.unwrap(wrappedKey, validContext)).rejects.toThrow(
        /GCP KMS key not found/,
      );
    });
  });

  describe('round-trip', () => {
    it('wraps and unwraps a key correctly through the mocked SDK', async () => {
      const originalKey = Buffer.from('c'.repeat(64), 'hex');
      const simulatedCiphertext = new Uint8Array(
        Buffer.from('simulated-gcp-ciphertext'),
      );

      __setMockEncrypt(
        jest.fn().mockResolvedValue([{ ciphertext: simulatedCiphertext }]),
      );
      __setMockDecrypt(
        jest
          .fn()
          .mockResolvedValue([{ plaintext: new Uint8Array(originalKey) }]),
      );

      const wrapped = await provider.wrap(originalKey, validContext);
      const unwrapped = await provider.unwrap(wrapped, validContext);

      expect(unwrapped).toEqual(originalKey);
    });
  });
});
