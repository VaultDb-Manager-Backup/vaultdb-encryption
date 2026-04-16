import { AzureKeyVaultProvider } from './azure-kms.provider';
import { KeyProviderContext } from '../interfaces/encryption.interface';

const azureKeysMock = require('@azure/keyvault-keys');
const azureIdentityMock = require('@azure/identity');
const {
  CryptographyClient,
  __setMockWrap,
  __setMockUnwrap,
  __resetMockAzureKeys,
  __getMockWrap,
  __getMockUnwrap,
} = azureKeysMock;
const { DefaultAzureCredential } = azureIdentityMock;

describe('AzureKeyVaultProvider', () => {
  let provider: AzureKeyVaultProvider;

  const orgKey = Buffer.from('d'.repeat(64), 'hex'); // 32 bytes
  const validContext: KeyProviderContext = {
    organizationId: 'org-xyz',
    salt: Buffer.from('salt-bytes'),
    kmsConfig: {
      provider: 'azure',
      key_id: 'https://vaultdb-test.vault.azure.net/keys/contract-test-key/v1',
    },
  };

  beforeEach(() => {
    __resetMockAzureKeys();
    CryptographyClient.clearInstances();
    DefaultAzureCredential.clearInstances();
    provider = new AzureKeyVaultProvider();
  });

  describe('wrap', () => {
    it('calls wrapKey with RSA-OAEP and the correct key URI', async () => {
      const resultBytes = new Uint8Array(Buffer.from('wrapped-bytes'));
      __setMockWrap(
        jest
          .fn()
          .mockResolvedValue({ result: resultBytes, algorithm: 'RSA-OAEP' }),
      );

      const wrapped = await provider.wrap(orgKey, validContext);

      expect(wrapped).toBe(Buffer.from(resultBytes).toString('base64'));

      const mockWrap = __getMockWrap();
      expect(mockWrap).toHaveBeenCalledTimes(1);

      const call = mockWrap.mock.calls[0][0];
      expect(call.algorithm).toBe('RSA-OAEP');
      expect(call.key).toEqual(orgKey);
      expect(call.keyUri).toBe(validContext.kmsConfig!.key_id);

      // DefaultAzureCredential should have been instantiated
      expect(DefaultAzureCredential.instances.length).toBeGreaterThanOrEqual(1);
    });

    it('throws when kmsConfig is missing', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-xyz',
        salt: Buffer.from('salt'),
      };

      await expect(provider.wrap(orgKey, ctx)).rejects.toThrow(
        /Azure Key Vault config is required/,
      );
    });

    it('throws when kmsConfig.provider is not azure', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-xyz',
        salt: Buffer.from('salt'),
        kmsConfig: { provider: 'aws', key_id: 'arn:...' },
      };

      await expect(provider.wrap(orgKey, ctx)).rejects.toThrow(
        /Azure Key Vault config is required/,
      );
    });

    it('throws when Azure returns empty result', async () => {
      __setMockWrap(jest.fn().mockResolvedValue({ result: null }));

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        'Azure Key Vault wrap returned empty result',
      );
    });

    it('translates 403 / Forbidden to "access denied"', async () => {
      __setMockWrap(
        jest.fn().mockRejectedValue({ statusCode: 403, code: 'Forbidden' }),
      );

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        /Azure Key Vault access denied/,
      );
    });

    it('translates 404 / KeyNotFound to "key not found"', async () => {
      __setMockWrap(
        jest.fn().mockRejectedValue({ statusCode: 404, code: 'KeyNotFound' }),
      );

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        /Azure Key Vault key not found/,
      );
    });

    it('translates 5xx to "unavailable, retry later"', async () => {
      __setMockWrap(jest.fn().mockRejectedValue({ statusCode: 503 }));

      await expect(provider.wrap(orgKey, validContext)).rejects.toThrow(
        /Azure Key Vault unavailable, retry later/,
      );
    });
  });

  describe('unwrap', () => {
    const wrappedKey = Buffer.from('wrapped-bytes').toString('base64');

    it('calls unwrapKey with RSA-OAEP and decoded ciphertext', async () => {
      const resultBytes = new Uint8Array(Buffer.from('original-org-key'));
      __setMockUnwrap(
        jest
          .fn()
          .mockResolvedValue({ result: resultBytes, algorithm: 'RSA-OAEP' }),
      );

      const result = await provider.unwrap(wrappedKey, validContext);

      expect(Buffer.isBuffer(result)).toBe(true);
      expect(result).toEqual(Buffer.from(resultBytes));

      const mockUnwrap = __getMockUnwrap();
      const call = mockUnwrap.mock.calls[0][0];
      expect(call.algorithm).toBe('RSA-OAEP');
      expect(call.encryptedKey).toEqual(Buffer.from(wrappedKey, 'base64'));
      expect(call.keyUri).toBe(validContext.kmsConfig!.key_id);
    });

    it('throws when kmsConfig is missing', async () => {
      const ctx: KeyProviderContext = {
        organizationId: 'org-xyz',
        salt: Buffer.from('salt'),
      };

      await expect(provider.unwrap(wrappedKey, ctx)).rejects.toThrow(
        /Azure Key Vault config is required/,
      );
    });

    it('throws when Azure returns empty result', async () => {
      __setMockUnwrap(jest.fn().mockResolvedValue({ result: null }));

      await expect(provider.unwrap(wrappedKey, validContext)).rejects.toThrow(
        'Azure Key Vault unwrap returned empty result',
      );
    });

    it('translates 403 on unwrap', async () => {
      __setMockUnwrap(jest.fn().mockRejectedValue({ statusCode: 403 }));

      await expect(provider.unwrap(wrappedKey, validContext)).rejects.toThrow(
        /Azure Key Vault access denied/,
      );
    });
  });

  describe('round-trip', () => {
    it('wraps and unwraps a key correctly through the mocked SDK', async () => {
      const originalKey = Buffer.from('e'.repeat(64), 'hex');
      const simulatedWrapped = new Uint8Array(
        Buffer.from('simulated-azure-wrapped'),
      );

      __setMockWrap(
        jest.fn().mockResolvedValue({
          result: simulatedWrapped,
          algorithm: 'RSA-OAEP',
        }),
      );
      __setMockUnwrap(
        jest.fn().mockResolvedValue({
          result: new Uint8Array(originalKey),
          algorithm: 'RSA-OAEP',
        }),
      );

      const wrapped = await provider.wrap(originalKey, validContext);
      const unwrapped = await provider.unwrap(wrapped, validContext);

      expect(unwrapped).toEqual(originalKey);
    });
  });
});
