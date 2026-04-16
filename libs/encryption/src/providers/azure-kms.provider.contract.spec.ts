/**
 * BYOK-025: Real-cloud contract tests for AzureKeyVaultProvider.
 *
 * These tests exercise the provider against an actual Azure Key Vault
 * instance provisioned by BYOK-002 (scripts/provision-byok-azure.sh).
 * They are NOT run by `yarn test` — that uses __mocks__/@azure/keyvault-keys.
 * Only `yarn test:byok-contract` (executed nightly by the GitHub Actions
 * workflow byok-contract-nightly) runs them, and only when the required
 * env vars are present.
 *
 * Local execution:
 *   1. Run scripts/provision-byok-azure.sh once to provision the test env.
 *   2. Authenticate to Azure using ONE of:
 *        a) `az login`                                 (recommended — picks up via DefaultAzureCredential)
 *        b) service-principal env vars:                (for CI or headless runs)
 *             export AZURE_KV_TEST_TENANT_ID=<tenant-id>
 *             export AZURE_KV_TEST_CLIENT_ID=<sp-app-id>
 *             export AZURE_KV_TEST_CLIENT_SECRET=<sp-password>
 *   3. Export: `AZURE_KV_TEST_KEY_URI=https://<vault>.vault.azure.net/keys/<name>`
 *   4. yarn test:byok-contract
 *
 * The spec uses `AZURE_KV_TEST_KEY_URI` as the single opt-in signal.
 * When that var is set the suite runs and trusts DefaultAzureCredential
 * to resolve credentials via whichever of (a)/(b) is in place. If
 * credentials are missing at runtime the test fails loudly (not skipped)
 * because the operator explicitly asked for a real run.
 *
 * Duration budget: each test under 30 seconds (NFR-05).
 *
 * Isolation: no key creation or deletion, no IAM changes. The contract
 * binding is at the KEY scope (BYOK-002) so the service principal cannot
 * create keys even if it tried.
 */

import { randomBytes } from 'crypto';
import { AzureKeyVaultProvider } from './azure-kms.provider';
import { KeyProviderContext } from '../interfaces/encryption.interface';

const KEY_URI = process.env.AZURE_KV_TEST_KEY_URI;
// Explicit opt-in: when KEY_URI is set, the spec runs and trusts
// DefaultAzureCredential to resolve creds (az CLI login, env-var
// service principal, managed identity, etc). We do NOT pre-validate
// credential presence — the SDK surfaces the failure mode at runtime
// with a clearer message than we could guess.
const SHOULD_RUN = !!KEY_URI;

// For the CI / explicit-env-var strategy: DefaultAzureCredential reads
// AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET. Our test env
// vars use the AZURE_KV_TEST_* namespace to avoid collision with
// production creds — alias them here so the SDK picks them up without
// code changes in the provider. The aliasing is a no-op when the
// AZURE_KV_TEST_* vars are unset (e.g. when using `az login` locally).
if (SHOULD_RUN) {
  if (process.env.AZURE_KV_TEST_TENANT_ID) {
    process.env.AZURE_TENANT_ID = process.env.AZURE_KV_TEST_TENANT_ID;
  }
  if (process.env.AZURE_KV_TEST_CLIENT_ID) {
    process.env.AZURE_CLIENT_ID = process.env.AZURE_KV_TEST_CLIENT_ID;
  }
  if (process.env.AZURE_KV_TEST_CLIENT_SECRET) {
    process.env.AZURE_CLIENT_SECRET = process.env.AZURE_KV_TEST_CLIENT_SECRET;
  }
}

// Detect SDK availability without crashing the test file load.
let sdkAvailable = false;
try {
  require.resolve('@azure/keyvault-keys');
  require.resolve('@azure/identity');
  sdkAvailable = true;
} catch {
  sdkAvailable = false;
}

const describeIf = SHOULD_RUN && sdkAvailable ? describe : describe.skip;

describeIf('AzureKeyVaultProvider (contract)', () => {
  const provider = new AzureKeyVaultProvider();
  const context: KeyProviderContext = {
    organizationId: 'contract-test-org-001',
    salt: Buffer.alloc(32, 0),
    kmsConfig: {
      provider: 'azure',
      key_id: KEY_URI || '',
    },
  };

  it('round-trips a 32-byte payload through wrap/unwrap', async () => {
    const started = Date.now();
    const orgKey = randomBytes(32);

    const wrapped = await provider.wrap(orgKey, context);
    expect(typeof wrapped).toBe('string');
    expect(wrapped.length).toBeGreaterThan(0);

    const unwrapped = await provider.unwrap(wrapped, context);
    expect(Buffer.compare(orgKey, unwrapped)).toBe(0);

    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(30_000);
  });

  it('rejects an invalid key URI with a translated error', async () => {
    const badContext: KeyProviderContext = {
      ...context,
      kmsConfig: {
        provider: 'azure',
        // Well-formed URI pointing at a key that does not exist.
        key_id: KEY_URI!.replace(/\/keys\/[^/]+/, '/keys/does-not-exist'),
      },
    };

    const orgKey = randomBytes(32);

    // Azure Key Vault surfaces not-found as either 404 or forbidden
    // depending on RBAC evaluation order; we only assert it is an Error
    // with a recognizable marker, not a raw SDK exception.
    await expect(provider.wrap(orgKey, badContext)).rejects.toThrow(
      /Azure Key Vault/i,
    );
  });
});

// Visibility: when the suite is skipped because the opt-in env var or
// SDK is missing, log a single hint line so developers running
// `yarn test:byok-contract` locally know what to provision.
if (!SHOULD_RUN || !sdkAvailable) {
  console.log(
    `[azure-kms.contract] skipped — ` +
      `AZURE_KV_TEST_KEY_URI=${SHOULD_RUN ? 'set' : 'missing (set it to opt in; auth via `az login` or AZURE_KV_TEST_{TENANT_ID,CLIENT_ID,CLIENT_SECRET})'}, ` +
      `SDK=${sdkAvailable ? 'installed' : 'not installed (pnpm add -D @azure/keyvault-keys @azure/identity)'}`,
  );
}
