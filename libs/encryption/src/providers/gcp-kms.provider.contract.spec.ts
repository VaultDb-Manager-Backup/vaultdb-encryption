/**
 * BYOK-025: Real-cloud contract tests for GcpKmsProvider.
 *
 * These tests exercise the provider against an actual GCP Cloud KMS
 * instance provisioned by BYOK-001 (scripts/provision-byok-gcp.sh).
 * They are NOT run by the default `yarn test` Jest run — that uses the
 * mocked SDK via __mocks__/@google-cloud/kms.ts. Only the dedicated
 * `yarn test:byok-contract` command (executed nightly by the GitHub
 * Actions workflow byok-contract-nightly) runs them, and only when the
 * required env vars are present.
 *
 * Local execution:
 *   1. Run scripts/provision-byok-gcp.sh once to provision the test env.
 *   2. Authenticate to GCP using ONE of:
 *        a) `gcloud auth application-default login`   (recommended — ADC, no files in repo)
 *        b) `export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json`   (explicit file)
 *        c) set `GCP_KMS_TEST_SA_JSON` to the raw JSON contents   (CI only — inline secret)
 *   3. Export: `GCP_KMS_TEST_KEY_NAME=projects/.../cryptoKeys/contract-test-key`
 *   4. yarn test:byok-contract
 *
 * The spec uses `GCP_KMS_TEST_KEY_NAME` as the single opt-in signal —
 * when that var is set the suite runs and trusts the `@google-cloud/kms`
 * SDK to resolve credentials via whichever of (a)/(b)/(c) is in place.
 * If credentials are missing at runtime the test fails loudly (not
 * skipped) because the operator explicitly asked for a real run.
 *
 * Duration budget: each test must complete under 30 seconds (NFR-05).
 * Total: wrap + unwrap + error path ≈ 3 round-trips ≈ under 10 seconds.
 *
 * Isolation: no state is mutated in GCP — only encrypt/decrypt operations.
 * Each test uses a fresh random 32-byte buffer so there is no cross-test
 * contamination.
 */

import { randomBytes } from 'crypto';
import { GcpKmsProvider } from './gcp-kms.provider';
import { KeyProviderContext } from '../interfaces/encryption.interface';

const KEY_NAME = process.env.GCP_KMS_TEST_KEY_NAME;
// Explicit opt-in: when KEY_NAME is set, the spec runs and trusts the
// SDK to resolve credentials (ADC via `gcloud auth application-default
// login`, GOOGLE_APPLICATION_CREDENTIALS file, or — in CI —
// GCP_KMS_TEST_SA_JSON materialized by the workflow to a temp file).
// We do NOT pre-validate credential presence here because the valid
// paths are multiple and platform-dependent; let the SDK surface the
// failure mode if credentials are missing at runtime.
const SHOULD_RUN = !!KEY_NAME;

// Detect SDK availability without crashing the test file load.
let sdkAvailable = false;
try {
  require.resolve('@google-cloud/kms');
  sdkAvailable = true;
} catch {
  sdkAvailable = false;
}

const describeIf = SHOULD_RUN && sdkAvailable ? describe : describe.skip;

describeIf('GcpKmsProvider (contract)', () => {
  const provider = new GcpKmsProvider();
  const context: KeyProviderContext = {
    organizationId: 'contract-test-org-001',
    salt: Buffer.alloc(32, 0),
    kmsConfig: {
      provider: 'gcp',
      key_id: KEY_NAME || '',
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

  it('uses additionalAuthenticatedData bound to the organization', async () => {
    const orgKey = randomBytes(32);
    const wrapped = await provider.wrap(orgKey, context);

    // Unwrap with a DIFFERENT organization ID should fail because AAD
    // binding prevents cross-org decryption.
    const wrongContext: KeyProviderContext = {
      ...context,
      organizationId: 'contract-test-org-002',
    };

    await expect(provider.unwrap(wrapped, wrongContext)).rejects.toThrow();
  });

  it('translates NOT_FOUND errors for an invalid key resource name', async () => {
    const badContext: KeyProviderContext = {
      ...context,
      kmsConfig: {
        provider: 'gcp',
        key_id: `${KEY_NAME}-does-not-exist-${Date.now()}`,
      },
    };

    const orgKey = randomBytes(32);

    // Either NOT_FOUND or INVALID_ARGUMENT depending on the exact mangling
    // — we only assert that it surfaces as an Error with a recognizable
    // message, not a raw SDK exception.
    await expect(provider.wrap(orgKey, badContext)).rejects.toThrow(/GCP KMS/i);
  });
});

// Visibility: when the suite is skipped because the opt-in env var or
// SDK is missing, log a single hint line so developers running
// `yarn test:byok-contract` locally know what to provision.
if (!SHOULD_RUN || !sdkAvailable) {
  console.log(
    `[gcp-kms.contract] skipped — ` +
      `GCP_KMS_TEST_KEY_NAME=${SHOULD_RUN ? 'set' : 'missing (set it to opt in; auth via `gcloud auth application-default login` or GOOGLE_APPLICATION_CREDENTIALS)'}, ` +
      `SDK=${sdkAvailable ? 'installed' : 'not installed (pnpm add -D @google-cloud/kms)'}`,
  );
}
