/**
 * load-smart-account-artifact.mjs — test-only loader for the compiled
 * SmartAccount artifact.
 *
 * The Foundry `out/` directory is gitignored, so the on-chain tests need a
 * defined source for the ABI + bytecode. Resolution order:
 *
 *   1. $SMART_ACCOUNT_ARTIFACT — explicit path override.
 *   2. Repo-relative default: <repoRoot>/contracts/solidity/out/
 *      SmartAccount.sol/SmartAccount.json.
 *
 * When neither exists the loader returns `null`; callers should `skip` the
 * on-chain tests with a clear message (the artifact requires a local
 * `forge build` / `forge build --use 0.8.24`).
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/helpers → packages/chain-eth → packages → repo root
const REPO_ROOT = join(HERE, '..', '..', '..', '..');

export const DEFAULT_ARTIFACT_PATH = join(
  REPO_ROOT,
  'contracts',
  'solidity',
  'out',
  'SmartAccount.sol',
  'SmartAccount.json',
);

/**
 * Load the compiled SmartAccount artifact.
 * @returns {{ abi: object[], bytecode: { object: string } } | null}
 */
export function loadSmartAccountArtifact() {
  const path = process.env.SMART_ACCOUNT_ARTIFACT || DEFAULT_ARTIFACT_PATH;
  if (!existsSync(path)) return null;
  try {
    const raw = JSON.parse(readFileSync(path, 'utf8'));
    if (!raw.abi || !raw.bytecode?.object) return null;
    return raw;
  } catch {
    return null;
  }
}

/**
 * Human-readable hint for when the artifact is missing.
 * @returns {string}
 */
export function artifactMissingHint() {
  return (
    `SmartAccount artifact not found. Run ` +
    `\`forge build --use 0.8.24\` in contracts/solidity first, ` +
    `or set SMART_ACCOUNT_ARTIFACT to the built artifact JSON.`
  );
}
