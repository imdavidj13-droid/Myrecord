/**
 * TEST-ONLY D1 transport composition for the v2 browser vault client.
 *
 * Imports existing D1 adapters and adapts their result contracts. This is
 * NOT imported by App, any Worker, or production routing. Requires a separate
 * synthetic-only D1 database with all three draft SQL schemas applied.
 *
 * No words, plaintext, private keys or decrypted records enter this adapter.
 * Do not deploy as an HTTP API without security/legal review and abuse controls.
 */
import type { VaultTransportForTests } from "./browser-vault-session";
import type { PrototypeD1Database } from "./d1-transaction";
import type { SyntheticVaultBackup } from "./synthetic-vault-store";
import { isValidVaultLookupIdForTests } from "./recovery-bootstrap";
import {
  issueRegistrationChallengeD1ForTests, registerVaultD1ForTests
} from "./d1-registration";
import { issueD1ReadChallengeForTests } from "./d1-read-export";
import { readIntegrityHistoryD1ForTests } from "./d1-v2-read";
import {
  issueIntegrityAppendChallengeD1ForTests, appendIntegrityEntryD1ForTests
} from "./d1-v2-integrity";

const vaultIdPattern = /^[A-Za-z0-9_-]{22}$/;
const maxBackupJson = 4096;
const maxLookupRows = 2;

export function createD1VaultTransportForTests(
  db: PrototypeD1Database, clock: () => number
): VaultTransportForTests {
  // Passing in a dedicated synthetic D1 is the caller's responsibility.
  // Do not accept an arbitrary request-provided DB instance in a Worker.
  function now(): number {
    const current = clock();
    if (!Number.isSafeInteger(current) || current < 0) {
      throw new Error("Invalid test server clock.");
    }
    return current;
  }
  return {
    issueRegistrationChallenge(vaultId) {
      return issueRegistrationChallengeD1ForTests(db, vaultId, now());
    },
    async register(input) {
      await registerVaultD1ForTests(
        db, input.backup, input.lookupId,
        input.proof, input.intent, now()
      );
    },
    async lookup(lookupId) {
      if (!isValidVaultLookupIdForTests(lookupId)) {
        throw new Error("Invalid recovery locator.");
      }
      const statement = db.prepare(`
        SELECT vault_id, lookup_id, wrapped_backup_json
        FROM sandbox_vaults
        WHERE lookup_id=? AND status='active'
        LIMIT ${maxLookupRows}
      `).bind(lookupId);
      // The limited result is obtained via D1 batch because the shared
      // prototype statement interface exposes first(), not all().
      const result = await db.batch([statement]) as Array<{
        success?: boolean; results?: unknown[]
      }>;
      if (!Array.isArray(result) || result.length !== 1 ||
          result[0]?.success !== true ||
          !Array.isArray(result[0].results) ||
          result[0].results.length > 1) {
        throw new Error("Ambiguous or malformed encrypted vault lookup.");
      }
      if (result[0].results.length === 0) return null;
      const row = result[0].results[0] as {
        vault_id?: unknown; lookup_id?: unknown;
        wrapped_backup_json?: unknown
      };
      if (!row || !vaultIdPattern.test(String(row.vault_id)) ||
          row.lookup_id !== lookupId ||
          typeof row.wrapped_backup_json !== "string" ||
          row.wrapped_backup_json.length > maxBackupJson) {
        throw new Error("Invalid encrypted vault lookup.");
      }
      let backup: SyntheticVaultBackup;
      try {
        backup = JSON.parse(row.wrapped_backup_json) as SyntheticVaultBackup;
      } catch {
        throw new Error("Corrupted encrypted vault backup.");
      }
      if (!backup || backup.vaultId !== row.vault_id ||
          backup.wrappedDataKey?.vaultId !== row.vault_id ||
          backup.wrappedSigningKey?.vaultId !== row.vault_id ||
          !backup.verificationKey ||
          backup.verificationKey.kty !== "EC" ||
          backup.verificationKey.crv !== "P-256" ||
          backup.verificationKey.d !== undefined ||
          backup.verificationKey.x !== backup.wrappedSigningKey.publicKey?.x ||
          backup.verificationKey.y !== backup.wrappedSigningKey.publicKey?.y) {
        throw new Error("Inconsistent encrypted vault backup.");
      }
      return backup;
    },
    issueReadChallenge(vaultId, action) {
      return issueD1ReadChallengeForTests(db, vaultId, action, 0, now());
    },
    async read(input) {
      if (input.challenge.vaultId !== input.vaultId ||
          input.action !== input.challenge.action) {
        throw new Error("Read request identity mismatch.");
      }
      const result = await readIntegrityHistoryD1ForTests(
        db, input.challenge, input.action, input.proof, now()
      );
      return {
        entries: result.entries,
        latestRevision: result.revision,
        headDigest: result.headDigest
      };
    },
    issueAppendChallenge(envelope) {
      return issueIntegrityAppendChallengeD1ForTests(db, envelope, now());
    },
    async append(input) {
      await appendIntegrityEntryD1ForTests(
        db, input.challenge, input.envelope, input.proof, now()
      );
    }
  };
}
