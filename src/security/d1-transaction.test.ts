import { describe, expect, it } from "vitest";
import { createWrappedVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests } from "./signing-recovery";
import { encryptSyntheticEntry } from "./crypto";
import { generateRecoveryWords } from "./recovery";
import { issueChallengeForTests } from "./access-proof";
import {
  signBoundAppendForTests, verifyBoundAppendForTests,
  digestAppendIntentForTests, appendCiphertextD1ForTests,
  type PrototypeD1Database, type PrototypeD1Statement
} from "./d1-transaction";
import type { EncryptedStoredEntry } from "./synthetic-vault-store";

const now = 1_783_000_000_000;
async function fixture() {
  const phrase = generateRecoveryWords();
  const data = await createWrappedVaultKeyForTests(phrase);
  const signing = await createWrappedSigningCredentialForTests(phrase, data.envelope.vaultId);
  const challenge = issueChallengeForTests(data.envelope.vaultId, "append", now);
  const entry: EncryptedStoredEntry = {
    entryId: "syntheticEntry_123456789",
    revision: 1,
    ciphertext: await encryptSyntheticEntry(data.key, "synthetic only")
  };
  const signature = await signBoundAppendForTests(signing.privateKey, challenge, entry);
  return { data, signing, challenge, entry, signature };
}

function recordingDB(jwk: JsonWebKey) {
  const statements: Array<{ sql: string; args: Array<string | number> }> = [];
  let batches = 0;
  const db: PrototypeD1Database = {
    prepare(sql: string): PrototypeD1Statement {
      return {
        bind(...args: Array<string | number>): PrototypeD1Statement {
          statements.push({ sql, args });
          return this;
        },
        async first<T>(): Promise<T | null> {
          return { verification_jwk: JSON.stringify(jwk) } as T;
        }
      };
    },
    async batch(batch: PrototypeD1Statement[]) {
      expect(batch).toHaveLength(2);
      batches++;
      return [];
    }
  };
  return { db, statements, count: () => batches };
}

describe("D1 atomic append adapter — synthetic only, no live D1", () => {
  it("binds signatures to the exact ciphertext and revision", async () => {
    const f = await fixture();
    expect(await verifyBoundAppendForTests(
      f.signing.publicKey, f.challenge, f.entry, f.signature
    )).toBe(true);
    expect(await verifyBoundAppendForTests(
      f.signing.publicKey, f.challenge, { ...f.entry, revision: 2 }, f.signature
    )).toBe(false);
    expect(await verifyBoundAppendForTests(
      f.signing.publicKey, f.challenge,
      { ...f.entry, entryId: "differentEntry_123456789" }, f.signature
    )).toBe(false);
    const altered = { ...f.entry, ciphertext: {
      ...f.entry.ciphertext,
      ciphertext: f.entry.ciphertext.ciphertext.replace(/^./, "A")
    }};
    if (altered.ciphertext.ciphertext === f.entry.ciphertext.ciphertext) {
      altered.ciphertext.ciphertext = "B" + altered.ciphertext.ciphertext.slice(1);
    }
    expect(await verifyBoundAppendForTests(
      f.signing.publicKey, f.challenge, altered, f.signature
    )).toBe(false);
  });

  it("uses a single D1 batch to claim the nonce and insert ciphertext", async () => {
    const f = await fixture();
    const recorder = recordingDB(f.signing.envelope.publicKey);
    await appendCiphertextD1ForTests(
      recorder.db, f.challenge, f.entry, f.signature, now + 1
    );
    expect(recorder.count()).toBe(1);
    expect(recorder.statements).toHaveLength(3);
    expect(recorder.statements[1].sql).toContain("sandbox_consumed_nonces");
    expect(recorder.statements[1].sql).toContain("request_digest = ?");
    expect(recorder.statements[2].sql).toContain("sandbox_entries");
    expect(recorder.statements[1].args).toContain(
      await digestAppendIntentForTests(f.challenge, f.entry)
    );
    expect(JSON.stringify(recorder.statements)).not.toContain("synthetic only");
    expect(JSON.stringify(recorder.statements)).not.toContain(f.data.envelope.wrappedKey);
  });

  it("rejects expired challenges and invalid signatures before database access", async () => {
    const f = await fixture();
    const recorder = recordingDB(f.signing.envelope.publicKey);
    await expect(appendCiphertextD1ForTests(
      recorder.db, f.challenge, f.entry, f.signature, now + 60_000
    )).rejects.toThrow();
    const other = await createWrappedSigningCredentialForTests(
      generateRecoveryWords(), f.data.envelope.vaultId
    );
    const wrongDB = recordingDB(other.envelope.publicKey);
    await expect(appendCiphertextD1ForTests(
      wrongDB.db, f.challenge, f.entry, f.signature, now + 1
    )).rejects.toThrow();
    expect(recorder.count()).toBe(0);
    expect(wrongDB.count()).toBe(0);
  });

  it("rejects malformed entries before signing and never queries D1", async () => {
    const f = await fixture();
    const recorder = recordingDB(f.signing.envelope.publicKey);
    await expect(appendCiphertextD1ForTests(
      recorder.db, f.challenge,
      { ...f.entry, revision: 0 }, f.signature, now + 1
    )).rejects.toThrow();
    expect(recorder.count()).toBe(0);
  });

  it("propagates D1 batch failures rather than claiming success", async () => {
    const f = await fixture();
    const db: PrototypeD1Database = {
      prepare(): PrototypeD1Statement {
        return { bind(): PrototypeD1Statement { return this; }, async first<T>() { return { verification_jwk: JSON.stringify(f.signing.envelope.publicKey) } as T; } };
      },
      async batch() { throw new Error("D1 transaction rolled back"); }
    };
    await expect(appendCiphertextD1ForTests(
      db, f.challenge, f.entry, f.signature, now + 1
    )).rejects.toThrow("rolled back");
  });
});
