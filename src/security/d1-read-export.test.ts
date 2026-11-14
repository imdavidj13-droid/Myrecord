import { describe, expect, it } from "vitest";
import { generateRecoveryWords } from "./recovery";
import { createWrappedVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests } from "./signing-recovery";
import { issueChallengeForTests } from "./access-proof";
import {
  executeD1ReadForTests, issueD1ReadChallengeForTests, signD1ReadRequestForTests
} from "./d1-read-export";
import type { PrototypeD1Database, PrototypeD1Statement } from "./d1-transaction";

const now = 1_783_000_000_000;

async function setup() {
  const phrase = generateRecoveryWords();
  const data = await createWrappedVaultKeyForTests(phrase);
  const signing = await createWrappedSigningCredentialForTests(phrase, data.envelope.vaultId);
  const backup = {
    vaultId: data.envelope.vaultId,
    wrappedDataKey: data.envelope,
    wrappedSigningKey: signing.envelope,
    verificationKey: signing.envelope.publicKey
  };
  const rows = [{entry_id:"syntheticEntry_123456789",revision:1,encrypted_envelope_json:
    JSON.stringify({version:1,algorithm:"AES-256-GCM",iv:"AAAAAAAAAAAAAAAA",ciphertext:"AAAAAAAAAAAAAAAAAAAAAAAA"})}];
  return { signing, backup, rows };
}

function mockDB(f: Awaited<ReturnType<typeof setup>>) {
  const sqls: string[] = [];
  let batches = 0;
  let success = true;
  const db: PrototypeD1Database = {
    prepare(sql: string): PrototypeD1Statement {
      sqls.push(sql);
      return {
        bind(): PrototypeD1Statement {return this;},
        async first<T>(): Promise<T|null> {
          return {verification_jwk:JSON.stringify(f.signing.envelope.publicKey),
            latest_revision:1,wrapped_backup_json:JSON.stringify(f.backup)} as T;
        },
        async run() {return {meta:{changes:1}};}
      };
    },
    async batch(statements: PrototypeD1Statement[]) {
      batches++;
      expect(statements).toHaveLength(2);
      if (!success) throw new Error("D1 replay nonce rejected");
      return [{success:true,results:[]},{success:true,results:f.rows}];
    }
  };
  return {db,sqls,batches:()=>batches,fail:()=>{success=false;}};
}

describe("authenticated D1 read and export — synthetic only",()=>{
  it("verifies a request-bound signature and batches nonce consumption with ciphertext read",async()=>{
    const f=await setup(), recorded=mockDB(f);
    const challenge=issueChallengeForTests(f.backup.vaultId,"read",now);
    const proof=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"read",0);
    const result=await executeD1ReadForTests(recorded.db,challenge,"read",0,proof,now+1);
    expect(result.entries).toHaveLength(1);
    expect(result.latestRevision).toBe(1);
    expect(result.backup).toBeUndefined();
    expect(recorded.batches()).toBe(1);
    expect(recorded.sqls.some(s=>s.includes("sandbox_consumed_nonces"))).toBe(true);
    expect(recorded.sqls.some(s=>s.includes("ORDER BY revision ASC"))).toBe(true);
    expect(JSON.stringify(result)).not.toContain(f.signing.envelope.wrappedPrivateKey);
  });

  it("returns encrypted backup only with separate signed export permission",async()=>{
    const f=await setup(), recorded=mockDB(f);
    const challenge=issueChallengeForTests(f.backup.vaultId,"export",now);
    const proof=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"export",0);
    const result=await executeD1ReadForTests(recorded.db,challenge,"export",0,proof,now+1);
    expect(result.backup).toEqual(f.backup);
    expect(JSON.stringify(result)).not.toContain("synthetic only");
  });

  it("refuses partial encrypted exports and nonzero export cursors",async()=>{
    const f=await setup(), recorded=mockDB(f);
    const challenge=issueChallengeForTests(f.backup.vaultId,"export",now);
    await expect(signD1ReadRequestForTests(f.signing.privateKey,challenge,"export",1)).rejects.toThrow();
    const proof=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"export",0);
    // A stale or incomplete server response must not be presented as a full export.
    f.rows.splice(0,1);
    await expect(executeD1ReadForTests(recorded.db,challenge,"export",0,proof,now+1)).rejects.toThrow("Incomplete");
  });

  it("rejects changing the action or requested revision",async()=>{
    const f=await setup(), recorded=mockDB(f);
    const challenge=issueChallengeForTests(f.backup.vaultId,"read",now);
    const proof=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"read",0);
    await expect(executeD1ReadForTests(recorded.db,challenge,"read",1,proof,now+1)).rejects.toThrow();
    await expect(executeD1ReadForTests(recorded.db,challenge,"export",0,proof,now+1)).rejects.toThrow();
    expect(recorded.batches()).toBe(0);
  });

  it("rejects a different vault signing key and expired challenges",async()=>{
    const f=await setup(), recorded=mockDB(f);
    const other=await setup();
    const challenge=issueChallengeForTests(f.backup.vaultId,"read",now);
    const bad=await signD1ReadRequestForTests(other.signing.privateKey,challenge,"read",0);
    await expect(executeD1ReadForTests(recorded.db,challenge,"read",0,bad,now+1)).rejects.toThrow();
    const good=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"read",0);
    await expect(executeD1ReadForTests(recorded.db,challenge,"read",0,good,now+60_000)).rejects.toThrow();
    expect(recorded.batches()).toBe(0);
  });

  it("propagates failed nonce-claim transactions and does not return rows",async()=>{
    const f=await setup(), recorded=mockDB(f);
    const challenge=issueChallengeForTests(f.backup.vaultId,"read",now);
    const proof=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"read",0);
    recorded.fail();
    await expect(executeD1ReadForTests(recorded.db,challenge,"read",0,proof,now+1)).rejects.toThrow("replay");
  });

  it("persists an exact read challenge digest only for active registered vaults",async()=>{
    const f=await setup(), recorded=mockDB(f);
    const challenge=await issueD1ReadChallengeForTests(recorded.db,f.backup.vaultId,"read",0,now);
    expect(challenge.vaultId).toBe(f.backup.vaultId);
    expect(recorded.sqls.some(s=>s.includes("INSERT INTO sandbox_challenges"))).toBe(true);
  });
});
