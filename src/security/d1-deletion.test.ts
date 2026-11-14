import { describe, expect, it } from "vitest";
import { generateRecoveryWords } from "./recovery";
import { createWrappedVaultKeyForTests } from "./key-wrapping";
import { createWrappedSigningCredentialForTests } from "./signing-recovery";
import { issueChallengeForTests } from "./access-proof";
import {
  signDeletionIntentForTests,requestVaultDeletionD1ForTests,
  issueDeletionChallengeD1ForTests
} from "./d1-deletion";
import type { PrototypeD1Database, PrototypeD1Statement } from "./d1-transaction";

const now=1_783_000_000_000;
async function setup() {
  const data=await createWrappedVaultKeyForTests(generateRecoveryWords());
  const signing=await createWrappedSigningCredentialForTests(generateRecoveryWords(),data.envelope.vaultId);
  return {vaultId:data.envelope.vaultId,signing};
}
function database(jwk:JsonWebKey,vaultId:string) {
  const queries:string[]=[];
  let batches=0;
  let resultMode:"ok"|"reject"="ok";
  const db:PrototypeD1Database={
    prepare(sql:string):PrototypeD1Statement {
      queries.push(sql);
      return {
        bind():PrototypeD1Statement {return this;},
        async first<T>():Promise<T|null> {return {verification_jwk:JSON.stringify(jwk)} as T;},
        async run() {return {meta:{changes:1}};}
      };
    },
    async batch(rows:PrototypeD1Statement[]) {
      batches++;
      expect(rows).toHaveLength(2);
      if(resultMode==="reject")throw new Error("D1 transaction aborted");
      return [{success:true,results:[]},{success:true,results:[{vault_id:vaultId}]}];
    }
  };
  return {db,queries,batches:()=>batches,reject:()=>{resultMode="reject";}};
}
describe("signed deletion pending prototype",()=>{
  it("accepts a vault-bound signed deletion request and consumes its nonce in a batch",async()=>{
    const f=await setup(),store=database(f.signing.envelope.publicKey,f.vaultId);
    const challenge=issueChallengeForTests(f.vaultId,"delete",now);
    const signature=await signDeletionIntentForTests(f.signing.privateKey,challenge);
    await requestVaultDeletionD1ForTests(store.db,challenge,signature,now+1);
    expect(store.batches()).toBe(1);
    expect(store.queries.some(q=>q.includes("sandbox_consumed_nonces"))).toBe(true);
    expect(store.queries.some(q=>q.includes("status = 'deletion_pending'"))).toBe(true);
    expect(store.queries.some(q=>q.includes("DELETE FROM sandbox_entries"))).toBe(false);
  });
  it("rejects wrong private keys, changed vault IDs and expired requests",async()=>{
    const f=await setup(),attacker=await setup(),store=database(f.signing.envelope.publicKey,f.vaultId);
    const challenge=issueChallengeForTests(f.vaultId,"delete",now);
    const signature=await signDeletionIntentForTests(attacker.signing.privateKey,challenge);
    await expect(requestVaultDeletionD1ForTests(store.db,challenge,signature,now+1)).rejects.toThrow();
    const valid=await signDeletionIntentForTests(f.signing.privateKey,challenge);
    await expect(requestVaultDeletionD1ForTests(store.db,{
      ...challenge,vaultId:attacker.vaultId
    },valid,now+1)).rejects.toThrow();
    await expect(requestVaultDeletionD1ForTests(store.db,challenge,valid,now+60_000)).rejects.toThrow();
    expect(store.batches()).toBe(0);
  });
  it("rejects failed D1 transactions rather than confirming deletion",async()=>{
    const f=await setup(),store=database(f.signing.envelope.publicKey,f.vaultId);
    const challenge=issueChallengeForTests(f.vaultId,"delete",now);
    const signature=await signDeletionIntentForTests(f.signing.privateKey,challenge);
    store.reject();
    await expect(requestVaultDeletionD1ForTests(store.db,challenge,signature,now+1)).rejects.toThrow("aborted");
  });
  it("creates a registered challenge with a request-specific digest",async()=>{
    const f=await setup(),store=database(f.signing.envelope.publicKey,f.vaultId);
    const challenge=await issueDeletionChallengeD1ForTests(store.db,f.vaultId,now);
    expect(challenge.action).toBe("delete");
    expect(store.queries.some(q=>q.includes("INSERT INTO sandbox_challenges"))).toBe(true);
  });
});
