import {describe,expect,it} from "vitest";
import {generateRecoveryWords} from "./recovery";
import {createWrappedVaultKeyForTests} from "./key-wrapping";
import {createWrappedSigningCredentialForTests} from "./signing-recovery";
import {encryptIntegrityEntryForTests,GENESIS_DIGEST_FOR_TESTS} from "./integrity-chain";
import {issueChallengeForTests} from "./access-proof";
import {signD1ReadRequestForTests} from "./d1-read-export";
import {readIntegrityHistoryD1ForTests} from "./d1-v2-read";
import type {PrototypeD1Database,PrototypeD1Statement} from "./d1-transaction";

const now=1_783_000_000_000;
async function fixture(){
  const data=await createWrappedVaultKeyForTests(generateRecoveryWords());
  const signing=await createWrappedSigningCredentialForTests(generateRecoveryWords(),data.envelope.vaultId);
  const first=await encryptIntegrityEntryForTests(
    data.key,"Synthetic A",data.envelope.vaultId,
    "fictionalEntry_12345678",1,GENESIS_DIGEST_FOR_TESTS
  );
  const second=await encryptIntegrityEntryForTests(
    data.key,"Synthetic B",data.envelope.vaultId,
    "fictionalEntry_98765432",2,first.digest
  );
  return {data,signing,first,second};
}
function database(f:Awaited<ReturnType<typeof fixture>>){
  let rows=[f.first,f.second];
  let head={latest_revision:2,head_digest:f.second.digest};
  let batches=0;
  let reject=false;
  const db:PrototypeD1Database={
    prepare(sql:string):PrototypeD1Statement{
      return {
        bind():PrototypeD1Statement{return this;},
        async first<T>():Promise<T|null>{
          return {verification_jwk:JSON.stringify(f.signing.envelope.publicKey)} as T;
        },
        async run(){return {meta:{changes:1}};}
      };
    },
    async batch(statements:PrototypeD1Statement[]){
      batches++;
      expect(statements).toHaveLength(3);
      if(reject)throw new Error("Replay denied");
      return [
        {success:true,results:[]},
        {success:true,results:rows.map(x=>({
          entry_id:x.entryId,revision:x.revision,
          previous_digest:x.previousDigest,envelope_digest:x.digest,
          encrypted_envelope_json:JSON.stringify(x)
        }))},
        {success:true,results:[head]}
      ];
    }
  };
  return {
    db,batches:()=>batches,
    setRows:(next:typeof rows)=>{rows=next;},
    setHead:(value:typeof head)=>{head=value;},
    deny:()=>{reject=true;}
  };
}
describe("isolated signed D1 v2 read and history verification",()=>{
  it("checks two complete linked records and the database head",async()=>{
    const f=await fixture(),mock=database(f);
    const challenge=issueChallengeForTests(f.data.envelope.vaultId,"read",now);
    const proof=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"read",0);
    const result=await readIntegrityHistoryD1ForTests(mock.db,challenge,"read",proof,now+1,f.second.digest);
    expect(result.revision).toBe(2);
    expect(result.headDigest).toBe(f.second.digest);
    expect(mock.batches()).toBe(1);
    expect(JSON.stringify(result)).not.toContain("Synthetic A");
  });
  it("rejects a missing record and a mismatched trusted head",async()=>{
    const f=await fixture(),mock=database(f);
    const challenge=issueChallengeForTests(f.data.envelope.vaultId,"export",now);
    const proof=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"export",0);
    mock.setRows([f.first]);
    await expect(readIntegrityHistoryD1ForTests(mock.db,challenge,"export",proof,now+1))
      .rejects.toThrow("differs");
    mock.setRows([f.first,f.second]);
    await expect(readIntegrityHistoryD1ForTests(mock.db,challenge,"export",proof,now+1,f.first.digest))
      .rejects.toThrow();
  });
  it("rejects incorrect public keys and failed nonce transactions",async()=>{
    const f=await fixture(),mock=database(f),other=await fixture();
    const challenge=issueChallengeForTests(f.data.envelope.vaultId,"read",now);
    const bad=await signD1ReadRequestForTests(other.signing.privateKey,challenge,"read",0);
    await expect(readIntegrityHistoryD1ForTests(mock.db,challenge,"read",bad,now+1))
      .rejects.toThrow("denied");
    const good=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"read",0);
    mock.deny();
    await expect(readIntegrityHistoryD1ForTests(mock.db,challenge,"read",good,now+1))
      .rejects.toThrow("Replay");
  });
  it("rejects server head mismatch and altered record ordering",async()=>{
    const f=await fixture(),mock=database(f);
    const challenge=issueChallengeForTests(f.data.envelope.vaultId,"read",now);
    const proof=await signD1ReadRequestForTests(f.signing.privateKey,challenge,"read",0);
    mock.setRows([f.second,f.first]);
    await expect(readIntegrityHistoryD1ForTests(mock.db,challenge,"read",proof,now+1)).rejects.toThrow();
    mock.setRows([f.first,f.second]);
    mock.setHead({latest_revision:2,head_digest:f.first.digest});
    await expect(readIntegrityHistoryD1ForTests(mock.db,challenge,"read",proof,now+1)).rejects.toThrow();
  });
});
