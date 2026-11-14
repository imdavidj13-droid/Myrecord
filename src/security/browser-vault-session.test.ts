import {describe, expect, it} from "vitest";
import {generateRecoveryWords} from "./recovery";
import {BrowserVaultSessionForTests, type VaultTransportForTests} from "./browser-vault-session";
import {issueChallengeForTests, InMemoryProofVerifierForTests,
  importVerificationKeyForTests, type ProofChallengeV1} from "./access-proof";
import {verifyRegistrationIntentForTests} from "./registration-intent";
import {verifyIntegrityChainForTests,
  type IntegrityEnvelopeV2} from "./integrity-chain";
import type {SyntheticVaultBackup} from "./synthetic-vault-store";

function syntheticTransport() {
  const vaults = new Map<string, {
    backup:SyntheticVaultBackup; lookupId:string; entries:IntegrityEnvelopeV2[];
  }>();
  const pending = new Map<string, {challenge:ProofChallengeV1;envelope?:string}>();
  const consumed = new Set<string>();
  const proofVerifier = new InMemoryProofVerifierForTests();
  const wire:unknown[] = [];
  const copy = <T>(value:T):T => JSON.parse(JSON.stringify(value)) as T;

  function challenge(vaultId:string,action:"append"|"read"|"export", envelope?:IntegrityEnvelopeV2) {
    const value = issueChallengeForTests(vaultId,action);
    pending.set(value.nonce,{challenge:value,envelope:envelope?JSON.stringify(envelope):undefined});
    return value;
  }
  function claim(value:ProofChallengeV1,action:"append"|"read"|"export",vaultId:string) {
    const outstanding=pending.get(value.nonce);
    if(!outstanding || consumed.has(value.nonce) ||
       JSON.stringify(outstanding.challenge)!==JSON.stringify(value) ||
       value.action!==action || value.vaultId!==vaultId) {
      throw new Error("Invalid or replayed synthetic challenge.");
    }
    consumed.add(value.nonce);
    pending.delete(value.nonce);
    return outstanding;
  }
  const transport:VaultTransportForTests={
    async issueRegistrationChallenge(vaultId) {
      const value=issueChallengeForTests(vaultId,"append");
      proofVerifier.register(value);
      return copy(value);
    },
    async register(input) {
      wire.push(copy(input));
      const key=await importVerificationKeyForTests(input.backup.verificationKey);
      const authorized=await proofVerifier.verify(
        input.proof,key,input.backup.vaultId,"append"
      );
      if (!authorized || !await verifyRegistrationIntentForTests(
        key,input.proof.challenge,input.backup,input.lookupId,input.intent
      )) throw new Error("Registration authorization denied.");
      if(vaults.has(input.backup.vaultId)) throw new Error("Vault already registered.");
      vaults.set(input.backup.vaultId,{
        backup:copy(input.backup),lookupId:input.lookupId,entries:[]
      });
    },
    async lookup(lookupId) {
      for(const item of vaults.values()) {
        if(item.lookupId===lookupId) return copy(item.backup);
      }
      return null;
    },
    async issueReadChallenge(vaultId,action) {
      if(!vaults.has(vaultId))throw new Error("Vault not found.");
      return copy(challenge(vaultId,action));
    },
    async read(input) {
      wire.push(copy(input));
      claim(input.challenge,input.action,input.vaultId);
      const item=vaults.get(input.vaultId);
      if(!item)throw new Error("Vault not found.");
      const result=await verifyIntegrityChainForTests(item.entries);
      return copy({
        entries:item.entries,latestRevision:result.revision,headDigest:result.headDigest
      });
    },
    async issueAppendChallenge(envelope) {
      if(!vaults.has(envelope.vaultId))throw new Error("Vault not found.");
      return copy(challenge(envelope.vaultId,"append",envelope));
    },
    async append(input) {
      wire.push(copy(input));
      const issued=claim(input.challenge,"append",input.envelope.vaultId);
      if(issued.envelope!==JSON.stringify(input.envelope))
        throw new Error("Append payload changed.");
      const item=vaults.get(input.envelope.vaultId);
      if(!item)throw new Error("Vault not found.");
      const current=await verifyIntegrityChainForTests(item.entries);
      if(input.envelope.revision!==current.revision+1 ||
         input.envelope.previousDigest!==current.headDigest)
        throw new Error("Revision conflict.");
      const next=[...item.entries,copy(input.envelope)];
      await verifyIntegrityChainForTests(next);
      item.entries=next;
    }
  };
  return {
    transport, wire, vaults,
    suppressLastEntry() {
      const item=[...vaults.values()][0];
      if(item) item.entries=item.entries.slice(0,-1);
    },
    tamperCiphertext() {
      const item=[...vaults.values()][0];
      if(item && item.entries.length) {
        const entry=item.entries[0];
        item.entries[0]={...entry,ciphertext:(entry.ciphertext.startsWith("A")?"B":"A")+entry.ciphertext.slice(1)};
      }
    }
  };
}
describe("browser vault session composition — synthetic-only boundary",()=>{
  it("registers, appends twice, recovers from words and exports verified plaintext locally",async()=>{
    const fake=syntheticTransport();
    const phrase=generateRecoveryWords();
    const first=await BrowserVaultSessionForTests.register(fake.transport,phrase);
    expect((await first.read()).entries).toHaveLength(0);
    const one=await first.appendSyntheticText("Fictional sample one");
    expect(one.entries.map(e=>e.text)).toEqual(["Fictional sample one"]);
    const two=await first.appendSyntheticText("Fictional sample two");
    expect(two.entries.map(e=>e.text)).toEqual(["Fictional sample one","Fictional sample two"]);
    const recovered=await BrowserVaultSessionForTests.recover(
      fake.transport,phrase,two.headDigest
    );
    expect((await recovered.export(two.headDigest)).entries).toEqual(two.entries);
    const serialized=JSON.stringify(fake.wire);
    expect(serialized).not.toContain(phrase);
    expect(serialized).not.toContain("Fictional sample one");
    expect(serialized).not.toContain("Fictional sample two");
    expect(fake.vaults.size).toBe(1);
  });

  it("rejects wrong recovery words and detects a missing last revision with a trusted head",async()=>{
    const fake=syntheticTransport(),phrase=generateRecoveryWords();
    const session=await BrowserVaultSessionForTests.register(fake.transport,phrase);
    const after=await session.appendSyntheticText("Invented event");
    await expect(BrowserVaultSessionForTests.recover(
      fake.transport,generateRecoveryWords()
    )).rejects.toThrow();
    fake.suppressLastEntry();
    await expect(BrowserVaultSessionForTests.recover(
      fake.transport,phrase,after.headDigest
    )).rejects.toThrow();
  });

  it("rejects rollback in the same browser session even without an external head",async()=>{
    const fake=syntheticTransport(),phrase=generateRecoveryWords();
    const session=await BrowserVaultSessionForTests.register(fake.transport,phrase);
    await session.appendSyntheticText("Invented event");
    fake.suppressLastEntry();
    await expect(session.read()).rejects.toThrow("rolled back");
    await expect(session.export()).rejects.toThrow("rolled back");
  });

  it("rejects altered ciphertext and never delivers it as readable history",async()=>{
    const fake=syntheticTransport(),phrase=generateRecoveryWords();
    const session=await BrowserVaultSessionForTests.register(fake.transport,phrase);
    await session.appendSyntheticText("Invented event");
    fake.tamperCiphertext();
    await expect(session.read()).rejects.toThrow();
  });

  it("rejects an empty entry before it reaches the transport",async()=>{
    const fake=syntheticTransport(),phrase=generateRecoveryWords();
    const session=await BrowserVaultSessionForTests.register(fake.transport,phrase);
    const before=fake.wire.length;
    await expect(session.appendSyntheticText("  ")).rejects.toThrow("Empty");
    expect(fake.wire).toHaveLength(before);
  });

  it("rejects a delayed authenticated read that finishes after session closure",async()=>{
    const fake=syntheticTransport(),phrase=generateRecoveryWords();
    const session=await BrowserVaultSessionForTests.register(fake.transport,phrase);
    const original=fake.transport.read.bind(fake.transport);
    let signalEntered:()=>void=()=>{};
    const entered=new Promise<void>(resolve=>{signalEntered=resolve;});
    let release:(result:Awaited<ReturnType<typeof original>>)=>void=()=>{};
    fake.transport.read=async input=>{
      const result=await original(input);
      return new Promise(resolve=>{release=resolve;signalEntered();});
    };
    const pending=session.read();
    await entered;
    session.close();
    release({entries:[],latestRevision:0,headDigest:"0".repeat(64)});
    await expect(pending).rejects.toThrow("closed");
  });
  it("rejects subsequent operations after the test session is closed",async()=>{
    const fake=syntheticTransport(),phrase=generateRecoveryWords();
    const session=await BrowserVaultSessionForTests.register(fake.transport,phrase);
    session.close();
    await expect(session.read()).rejects.toThrow("closed");
    await expect(session.export()).rejects.toThrow("closed");
    await expect(session.appendSyntheticText("Fictional")).rejects.toThrow("closed");
  });
  it("uses a separate authorization action for export",async()=>{
    const fake=syntheticTransport(),phrase=generateRecoveryWords();
    const session=await BrowserVaultSessionForTests.register(fake.transport,phrase);
    await session.export();
    expect(fake.wire.some(value=>{
      const item=value as {action?:string};
      return item.action==="export";
    })).toBe(true);
  });
});
