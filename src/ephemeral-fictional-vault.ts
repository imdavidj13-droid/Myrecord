/**
 * EXISTING-SITE FICTIONAL TEST ONLY.
 *
 * AES-256-GCM data and SHA-256 revision chain stay in this browser tab.
 * Nothing is sent to a server, persisted to web storage, or backed up.
 * Closing or refreshing irreversibly loses the fictional test records.
 *
 * This is NOT the production vault/recovery protocol.
 */
import { encryptIntegrityEntryForTests, decryptIntegrityEntryForTests,
  verifyIntegrityChainForTests, GENESIS_DIGEST_FOR_TESTS,
  type IntegrityEnvelopeV2 } from "./security/integrity-chain";
import type {WorkspaceHistory,WorkspaceSession} from "./vault-workspace";

const testVaultId = () => {
  const b=crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
};
export class EphemeralFictionalVault implements WorkspaceSession {
  private entries: IntegrityEnvelopeV2[]=[];
  private closed=false;
  private constructor(private readonly vaultId:string,private readonly key:CryptoKey){}
  static async create():Promise<EphemeralFictionalVault>{
    const key=await crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
    return new EphemeralFictionalVault(testVaultId(),key);
  }
  private check(){
    if(this.closed)throw new Error("The fictional test vault has been closed.");
  }
  async read():Promise<WorkspaceHistory>{
    this.check();
    const verified=await verifyIntegrityChainForTests(this.entries);
    const entries=[];
    for(const envelope of this.entries){
      this.check();
      entries.push({
        entryId:envelope.entryId,revision:envelope.revision,
        text:await decryptIntegrityEntryForTests(this.key,envelope)
      });
    }
    this.check();
    return {entries,latestRevision:verified.revision,headDigest:verified.headDigest};
  }
  async appendSyntheticText(value:string):Promise<WorkspaceHistory>{
    this.check();
    if(!value.trim())throw new Error("Cannot save empty test writing.");
    const verified=await verifyIntegrityChainForTests(this.entries);
    const envelope=await encryptIntegrityEntryForTests(
      this.key,value,this.vaultId,testVaultId(),verified.revision+1,
      verified.headDigest || GENESIS_DIGEST_FOR_TESTS
    );
    this.check();
    this.entries.push(envelope);
    return this.read();
  }
  export():Promise<WorkspaceHistory>{
    return this.read();
  }
  async eraseEphemeralForTests():Promise<void>{
    this.check();
    // No server, database or browser-storage copies exist in this test mode.
    // Clear the ciphertext references and close the key handle. Any
    // deliberately downloaded plaintext export remains outside this control.
    this.close();
  }
  close():void{
    this.closed=true;
    this.entries=[];
  }
}
