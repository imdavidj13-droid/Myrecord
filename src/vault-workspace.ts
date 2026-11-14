/**
 * Presentation-facing vault workflow. No cryptography, local storage, fetch
 * calls or production service binding. Screens accept an explicitly injected
 * implementation; public MySafeSpace supplies none.
 *
 * Tests can inject an isolated, synthetic-only BrowserVaultSessionForTests.
 * Never persist decrypted entries in browser storage.
 */
export type WorkspaceEntry = Readonly<{
  entryId: string;
  revision: number;
  text: string;
}>;
export type WorkspaceHistory = Readonly<{
  entries: ReadonlyArray<WorkspaceEntry>;
  latestRevision: number;
  headDigest: string;
}>;
export type WorkspaceSnapshot = Readonly<{
  phase: "locked" | "loading" | "ready" | "saving" | "exporting" | "deleting" | "error" | "closed";
  entries: ReadonlyArray<WorkspaceEntry>;
  revision: number;
  headDigest: string | null;
  error: string | null;
}>;
export interface WorkspaceSession {
  read(): Promise<WorkspaceHistory>;
  appendSyntheticText(text: string): Promise<WorkspaceHistory>;
  export(): Promise<WorkspaceHistory>;
  requestDeletionForTests?(): Promise<void>;
  eraseEphemeralForTests?(): Promise<void>;
  close?(): void;
}

const initial: WorkspaceSnapshot = {
  phase:"locked",entries:[],revision:0,headDigest:null,error:null
};

/**
 * One operation at a time, never reports success until its result verifies,
 * and closes against pending asynchronous callbacks. This is only a UI
 * controller; all real authentication must be enforced by the service.
 */
export class VaultWorkspaceController {
  private state: WorkspaceSnapshot = initial;
  private listeners = new Set<() => void>();
  private busy = false;
  private generation = 0;
  private session: WorkspaceSession | null = null;

  getSnapshot = (): WorkspaceSnapshot => this.state;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {this.listeners.delete(listener);};
  };
  private emit(value: WorkspaceSnapshot) {
    this.state=value;
    for(const listener of this.listeners)listener();
  }
  private requireOpen(): WorkspaceSession {
    if(!this.session || this.state.phase==="closed") {
      throw new Error("No unlocked vault session.");
    }
    return this.session;
  }
  private async operate<T>(
    phase: WorkspaceSnapshot["phase"], operation: () => Promise<T>,
    commit: (result:T) => WorkspaceSnapshot
  ): Promise<T> {
    if(this.busy)throw new Error("Another vault operation is in progress.");
    this.busy=true;
    const token=this.generation;
    this.emit({...this.state,phase,error:null});
    try {
      const result=await operation();
      if(token!==this.generation)throw new Error("Vault session has closed.");
      this.emit(commit(result));
      return result;
    } catch(error) {
      if(token===this.generation) {
        this.emit({...this.state,phase:"error",
          error:error instanceof Error?error.message:"Vault operation failed."});
      }
      throw error;
    } finally {
      if(token===this.generation)this.busy=false;
    }
  }
  private ready(history:WorkspaceHistory):WorkspaceSnapshot {
    if(!history || !Number.isSafeInteger(history.latestRevision) ||
        history.latestRevision<0 || history.entries.length!==history.latestRevision ||
        !/^[0-9a-f]{64}$/.test(history.headDigest) ||
        history.entries.some((entry,index)=>
          entry.revision!==index+1 || !entry.entryId ||
          typeof entry.text!=="string")) {
      throw new Error("Incomplete vault history.");
    }
    return {
      phase:"ready",entries:history.entries.map(entry=>({...entry})),
      revision:history.latestRevision,headDigest:history.headDigest,error:null
    };
  }
  async unlock(session:WorkspaceSession):Promise<void> {
    if(this.busy)throw new Error("Another vault operation is in progress.");
    if(this.session && this.state.phase!=="closed")throw new Error("Vault already unlocked.");
    this.session=session;
    const openingGeneration=this.generation;
    try {
      await this.operate("loading",()=>session.read(),result=>this.ready(result));
    } catch {
      // An earlier, cancelled unlock must not close a subsequently opened
      // session. Its original key handle was already closed by close().
      if(this.session===session && this.generation===openingGeneration) {
        this.close();
      }
      throw new Error("Vault could not be unlocked.");
    }
  }
  async refresh():Promise<void> {
    const session=this.requireOpen();
    await this.operate("loading",()=>session.read(),result=>this.ready(result));
  }
  async saveFictionalText(text:string):Promise<void> {
    const session=this.requireOpen();
    if(typeof text!=="string" || !text.trim())throw new Error("Empty record.");
    await this.operate("saving",()=>session.appendSyntheticText(text),result=>this.ready(result));
  }
  async exportVerifiedHistory():Promise<WorkspaceHistory> {
    const session=this.requireOpen();
    return this.operate("exporting",()=>session.export(),result=>this.ready(result));
  }
  /** Erase only the current in-memory fictional vault, never a D1 record. */
  async eraseEphemeralVault():Promise<void> {
    const session=this.requireOpen();
    if(!session.eraseEphemeralForTests)throw new Error("In-memory erasure is not configured.");
    await this.operate("deleting",()=>session.eraseEphemeralForTests!(),()=>{
      this.session=null;
      return {...initial,phase:"closed"};
    });
    session.close?.();
  }
  async markDeletionPending():Promise<void> {
    const session=this.requireOpen();
    if(!session.requestDeletionForTests)throw new Error("Deletion is not configured.");
    await this.operate("deleting",()=>session.requestDeletionForTests!(),()=>{
      this.session=null;
      return {...initial,phase:"closed"};
    });
    session.close?.();
  }
  close():void {
    this.generation++;
    this.busy=false;
    const current=this.session;
    this.session=null;
    this.emit({...initial,phase:"closed"});
    current?.close?.();
  }
}
