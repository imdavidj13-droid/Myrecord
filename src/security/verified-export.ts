/**
 * P3: verified export packaging for synthetic-only record lifecycles.
 *
 * Produces a readable JSON document only after the authenticated client has
 * verified/decrypted the full v2 history. This file itself contains plaintext:
 * it must never be automatically downloaded, logged, uploaded or persisted.
 */
import type { WorkspaceHistory } from "../vault-workspace";

export type VerifiedExportV1 = Readonly<{
  format: "mysafespace-fictional-verified-export";
  version: 1;
  warning: "FICTIONAL TEST CONTENT ONLY — NOT A FORENSIC CERTIFICATION";
  latestRevision: number;
  headDigest: string;
  entries: ReadonlyArray<Readonly<{
    revision: number; entryId: string; text: string;
  }>>;
}>;
const hex=/^[0-9a-f]{64}$/;
const id=/^[A-Za-z0-9_-]{16,128}$/;

export function packageVerifiedExportForTests(history:WorkspaceHistory): VerifiedExportV1 {
  if (!history || !Number.isSafeInteger(history.latestRevision) ||
      history.latestRevision<0 || history.latestRevision!==history.entries?.length ||
      !hex.test(history.headDigest) ||
      history.entries.some((entry,index)=>
        !entry || entry.revision!==index+1 ||
        !id.test(entry.entryId) || typeof entry.text!=="string")) {
    throw new Error("Verified export history is incomplete.");
  }
  const entries=history.entries.map(e=>({
    revision:e.revision, entryId:e.entryId,text:e.text
  }));
  return {
    format:"mysafespace-fictional-verified-export",
    version:1,
    warning:"FICTIONAL TEST CONTENT ONLY — NOT A FORENSIC CERTIFICATION",
    latestRevision:history.latestRevision,
    headDigest:history.headDigest,
    entries
  };
}
export function serializeVerifiedExportForTests(history:WorkspaceHistory):string {
  return JSON.stringify(packageVerifiedExportForTests(history),null,2)+"\n";
}
