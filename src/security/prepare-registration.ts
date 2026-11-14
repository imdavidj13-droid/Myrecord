/**
 * Test-only browser registration preparation. Never sends recovery words
 * or recovered keys across a network. No production API is used.
 */
import { verifyLocalRecoveryConsistencyForTests } from "./recovery-consistency";
import { recoverSigningCredentialForTests } from "./signing-recovery";
import { signChallengeForTests, type ProofChallengeV1 } from "./access-proof";
import { signRegistrationIntentForTests, type SignedRegistrationIntentV1 } from "./registration-intent";
import type { SignedProofV1 } from "./access-proof";
import type { SyntheticVaultBackup } from "./synthetic-vault-store";

export type PreparedRegistrationForTests = Readonly<{
  proof: SignedProofV1;
  intent: SignedRegistrationIntentV1;
  lookupId: string;
  backup: SyntheticVaultBackup;
}>;

/**
 * Fails closed before signing if backup, lookup ID and recovery words do not
 * correspond. This cannot force a malicious or altered client to comply.
 */
export async function prepareRegistrationForTests(
  phrase: string, lookupId: string, backup: SyntheticVaultBackup,
  challenge: ProofChallengeV1
): Promise<PreparedRegistrationForTests> {
  await verifyLocalRecoveryConsistencyForTests(phrase, lookupId, backup);
  if (!challenge || challenge.vaultId !== backup.vaultId || challenge.action !== "append") {
    throw new Error("Incorrect registration challenge.");
  }
  const recovered = await recoverSigningCredentialForTests(phrase, backup.wrappedSigningKey);
  const proof = await signChallengeForTests(recovered.privateKey, challenge);
  const intent = await signRegistrationIntentForTests(
    recovered.privateKey, challenge, backup, lookupId
  );
  return { proof, intent, lookupId, backup };
}
