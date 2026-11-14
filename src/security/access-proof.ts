/**
 * MySafeSpace experimental anonymous access proof — SYNTHETIC TEST DATA ONLY.
 *
 * The server keeps only a public verification key and single-use challenges.
 * The browser holds the signing key. This avoids sending recovery words to the
 * server, but DOES NOT implement persistence, phrase-based recovery, storage
 * authorisation, session issuance, account protection or rollout security.
 *
 * Do not expose these prototypes as live API endpoints.
 */
export type VaultAction = "read" | "append" | "export" | "delete";
export type ProofChallengeV1 = Readonly<{
  version: 1;
  vaultId: string;
  action: VaultAction;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
}>;
export type SignedProofV1 = Readonly<{
  version: 1;
  challenge: ProofChallengeV1;
  signature: string;
}>;

const domain = "mysafespace:access-proof:v1";
const encoder = new TextEncoder();
const maxLifetimeMs = 60_000;
const maxClockSkewMs = 5_000;
const allowedActions: ReadonlyArray<VaultAction> = ["read", "append", "export", "delete"];
const vaultPattern = /^[A-Za-z0-9_-]{16,128}$/;

function api(): Crypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw new Error("Web Crypto is required.");
  }
  return globalThis.crypto;
}

function binary(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function b64u(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeB64u(value: unknown, expectedLength: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) ||
      value.length > Math.ceil(expectedLength * 4 / 3) + 2) {
    throw new Error("Invalid proof encoding.");
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(padded + "=".repeat((4 - padded.length % 4) % 4));
  const bytes = Uint8Array.from(Array.from(raw, char => char.charCodeAt(0)));
  if (bytes.length !== expectedLength || b64u(bytes) !== value) {
    throw new Error("Invalid proof encoding.");
  }
  return bytes;
}

function validateChallenge(challenge: ProofChallengeV1): void {
  if (!challenge || challenge.version !== 1 || !vaultPattern.test(challenge.vaultId) ||
      !allowedActions.includes(challenge.action) ||
      !Number.isSafeInteger(challenge.issuedAt) || !Number.isSafeInteger(challenge.expiresAt) ||
      challenge.expiresAt <= challenge.issuedAt ||
      challenge.expiresAt - challenge.issuedAt > maxLifetimeMs) {
    throw new Error("Invalid challenge.");
  }
  decodeB64u(challenge.nonce, 32);
}

function signedBytes(challenge: ProofChallengeV1): ArrayBuffer {
  validateChallenge(challenge);
  // Canonical fixed-order context, not an arbitrary JSON string.
  return binary(encoder.encode([
    domain, challenge.version, challenge.vaultId, challenge.action,
    challenge.nonce, challenge.issuedAt, challenge.expiresAt
  ].join("\n")));
}

export async function makeEphemeralSigningPairForTests(): Promise<CryptoKeyPair> {
  return api().subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]
  );
}

export async function exportVerificationKeyForTests(key: CryptoKey): Promise<JsonWebKey> {
  if (key.type !== "public") throw new Error("Only public keys may be exported.");
  return api().subtle.exportKey("jwk", key);
}

export async function importVerificationKeyForTests(jwk: JsonWebKey): Promise<CryptoKey> {
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y || jwk.d) {
    throw new Error("Invalid public verification key.");
  }
  return api().subtle.importKey(
    "jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
  );
}

/** Server-side challenge generator prototype. Requires secure session binding in real deployment. */
export function issueChallengeForTests(
  vaultId: string, action: VaultAction, now = Date.now()
): ProofChallengeV1 {
  if (!Number.isSafeInteger(now) || !vaultPattern.test(vaultId) ||
      !allowedActions.includes(action)) throw new Error("Invalid challenge request.");
  const challenge: ProofChallengeV1 = {
    version: 1, vaultId, action,
    nonce: b64u(api().getRandomValues(new Uint8Array(32))),
    issuedAt: now, expiresAt: now + maxLifetimeMs
  };
  validateChallenge(challenge);
  return challenge;
}

/** Browser-side signer prototype. Never uses or accepts recovery words. */
export async function signChallengeForTests(
  privateKey: CryptoKey, challenge: ProofChallengeV1
): Promise<SignedProofV1> {
  if (privateKey.type !== "private" || !privateKey.usages.includes("sign")) {
    throw new Error("A signing private key is required.");
  }
  const signature = await api().subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, privateKey, signedBytes(challenge)
  );
  return { version: 1, challenge, signature: b64u(new Uint8Array(signature)) };
}

/**
 * In-memory, single-use server-side verifier for tests. Never treat it as a
 * distributed replay store: Workers require transactional, shared state.
 */
export class InMemoryProofVerifierForTests {
  private readonly outstanding = new Map<string, ProofChallengeV1>();

  register(challenge: ProofChallengeV1): void {
    validateChallenge(challenge);
    if (this.outstanding.has(challenge.nonce)) throw new Error("Duplicate challenge.");
    this.outstanding.set(challenge.nonce, { ...challenge });
  }

  async verify(
    proof: SignedProofV1,
    publicKey: CryptoKey,
    expectedVaultId: string,
    expectedAction: VaultAction,
    now = Date.now()
  ): Promise<boolean> {
    if (!proof || proof.version !== 1 || !proof.challenge || !Number.isSafeInteger(now)) return false;
    let challenge: ProofChallengeV1;
    try {
      challenge = proof.challenge;
      validateChallenge(challenge);
      if (challenge.vaultId !== expectedVaultId || challenge.action !== expectedAction ||
          now < challenge.issuedAt - maxClockSkewMs || now >= challenge.expiresAt) return false;
      const registered = this.outstanding.get(challenge.nonce);
      if (!registered) return false;
      // Check all fields against the original server-issued challenge.
      if (signedFingerprint(registered) !== signedFingerprint(challenge)) return false;
      // Consume before verifying so all failed attempts also burn the challenge.
      this.outstanding.delete(challenge.nonce);
      if (publicKey.type !== "public" || !publicKey.usages.includes("verify")) return false;
      const signature = decodeB64u(proof.signature, 64); // P-256 IEEE-P1363 signature
      return await api().subtle.verify(
        { name: "ECDSA", hash: "SHA-256" }, publicKey,
        binary(signature), signedBytes(challenge)
      );
    } catch {
      return false;
    }
  }
}

function signedFingerprint(challenge: ProofChallengeV1): string {
  return [
    challenge.version, challenge.vaultId, challenge.action,
    challenge.nonce, challenge.issuedAt, challenge.expiresAt
  ].join("\n");
}
