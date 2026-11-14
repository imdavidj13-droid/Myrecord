/**
 * CI-ONLY authenticated protocol Worker.
 *
 * This entrypoint is referenced exclusively by wrangler.protocol-test.jsonc
 * (fictional database UUID). The deployed wrangler.jsonc must NEVER point at
 * this file. Do not make these paths publicly available.
 *
 * All request bodies must contain synthetic ciphertext metadata and signatures
 * only. Recovery words, private keys and plaintext are rejected by shape.
 */
import { createD1VaultTransportForTests } from "../src/security/d1-v2-transport";
import type { PrototypeD1Database } from "../src/security/d1-transaction";

type Env = { DB: PrototypeD1Database };
const prefix = "/__local_protocol__/";
const maxBody = 1_900_000;

function response(value: unknown, status=200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    }
  });
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid request object.");
  }
  return value as Record<string, unknown>;
}
function requireKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  if (Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.prototype.hasOwnProperty.call(value,key))) {
    throw new Error("Unexpected request fields.");
  }
}
function noSecrets(value: unknown): void {
  // This is an accidental-use guard, not a complete data-loss prevention tool.
  if (!value || typeof value !== "object") return;
  for (const [key, nested] of Object.entries(value)) {
    if (/^(?:recoveryPhrase|phrase|plaintext|privateKey|privateSigningKey|password|testimony)$/i.test(key)) {
      throw new Error("Sensitive fields are forbidden.");
    }
    noSecrets(nested);
  }
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST" || !url.pathname.startsWith(prefix)) {
      return response({error:"not_found"},404);
    }
    if (Number(request.headers.get("content-length") || 0) > maxBody) {
      return response({error:"payload_too_large"},413);
    }
    const route = url.pathname.slice(prefix.length);
    const supported = [
      "register-challenge","register","lookup","read-challenge","read",
      "append-challenge","append"
    ];
    if (!supported.includes(route)) return response({error:"not_found"},404);
    let payload: Record<string,unknown>;
    try {
      const text = await request.text();
      if (text.length > maxBody) return response({error:"payload_too_large"},413);
      payload = object(JSON.parse(text));
      noSecrets(payload);
      const transport = createD1VaultTransportForTests(env.DB, () => Date.now());
      switch (route) {
        case "register-challenge": {
          requireKeys(payload,["vaultId"]);
          return response(await transport.issueRegistrationChallenge(payload.vaultId as string));
        }
        case "register": {
          requireKeys(payload,["backup","lookupId","proof","intent"]);
          await transport.register(payload as Parameters<typeof transport.register>[0]);
          return response({ok:true});
        }
        case "lookup": {
          requireKeys(payload,["lookupId"]);
          return response(await transport.lookup(payload.lookupId as string));
        }
        case "read-challenge": {
          requireKeys(payload,["vaultId","action"]);
          const action=payload.action;
          if (action!=="read" && action!=="export") throw new Error("Invalid read action.");
          return response(await transport.issueReadChallenge(payload.vaultId as string,action));
        }
        case "read": {
          requireKeys(payload,["vaultId","action","challenge","proof"]);
          return response(await transport.read(payload as Parameters<typeof transport.read>[0]));
        }
        case "append-challenge": {
          requireKeys(payload,["envelope"]);
          return response(await transport.issueAppendChallenge(
            payload.envelope as Parameters<typeof transport.issueAppendChallenge>[0]
          ));
        }
        case "append": {
          requireKeys(payload,["envelope","challenge","proof"]);
          await transport.append(payload as Parameters<typeof transport.append>[0]);
          return response({ok:true});
        }
      }
    } catch {
      // No error details, record IDs, crypto material, or raw input in replies.
      return response({error:"request_rejected"},400);
    }
    return response({error:"not_found"},404);
  }
};
