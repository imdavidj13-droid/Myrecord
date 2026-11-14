/**
 * LOCAL CI WORKER ONLY. Never reference this entrypoint from wrangler.jsonc.
 *
 * A deliberately read-only, non-sensitive DB connectivity probe for fictional
 * sandbox fixtures. No vault ID, lookup ID, ciphertext, backup, user input,
 * authorization or mutation endpoint is exposed.
 */
interface Environment {
  DB: {
    prepare(sql: string): {
      first<T>(): Promise<T | null>;
    };
  };
}

const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  }
});

export default {
  async fetch(request: Request, env: Environment): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "GET" || url.pathname !== "/__local_test__/health") {
      return json({error:"not_found"},404);
    }
    try {
      const registration = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM sandbox_registration_challenges WHERE consumed_ms IS NOT NULL"
      ).first<{count:number}>();
      const vaults = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM sandbox_vaults WHERE status='active'"
      ).first<{count:number}>();
      const entries = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM sandbox_integrity_entries_v2"
      ).first<{count:number}>();
      const head = await env.DB.prepare(
        "SELECT COUNT(*) AS count FROM sandbox_integrity_heads_v2 WHERE latest_revision=2"
      ).first<{count:number}>();
      if (![registration,vaults,entries,head].every(Boolean)) {
        return json({ok:false},503);
      }
      // Counts contain no identifiers and do not expose encrypted records.
      const ok = registration!.count===1 &&
        vaults!.count===1 && entries!.count===2 && head!.count===1;
      return json({ok,fixture:"synthetic-local-only"},ok?200:503);
    } catch {
      return json({ok:false},503);
    }
  }
};
