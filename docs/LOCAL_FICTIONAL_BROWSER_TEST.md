# MySafeSpace — fictional localhost browser testing

**Development-only. Never enter real testimony, names, personal details or actual recovery words.**

The public website still has no live storage. This local-only harness uses the
**real React pages** and the existing *synthetic* signed vault client with a
fresh temporary Wrangler D1 database. It exists to validate the actual UI flow
without touching the production `mysafespace-db`.

## Prerequisites

- Node.js 22 or later
- A local checkout of `imdavidj13-droid/Myrecord`
- Dependencies installed with `npm install`

From the repository directory, run:

```bash
node scripts/start_local_browser_test.mjs
```

Then open:

**http://127.0.0.1:5176/local-test.html**

The launcher applies sandbox-only schemas to temporary **local** D1 state,
starts a Wrangler Worker at `127.0.0.1:18880`, and starts a separate Vite
server at `127.0.0.1:5176` with a same-origin proxy to the local Worker.
Nothing connects to any Cloudflare remote database.

## Manual acceptance scenario

1. Click **Create fictional vault**; record the displayed *test-only* twelve words.
2. Navigate to **Writing space**. Enter only a phrase such as
   `FICTIONAL ENTRY — no personal information` and click **Save fictional entry**.
3. Open **Vault**; confirm entry 1 appears and the revision is reported.
4. Add a second fictional entry; confirm the previous entry remains unchanged.
5. Visit **Export & deletion**, prepare a fictional JSON export and explicitly
   download it; verify both entries and the revision metadata. The export is
   readable plaintext on disk, so use only fictional text and delete the file.
6. Click **Close and clear test session**, then use **Test recovery** and enter
   the original fictional twelve words. Confirm both entries reappear.
7. Visit **Export & deletion** again; review and confirm the deletion-pending
   status with the exact confirmation string. Check that the test session
   closes and cannot read further records.
8. Stop the launcher with **Ctrl+C**. Its temporary local D1 state is deleted.

## Important limitations

- This harness is not configured as the production Vite/Workers entrypoint.
  The public `index.html` uses `src/main.tsx`, which does **not** inject a
  vault transport.
- Closing a session clears UI state and drops references to keys, subject to
  JavaScript garbage collection. This is not guaranteed zeroization.
- A `deletion_pending` transition is **not physical erasure**. Backups and
  retention policies need review.
- Chain validation cannot independently prove the backend has not hidden all
  historical revisions across a device restart. Externally anchored integrity
  still needs to be designed.
- Browser tests should cover refresh interruption, simultaneous revisions,
  blocked network requests, inaccessible browser storage and assistive
  technology before any live use.
- Never deploy `wrangler.protocol-test.jsonc` or expose
  `scripts/worker-protocol-test.ts` on the public hostname.
- Formal cryptographic/security, legal, privacy and safeguarding review is
  required before enabling real-user storage.
