# MySafeSpace

A privacy-first, **text-only** survivor testimony vault concept.

> **DESIGN PROTOTYPE ONLY — DO NOT ENTER REAL TESTIMONY.** The public website has no persistent record storage, registered vault accounts, usable recovery credentials or police export. It provides a fictional-only, browser-memory AES-GCM test mode. Signed D1 adapters remain experimental and are not publicly enabled. It must not be offered to survivors as a secure service until a reviewed cryptographic protocol, legal/safeguarding requirements, independent penetration testing and an operational security review are complete.

## Run locally

```bash
npm install
npm run dev
```

Run the test suite with `npm test` and check the production build with `npm run build`.

Security development notes: [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md).

## Product design

Approved identity: warm ivory, deep forest green, sage accents, subtle botanical details, spacious editorial typography, gentle and non-pressuring copy. The main writing experience includes Free Writing, Journal, Guided and Focus modes.

## Non-negotiable future requirements

- Text-only records; no uploads.
- Client-side encryption with independently reviewed key handling.
- Twelve-word recovery phrase generated from secure randomness.
- No operator access to plaintext or decryption keys.
- No public posts, public profiles, or compulsory email.
- Survivor-initiated readable exports with original-entry history and integrity metadata.
- No automatic police sharing.
- Careful treatment of minors, safeguarding, consent, lawful disclosure requests and metadata.
- Never silently persist plaintext; never send testimony to analytics, logs, or third-party scripts.

## Existing-site fictional testing

Use **Start fictional test** on the current MySafeSpace website. The real writing, dashboard and export screens can now save and display invented entries in a browser-memory AES-256-GCM vault.

**Important:** The records are not saved to Cloudflare D1, files, localStorage or any remote system. Refreshing, closing the browser tab or ending the test destroys all entries. Recovery and actual permanent deletion remain unavailable in this mode. Never enter real experiences, names or identifying information.

