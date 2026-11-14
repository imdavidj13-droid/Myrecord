# MyRecord

A privacy-first, **text-only** survivor testimony vault concept.

> **DESIGN PROTOTYPE ONLY — DO NOT ENTER REAL TESTIMONY.** This implementation intentionally has no backend, persistent storage, encryption, user accounts, recovery keys or police export. It must not be offered to survivors as a secure service until a reviewed cryptographic protocol, legal/safeguarding requirements, independent penetration testing and an operational security review are complete.

## Run locally

```bash
npm install
npm run dev
```

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

## Prototype behaviour

All text is kept only in the currently open page's React state. **It is not encrypted or saved and will be lost when the page reloads or closes.** Use synthetic test text only.
