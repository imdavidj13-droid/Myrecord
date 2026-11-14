"""Non-deployed SQLite regression for atomic MySafeSpace registration.

Uses entirely fictional identifiers; makes no Cloudflare or network calls.
Run: python3 scripts/test_d1_registration.py
"""
import sqlite3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
db = sqlite3.connect(":memory:")
db.execute("PRAGMA foreign_keys=ON")
for name in (
    "D1_TRANSACTIONAL_PROTOTYPE.sql",
    "D1_V2_INTEGRITY_EXTENSION.sql",
    "D1_REGISTRATION_PROTOTYPE.sql",
):
    db.executescript((root / "docs" / name).read_text(encoding="utf-8"))

vault_id = "fictionalVaultId123456"
lookup_id = "R" * 43
nonce = "N" * 43
marker = "M" * 43
at = 2001

def challenge(n, vault=vault_id):
    db.execute(
        """INSERT INTO sandbox_registration_challenges
           (nonce,vault_id,action,issued_ms,expires_ms)
           VALUES (?,?,'append',1000,61000)""", (n, vault)
    )
    db.commit()

def register(n, token, time=at, vault=vault_id, lookup=lookup_id):
    with db:
        db.execute(
            """UPDATE sandbox_registration_challenges
               SET consumed_ms=?,consume_marker=?
               WHERE nonce=? AND vault_id=? AND action='append'
                 AND issued_ms=1000 AND expires_ms=61000
                 AND consumed_ms IS NULL
                 AND issued_ms<=? AND expires_ms>?""",
            (time,token,n,vault,time+5000,time)
        )
        db.execute(
            """INSERT INTO sandbox_vaults
               (vault_id,lookup_id,verification_jwk,wrapped_backup_json)
               VALUES (
                 (SELECT vault_id FROM sandbox_registration_challenges
                  WHERE nonce=? AND vault_id=? AND consumed_ms=?
                    AND consume_marker=?),
                 ?,?,?)""",
            (n,vault,time,token,lookup,'{"kty":"EC"}','{"fictional":true}')
        )
        db.execute(
            "INSERT INTO sandbox_integrity_heads_v2(vault_id) VALUES (?)", (vault,)
        )

def expect_failure(label, fn):
    try:
        fn()
    except sqlite3.IntegrityError:
        db.rollback()
    else:
        raise AssertionError(f"Expected failure: {label}")

challenge(nonce)
expect_failure("wrong registration marker", lambda: register(nonce, marker, time=61000))
assert db.execute(
    "SELECT consumed_ms FROM sandbox_registration_challenges WHERE nonce=?",(nonce,)
).fetchone()[0] is None

register(nonce,marker)
assert db.execute(
    "SELECT COUNT(*) FROM sandbox_vaults WHERE vault_id=?",(vault_id,)
).fetchone()[0] == 1
assert db.execute(
    "SELECT latest_revision FROM sandbox_integrity_heads_v2 WHERE vault_id=?",(vault_id,)
).fetchone()[0] == 0

expect_failure("replay with a new marker", lambda: register(nonce,"Z"*43))
expect_failure("replay with original marker", lambda: register(nonce,marker))
assert db.execute(
    "SELECT consume_marker FROM sandbox_registration_challenges WHERE nonce=?",(nonce,)
).fetchone()[0] == marker

another_vault = "anotherVaultId123456"
another_nonce = "X"*43
challenge(another_nonce,another_vault)
expect_failure("lookup uniqueness rolls back nonce", lambda: register(
    another_nonce,"Y"*43,vault=another_vault,lookup=lookup_id
))
assert db.execute(
    "SELECT consumed_ms FROM sandbox_registration_challenges WHERE nonce=?",(another_nonce,)
).fetchone()[0] is None

expect_failure("vault without consumed registration challenge", lambda: db.execute(
    """INSERT INTO sandbox_vaults(vault_id,lookup_id,verification_jwk,wrapped_backup_json)
       VALUES (?,?,?,?)""",("orphanVaultId123456","Q"*43,"{}","{}")
))
assert db.execute("SELECT COUNT(*) FROM sandbox_vaults").fetchone()[0] == 1
print("D1 prototype registration SQLite checks passed: atomicity, expiry, replay, lookup uniqueness.")
