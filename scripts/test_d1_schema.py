"""SQLite regression checks for non-deployed MySafeSpace D1 draft.

Runs using Python's standard library only. Uses fictional identifiers and
synthetic ciphertext. No Cloudflare binding or live database is involved.
"""
import sqlite3
from pathlib import Path

schema = Path(__file__).resolve().parents[1] / "docs" / "D1_TRANSACTIONAL_PROTOTYPE.sql"
connection = sqlite3.connect(":memory:")
connection.execute("PRAGMA foreign_keys = ON")
connection.executescript(schema.read_text(encoding="utf-8"))

vault = "syntheticVaultId123456"
lookup = "A" * 43
nonce1 = "B" * 43
nonce2 = "C" * 43
nonce3 = "D" * 43

connection.execute(
    "INSERT INTO sandbox_vaults(vault_id, lookup_id, verification_jwk, wrapped_backup_json) VALUES (?, ?, ?, ?)",
    (vault, lookup, '{"kty":"EC"}', '{"encrypted":true}'),
)
connection.executemany(
    """INSERT INTO sandbox_challenges(nonce,vault_id,action,issued_ms,expires_ms,request_digest)
    VALUES (?, ?, 'append', 1000, 61000, ?)""",
    [(nonce1, vault, "digest-1"), (nonce2, vault, "digest-2"), (nonce3, vault, "digest-3")],
)
connection.commit()

claim_sql = """
INSERT INTO sandbox_consumed_nonces(nonce, consumed_ms)
VALUES (
    (SELECT nonce FROM sandbox_challenges
     WHERE nonce = ? AND vault_id = ? AND action = 'append'
       AND issued_ms = ? AND expires_ms = ? AND request_digest = ?
       AND issued_ms <= ? AND expires_ms > ?),
    ?
)
"""

def claim(nonce: str, digest: str, at: int = 2000) -> None:
    connection.execute(
        claim_sql, (nonce, vault, 1000, 61000, digest, at + 5000, at, at)
    )

def entry(entry_id: str, revision: int) -> None:
    connection.execute(
        """INSERT INTO sandbox_entries
        (entry_id,vault_id,revision,encrypted_envelope_json,server_received_ms)
        VALUES (?, ?, ?, ?, ?)""",
        (entry_id, vault, revision, '{"ciphertext":"synthetic"}', 2000),
    )

def assert_failure(label: str, action) -> None:
    try:
        action()
    except sqlite3.IntegrityError:
        connection.rollback()
    else:
        connection.rollback()
        raise AssertionError(f"Expected constraint rejection: {label}")

with connection:
    claim(nonce1, "digest-1")
    entry("fictional-entry-1", 1)

assert connection.execute(
    "SELECT latest_revision FROM sandbox_vaults WHERE vault_id=?", (vault,)
).fetchone()[0] == 1

assert_failure("nonce replay", lambda: claim(nonce1, "digest-1"))
assert_failure("incorrect request digest", lambda: claim(nonce2, "wrong"))
assert_failure("expired challenge", lambda: claim(nonce2, "digest-2", 61000))

def conflicting_revision():
    with connection:
        claim(nonce2, "digest-2")
        entry("fictional-entry-2", 3)  # expected revision 2; trigger rejects

assert_failure("non-sequential revision", conflicting_revision)
assert connection.execute(
    "SELECT 1 FROM sandbox_consumed_nonces WHERE nonce=?", (nonce2,)
).fetchone() is None, "Rejected append must roll back its nonce claim"

with connection:
    claim(nonce2, "digest-2")
    entry("fictional-entry-2", 2)
assert connection.execute(
    "SELECT latest_revision FROM sandbox_vaults WHERE vault_id=?", (vault,)
).fetchone()[0] == 2

assert_failure("update existing entry", lambda: connection.execute(
    "UPDATE sandbox_entries SET encrypted_envelope_json='changed' WHERE entry_id='fictional-entry-1'"
))
assert_failure("delete existing entry", lambda: connection.execute(
    "DELETE FROM sandbox_entries WHERE entry_id='fictional-entry-1'"
))
assert_failure("change registered verifier", lambda: connection.execute(
    "UPDATE sandbox_vaults SET verification_jwk='replacement' WHERE vault_id=?", (vault,)
))
assert_failure("change encrypted backup", lambda: connection.execute(
    "UPDATE sandbox_vaults SET wrapped_backup_json='replacement' WHERE vault_id=?", (vault,)
))
assert_failure("re-register lookup ID", lambda: connection.execute(
    "INSERT INTO sandbox_vaults(vault_id, lookup_id, verification_jwk, wrapped_backup_json) VALUES (?, ?, ?, ?)",
    ("anotherSyntheticVault123", lookup, "{}", "{}")
))

count = connection.execute("SELECT COUNT(*) FROM sandbox_entries").fetchone()[0]
assert count == 2
print("D1 draft schema SQLite checks passed: replay, rollback, sequential append, immutability.")
