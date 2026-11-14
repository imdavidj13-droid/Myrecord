"""Concurrent SQLite regression for the isolated D1 draft, no cloud access.

Tests two writers racing to append revision 1. Exactly one must commit,
and a failed writer's challenge claim must roll back. This tests SQLite
constraints, NOT Cloudflare D1 concurrency or edge deployment behavior.
"""
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

SCHEMA = (Path(__file__).resolve().parents[1] /
          "docs" / "D1_TRANSACTIONAL_PROTOTYPE.sql").read_text(encoding="utf-8")

VAULT = "syntheticVaultId123456"
NONCES = ["A" * 43, "B" * 43]

CLAIM = """
INSERT INTO sandbox_consumed_nonces(nonce,consumed_ms)
VALUES ((SELECT nonce FROM sandbox_challenges WHERE
    nonce=? AND vault_id=? AND action='append'
    AND issued_ms=1000 AND expires_ms=61000 AND request_digest=?
    AND issued_ms <= 2000 AND expires_ms > 2000), 2000)
"""
APPEND = """
INSERT INTO sandbox_entries(entry_id,vault_id,revision,encrypted_envelope_json,server_received_ms)
VALUES (?, ?, 1, '{"ciphertext":"fictional"}', 2000)
"""

with tempfile.TemporaryDirectory(prefix="mysafespace-sqlite-") as tmp:
    path = str(Path(tmp) / "vault.db")
    initial = sqlite3.connect(path, timeout=5)
    initial.execute("PRAGMA foreign_keys=ON")
    initial.execute("PRAGMA journal_mode=WAL")
    initial.executescript(SCHEMA)
    initial.execute(
        "INSERT INTO sandbox_vaults(vault_id, lookup_id, verification_jwk, wrapped_backup_json) "
        "VALUES (?, ?, '{}', '{}')", (VAULT, "X" * 43)
    )
    for i, nonce in enumerate(NONCES):
        initial.execute(
            "INSERT INTO sandbox_challenges(nonce,vault_id,action,issued_ms,expires_ms,request_digest) "
            "VALUES (?, ?, 'append', 1000, 61000, ?)",
            (nonce, VAULT, f"digest-{i}")
        )
    initial.commit()
    initial.close()

    ready = Barrier(2)

    def writer(index: int) -> bool:
        conn = sqlite3.connect(path, timeout=5)
        conn.execute("PRAGMA foreign_keys=ON")
        ready.wait(timeout=5)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(CLAIM, (NONCES[index], VAULT, f"digest-{index}"))
            conn.execute(APPEND, (f"synthetic-entry-{index}", VAULT))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            conn.rollback()
            return False
        finally:
            conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(writer, [0, 1]))

    verify = sqlite3.connect(path)
    entries = verify.execute("SELECT entry_id, revision FROM sandbox_entries").fetchall()
    claims = verify.execute("SELECT nonce FROM sandbox_consumed_nonces").fetchall()
    revision = verify.execute(
        "SELECT latest_revision FROM sandbox_vaults WHERE vault_id=?", (VAULT,)
    ).fetchone()[0]
    verify.close()
    assert sorted(outcomes) == [False, True], outcomes
    assert len(entries) == 1 and entries[0][1] == 1, entries
    assert len(claims) == 1, claims
    assert revision == 1, revision

print("SQLite concurrent append regression passed: one writer wins, loser rolls back.")
