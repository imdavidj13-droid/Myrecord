"""Isolated SQLite checks for MySafeSpace v2 digest-chain schema extension.
Synthetic placeholder envelope digests only; no real data or cloud access.
"""
import sqlite3
from pathlib import Path

root=Path(__file__).resolve().parents[1]
db=sqlite3.connect(":memory:")
db.execute("PRAGMA foreign_keys=ON")
db.executescript((root/"docs/D1_TRANSACTIONAL_PROTOTYPE.sql").read_text(encoding="utf-8"))
db.executescript((root/"docs/D1_V2_INTEGRITY_EXTENSION.sql").read_text(encoding="utf-8"))
vault="syntheticVaultId123456"
zero="0"*64
digest1="a"*64
digest2="b"*64
db.execute(
    "INSERT INTO sandbox_vaults(vault_id,lookup_id,verification_jwk,wrapped_backup_json) VALUES(?,?,?,?)",
    (vault,"X"*43,"{}","{}")
)
db.execute("INSERT INTO sandbox_integrity_heads_v2(vault_id) VALUES(?)",(vault,))
db.commit()

def append(identifier,revision,prior,digest):
    db.execute(
      """INSERT INTO sandbox_integrity_entries_v2
      (entry_id,vault_id,revision,previous_digest,envelope_digest,encrypted_envelope_json,server_received_ms)
      VALUES(?,?,?,?,?,?,?)""",
      (identifier,vault,revision,prior,digest,"{\"fictional\":true}",1000)
    )

with db:
    append("syntheticEntryOne123",1,zero,digest1)
assert db.execute("SELECT latest_revision,head_digest FROM sandbox_integrity_heads_v2").fetchone()==(1,digest1)

def reject(label,operation):
    try:
        with db:
            operation()
    except sqlite3.IntegrityError:
        pass
    else:
        raise AssertionError(f"Expected rejection: {label}")

reject("wrong prior digest",lambda:append("syntheticEntryTwo123",2,zero,digest2))
reject("skipped revision",lambda:append("syntheticEntryTwo123",3,digest1,digest2))
assert db.execute("SELECT latest_revision,head_digest FROM sandbox_integrity_heads_v2").fetchone()==(1,digest1)
with db:
    append("syntheticEntryTwo123",2,digest1,digest2)
assert db.execute("SELECT latest_revision,head_digest FROM sandbox_integrity_heads_v2").fetchone()==(2,digest2)
reject("record mutation",lambda:db.execute(
    "UPDATE sandbox_integrity_entries_v2 SET envelope_digest=? WHERE revision=1",(digest2,)
))
reject("record deletion",lambda:db.execute(
    "DELETE FROM sandbox_integrity_entries_v2 WHERE revision=1"
))
with db:
    db.execute("UPDATE sandbox_vaults SET status='deletion_pending' WHERE vault_id=?",(vault,))
reject("append on inactive vault",lambda:append("syntheticEntryThree123",3,digest2,"c"*64))
print("V2 integrity schema checks passed: continuity, append-only, deletion-pending.")
