"""Migrate an OFFLINE private registry copy to the wallet provider's named IdP.

Stop the custodian and identity writers first. Back up the live volume, migrate a
copy, verify the report, then install it with the original ownership. Never run
against a live registry. Identity subjects, account IDs and wallet/key bindings
are retained; old application sessions and pending consent are invalidated.
"""
import argparse
import json
from pathlib import Path
import sqlite3
import time
import uuid

OLD = 'https://auth-p2.demo.inoerawan.id/realms/competency-proof-p2'
NEW = 'https://login-dompet-identitas.demo.inoerawan.id/realms/competency-proof-p2'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--offline-copy',type=Path,required=True)
p.add_argument('--backup',type=Path,required=True)
p.add_argument('--report',type=Path,required=True)
a=p.parse_args()
for path in (a.offline_copy,a.backup,a.report):
    assert 'runtime' in path.resolve().parts,'Use private ignored runtime paths'
assert a.offline_copy.is_file() and not a.backup.exists()
with sqlite3.connect(a.offline_copy) as db:
    assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
    with sqlite3.connect(a.backup) as backup:db.backup(backup)
    a.backup.chmod(0o600)
    before=db.execute('SELECT id,subject,revision,gate FROM accounts ORDER BY id').fetchall()
    bindings=db.execute('SELECT * FROM wallet_bindings ORDER BY account_id').fetchall()
    assert not db.execute("SELECT 1 FROM accounts a JOIN accounts b ON a.subject=b.subject WHERE a.issuer=? AND b.issuer=?",(OLD,NEW)).fetchone(),'Conflicting identity mapping; reconcile manually'
    assert not db.execute("SELECT 1 FROM pending_operations WHERE state='DISPATCHED'").fetchone(),'Reconcile active dispatch first'
    accounts=[r[0] for r in db.execute('SELECT id FROM accounts WHERE issuer=?',(OLD,))]
    with db:
        db.execute('UPDATE accounts SET issuer=? WHERE issuer=?',(NEW,OLD))
        db.execute('UPDATE app_sessions SET revoked=1')
        db.execute("UPDATE pending_operations SET state='CANCELLED',reason='Identity service domain changed; start a new review' WHERE state='PENDING'")
        db.execute("UPDATE exchange_contexts SET state='EXPIRED' WHERE id IN (SELECT id FROM pending_operations WHERE state='CANCELLED')")
        for account in accounts:
            db.execute('INSERT INTO audit VALUES(?,?,?,?,?)',(str(uuid.uuid4()),account,'IDENTITY_DOMAIN_MIGRATED',NEW,int(time.time())))
        assert before==db.execute('SELECT id,subject,revision,gate FROM accounts ORDER BY id').fetchall()
        assert bindings==db.execute('SELECT * FROM wallet_bindings ORDER BY account_id').fetchall()
        assert not db.execute('SELECT 1 FROM app_sessions WHERE revoked=0').fetchone()
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
    assert db.execute('PRAGMA integrity_check').fetchone()==('ok',)
a.report.write_text(json.dumps({'result':'PASS','from':OLD,'to':NEW,'migratedAccounts':len(accounts),'walletBindingsRetained':len(bindings),'accountIdsSubjectsRevisionsGatesUnchanged':True,'oldSessionsRevoked':True,'oldPendingConsentCancelled':True,'sqliteIntegrity':'ok','limit':'Offline copy migration; install and verify live continuity separately'},indent=2)+'\n')
a.report.chmod(0o600)
print('PASS: offline issuer migration preserves account/subject/revision/gate and wallet/key bindings; old sessions cannot be reused.')
