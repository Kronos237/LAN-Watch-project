"""Lazy local SQLite history, exports, and scan comparison."""
import csv, json, sqlite3
from pathlib import Path

class HistoryStore:
    def __init__(self, path=None): self.path = Path(path or Path.home()/".lan-watch"/"history.sqlite3")
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db=sqlite3.connect(self.path); db.execute("PRAGMA foreign_keys=ON")
        db.executescript("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, started TEXT, finished TEXT, status TEXT, network TEXT, error TEXT); CREATE TABLE IF NOT EXISTS observations(scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE, ip TEXT, mac TEXT, hostname TEXT, vendor TEXT, observed TEXT, source TEXT, local INTEGER, gateway INTEGER); CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, time TEXT, kind TEXT, ip TEXT, mac TEXT, detail TEXT);")
        return db
    def save(self, result):
        with self.connect() as db:
            cur=db.execute("INSERT INTO scans(started,finished,status,network,error) VALUES(?,?,?,?,?)", (result.started_at,result.finished_at,result.status,json.dumps(result.network),result.error))
            sid=cur.lastrowid
            db.executemany("INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?)", [(sid,d.get("ip"),d.get("mac"),d.get("hostname"),d.get("vendor"),d.get("last_observed"),d.get("source"),int(d.get("is_local",False)),int(d.get("is_gateway",False))) for d in result.devices])
            db.execute("DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT 500)")
            return sid
    def record_events(self, events):
        if not events: return
        with self.connect() as db:
            db.executemany("INSERT INTO events(time,kind,ip,mac,detail) VALUES(?,?,?,?,?)",
                           [(e.get("time"),e.get("kind"),e.get("ip"),e.get("mac"),e.get("detail")) for e in events])
    def events(self, limit=100):
        with self.connect() as db: return db.execute("SELECT time,kind,ip,mac,detail FROM events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    def scans(self, limit=100):
        with self.connect() as db: return db.execute("SELECT id,started,finished,status,network,error FROM scans ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    def observations(self, scan_id):
        with self.connect() as db: return db.execute("SELECT ip,mac,hostname,vendor,observed,source,local,gateway FROM observations WHERE scan_id=?",(scan_id,)).fetchall()
    def export(self, scan_id, fmt, path):
        rows=self.observations(scan_id); fields=["ip","mac","hostname","vendor","observed","source","local","gateway"]
        records=[dict(zip(fields,row)) for row in rows]
        if fmt == "json": Path(path).write_text(json.dumps(records,indent=2),encoding="utf-8")
        elif fmt == "csv":
            with open(path,"w",newline="",encoding="utf-8") as f:
                writer=csv.DictWriter(f,fieldnames=fields); writer.writeheader(); writer.writerows(records)
        else: raise ValueError("format must be csv or json")
        return records
    def compare(self, first, second):
        a={r[1]:r for r in self.observations(first) if r[1]}; b={r[1]:r for r in self.observations(second) if r[1]}
        return {"new_observations":list(b.keys()-a.keys()),"not_observed_in_second_scan":list(a.keys()-b.keys()),"retained":list(a.keys()&b.keys())}
