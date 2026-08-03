"""Regression tests for SQLite locking in the scan-results database.

`save_scan_result` used to call `_update_statistics()` while still holding its
own write transaction. The nested call opened a *second* connection, which then
blocked on the write lock the caller already held, and with SQLite's default
busy timeout of 0 it failed instantly with "database is locked". The failure was
swallowed by a bare `except`, so every scan silently left the `statistics` table
stale.
"""

import sqlite3
import threading

from threatxtension.api.database import Database


def _result(extension_id, *, findings=3, files=("a.js", "b.js")):
    return {
        "extension_id": extension_id,
        "timestamp": "2026-01-01T00:00:00",
        "status": "completed",
        "overall_security_score": 70,
        "overall_risk": "critical",
        "total_findings": findings,
        "extracted_files": list(files),
    }


def _stats_table(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return {
            row["metric_name"]: row["metric_value"]
            for row in conn.execute("SELECT metric_name, metric_value FROM statistics")
        }
    finally:
        conn.close()


def test_save_scan_result_updates_statistics_table(tmp_path, capsys):
    db_path = tmp_path / "tx.db"
    db = Database(str(db_path))

    assert db.save_scan_result(_result("ext-a")) is True

    assert "database is locked" not in capsys.readouterr().out

    stats = _stats_table(db_path)
    assert stats["total_scans"] == 1
    assert stats["total_vulnerabilities"] == 3
    assert stats["total_files_analyzed"] == 2


def test_statistics_table_counts_critical_as_high_risk(tmp_path):
    db_path = tmp_path / "tx.db"
    db = Database(str(db_path))

    db.save_scan_result(_result("ext-critical"))

    assert _stats_table(db_path)["high_risk_extensions"] == 1


def test_delete_and_clear_do_not_deadlock(tmp_path, capsys):
    db_path = tmp_path / "tx.db"
    db = Database(str(db_path))
    db.save_scan_result(_result("ext-a"))
    db.save_scan_result(_result("ext-b"))

    assert db.delete_scan_result("ext-a") is True
    assert db.clear_all_results() is True

    assert "database is locked" not in capsys.readouterr().out
    assert _stats_table(db_path)["total_scans"] == 0


def test_concurrent_writes_and_reads_do_not_lock(tmp_path, capsys):
    db = Database(str(tmp_path / "tx.db"))
    failures = []

    def writer(n):
        for i in range(5):
            try:
                if not db.save_scan_result(_result(f"ext-{n}-{i}")):
                    failures.append(f"writer {n} returned False")
            except Exception as exc:  # pylint: disable=broad-except
                failures.append(f"writer {n}: {exc}")

    def reader():
        for _ in range(15):
            try:
                db.get_statistics()
                db.get_scan_history(10)
            except Exception as exc:  # pylint: disable=broad-except
                failures.append(f"reader: {exc}")

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not failures
    assert "database is locked" not in capsys.readouterr().out
    assert _stats_table(tmp_path / "tx.db")["total_scans"] == 20
