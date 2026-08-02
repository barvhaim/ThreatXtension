"""Regression tests for the stored risk-score direction migration."""

import sqlite3

from threatxtension.api.database import Database


def _insert_legacy_row(db_path, extension_id, score, risk_level):
    """Write a row the way the pre-inversion build did (score = how safe)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO scan_results
                (extension_id, timestamp, status, security_score, risk_level)
            VALUES (?, '2026-01-01T00:00:00', 'completed', ?, ?)
            """,
            (extension_id, score, risk_level),
        )
        conn.commit()
    finally:
        conn.close()


def _read_row(db_path, extension_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT security_score, risk_level FROM scan_results WHERE extension_id = ?",
            (extension_id,),
        ).fetchone()
        return row["security_score"], row["risk_level"]
    finally:
        conn.close()


def _schema_version(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT value FROM schema_meta WHERE key='version'").fetchone()[0]
    finally:
        conn.close()


def _drop_version_marker(db_path):
    """Simulate a database written before schema versioning existed."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DROP TABLE IF EXISTS schema_meta")
        conn.commit()
    finally:
        conn.close()


def test_legacy_rows_are_flipped_to_risk_direction(tmp_path):
    """A malicious extension stored as a low 'safety' score must become a high risk score."""

    db_path = str(tmp_path / "legacy.db")
    Database(db_path)
    _insert_legacy_row(db_path, "a" * 32, 10, "high")
    _drop_version_marker(db_path)

    Database(db_path)

    score, risk_level = _read_row(db_path, "a" * 32)
    assert score == 90
    assert risk_level == "critical"


def test_legacy_clean_extension_becomes_low_risk(tmp_path):
    """A genuinely clean extension stored as 100 must become 0 and read as low risk."""

    db_path = str(tmp_path / "clean.db")
    Database(db_path)
    _insert_legacy_row(db_path, "b" * 32, 100, "low")
    _drop_version_marker(db_path)

    Database(db_path)

    assert _read_row(db_path, "b" * 32) == (0, "low")


def test_migration_is_idempotent(tmp_path):
    """Re-opening a migrated database must not flip the scores back."""

    db_path = str(tmp_path / "idempotent.db")
    Database(db_path)
    _insert_legacy_row(db_path, "c" * 32, 10, "high")
    _drop_version_marker(db_path)

    Database(db_path)
    Database(db_path)
    Database(db_path)

    assert _read_row(db_path, "c" * 32) == (90, "critical")
    assert _schema_version(db_path) == Database.SCHEMA_VERSION


def test_fresh_database_is_stamped_without_flipping(tmp_path):
    """A new database is already in the risk direction, so rows must be left alone."""

    db_path = str(tmp_path / "fresh.db")
    Database(db_path)
    assert _schema_version(db_path) == Database.SCHEMA_VERSION

    # Written by the current build: 90 already means "dangerous".
    _insert_legacy_row(db_path, "d" * 32, 90, "critical")
    Database(db_path)

    assert _read_row(db_path, "d" * 32) == (90, "critical")


def test_statistics_high_risk_count_includes_critical(tmp_path):
    """`critical` rows must not vanish from the high-risk dashboard stat."""

    db_path = str(tmp_path / "stats.db")
    db = Database(db_path)
    _insert_legacy_row(db_path, "e" * 32, 90, "critical")
    _insert_legacy_row(db_path, "f" * 32, 40, "high")
    _insert_legacy_row(db_path, "g" * 32, 5, "low")

    assert db.get_statistics()["high_risk_extensions"] == 2
