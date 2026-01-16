"""
SQLite Database Module for ThreatXtension

Handles persistent storage of scan results, statistics, and history.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import contextmanager


class Database:
    """SQLite database manager for ThreatXtension."""

    def __init__(self, db_path: str = "threatxtension.db"):
        """Initialize database connection."""
        self.db_path = Path(db_path)
        self.init_database()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_database(self):
        """Initialize database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Scan results table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    extension_id TEXT UNIQUE NOT NULL,
                    extension_name TEXT,
                    url TEXT,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    security_score INTEGER,
                    risk_level TEXT,
                    total_findings INTEGER DEFAULT 0,
                    total_files INTEGER DEFAULT 0,
                    high_risk_count INTEGER DEFAULT 0,
                    medium_risk_count INTEGER DEFAULT 0,
                    low_risk_count INTEGER DEFAULT 0,
                    metadata TEXT,
                    manifest TEXT,
                    permissions_analysis TEXT,
                    sast_results TEXT,
                    webstore_analysis TEXT,
                    summary TEXT,
                    extracted_path TEXT,
                    extracted_files TEXT,
                    error TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Statistics table for aggregated metrics
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT UNIQUE NOT NULL,
                    metric_value INTEGER DEFAULT 0,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Initialize default statistics
            cursor.execute(
                """
                INSERT OR IGNORE INTO statistics (metric_name, metric_value)
                VALUES 
                    ('total_scans', 0),
                    ('high_risk_extensions', 0),
                    ('total_files_analyzed', 0),
                    ('total_vulnerabilities', 0)
            """
            )

            # Create indexes for better query performance
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_extension_id 
                ON scan_results(extension_id)
            """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON scan_results(timestamp DESC)
            """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_risk_level 
                ON scan_results(risk_level)
            """
            )

    def save_scan_result(self, result: Dict[str, Any]) -> bool:
        """Save or update scan result."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Extract metadata
                extension_id = result.get("extension_id")
                metadata = result.get("metadata", {}) or {}
                # Get extension_name from top-level first, then try metadata fields
                extension_name = (
                    result.get("extension_name")
                    or metadata.get("title")
                    or metadata.get("name")
                    or extension_id
                )

                # Calculate risk distribution
                risk_dist = result.get("risk_distribution", {})

                cursor.execute(
                    """
                    INSERT OR REPLACE INTO scan_results (
                        extension_id, extension_name, url, timestamp, status,
                        security_score, risk_level, total_findings, total_files,
                        high_risk_count, medium_risk_count, low_risk_count,
                        metadata, manifest, permissions_analysis, sast_results,
                        webstore_analysis, summary, extracted_path, extracted_files,
                        error, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        extension_id,
                        extension_name,
                        result.get("url"),
                        result.get("timestamp"),
                        result.get("status"),
                        result.get("overall_security_score"),
                        result.get("overall_risk"),
                        result.get("total_findings", 0),
                        len(result.get("extracted_files") or []),
                        risk_dist.get("high", 0),
                        risk_dist.get("medium", 0),
                        risk_dist.get("low", 0),
                        json.dumps(result.get("metadata", {})),
                        json.dumps(result.get("manifest", {})),
                        json.dumps(result.get("permissions_analysis", {})),
                        json.dumps(result.get("sast_results", {})),
                        json.dumps(result.get("webstore_analysis", {})),
                        json.dumps(result.get("summary", {})),
                        result.get("extracted_path"),
                        json.dumps(result.get("extracted_files", [])),
                        result.get("error"),
                        datetime.now().isoformat(),
                    ),
                )

                # Update statistics
                self._update_statistics()

                return True
        except Exception as e:
            print(f"Error saving scan result: {e}")
            return False

    def get_scan_result(self, extension_id: str) -> Optional[Dict[str, Any]]:
        """Get scan result by extension ID."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM scan_results WHERE extension_id = ?
                """,
                    (extension_id,),
                )

                row = cursor.fetchone()
                if not row:
                    return None

                return self._row_to_dict(row)
        except Exception as e:
            print(f"Error getting scan result: {e}")
            return None

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get scan history ordered by most recent."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT 
                        extension_id, extension_name, url, timestamp, status,
                        security_score, risk_level, total_findings, total_files,
                        high_risk_count, medium_risk_count, low_risk_count
                    FROM scan_results
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (limit,),
                )

                rows = cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Error getting scan history: {e}")
            return []

    def get_statistics(self) -> Dict[str, int]:
        """Get aggregated statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Get basic stats from statistics table
                cursor.execute("SELECT metric_name, metric_value FROM statistics")
                stats = {row["metric_name"]: row["metric_value"] for row in cursor.fetchall()}

                # Get additional computed stats
                cursor.execute(
                    """
                    SELECT 
                        COUNT(*) as total_scans,
                        SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk,
                        SUM(total_files) as total_files,
                        SUM(total_findings) as total_findings,
                        AVG(security_score) as avg_security_score
                    FROM scan_results
                    WHERE status = 'completed'
                """
                )

                row = cursor.fetchone()
                if row:
                    stats.update(
                        {
                            "total_scans": row["total_scans"] or 0,
                            "high_risk_extensions": row["high_risk"] or 0,
                            "total_files_analyzed": row["total_files"] or 0,
                            "total_vulnerabilities": row["total_findings"] or 0,
                            "avg_security_score": int(row["avg_security_score"] or 0),
                        }
                    )

                return stats
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {
                "total_scans": 0,
                "high_risk_extensions": 0,
                "total_files_analyzed": 0,
                "total_vulnerabilities": 0,
                "avg_security_score": 0,
            }

    def get_risk_distribution(self) -> Dict[str, int]:
        """Get distribution of risk levels."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT 
                        risk_level,
                        COUNT(*) as count
                    FROM scan_results
                    WHERE status = 'completed'
                    GROUP BY risk_level
                """
                )

                distribution = {"high": 0, "medium": 0, "low": 0}
                for row in cursor.fetchall():
                    risk_level = row["risk_level"]
                    if risk_level in distribution:
                        distribution[risk_level] = row["count"]

                return distribution
        except Exception as e:
            print(f"Error getting risk distribution: {e}")
            return {"high": 0, "medium": 0, "low": 0}

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scans with summary info."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT 
                        extension_id, extension_name, timestamp,
                        security_score, risk_level, total_findings
                    FROM scan_results
                    WHERE status = 'completed'
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (limit,),
                )

                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Error getting recent scans: {e}")
            return []

    def delete_scan_result(self, extension_id: str) -> bool:
        """Delete a scan result."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM scan_results WHERE extension_id = ?
                """,
                    (extension_id,),
                )

                self._update_statistics()
                return True
        except Exception as e:
            print(f"Error deleting scan result: {e}")
            return False

    def clear_all_results(self) -> bool:
        """Clear all scan results."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_results")
                self._update_statistics()
                return True
        except Exception as e:
            print(f"Error clearing results: {e}")
            return False

    def _update_statistics(self):
        """Update aggregated statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Update total scans
                cursor.execute(
                    """
                    UPDATE statistics 
                    SET metric_value = (
                        SELECT COUNT(*) FROM scan_results WHERE status = 'completed'
                    ),
                        updated_at = ?
                    WHERE metric_name = 'total_scans'
                """,
                    (datetime.now().isoformat(),),
                )

                # Update high risk count
                cursor.execute(
                    """
                    UPDATE statistics 
                    SET metric_value = (
                        SELECT COUNT(*) FROM scan_results 
                        WHERE status = 'completed' AND risk_level = 'high'
                    ),
                    updated_at = ?
                    WHERE metric_name = 'high_risk_extensions'
                """,
                    (datetime.now().isoformat(),),
                )

                # Update total files
                cursor.execute(
                    """
                    UPDATE statistics 
                    SET metric_value = (
                        SELECT COALESCE(SUM(total_files), 0) FROM scan_results 
                        WHERE status = 'completed'
                    ),
                    updated_at = ?
                    WHERE metric_name = 'total_files_analyzed'
                """,
                    (datetime.now().isoformat(),),
                )

                # Update total vulnerabilities
                cursor.execute(
                    """
                    UPDATE statistics 
                    SET metric_value = (
                        SELECT COALESCE(SUM(total_findings), 0) FROM scan_results 
                        WHERE status = 'completed'
                    ),
                    updated_at = ?
                    WHERE metric_name = 'total_vulnerabilities'
                """,
                    (datetime.now().isoformat(),),
                )

        except Exception as e:
            print(f"Error updating statistics: {e}")

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert database row to dictionary with JSON parsing."""
        result = dict(row)

        # Parse JSON fields
        json_fields = [
            "metadata",
            "manifest",
            "permissions_analysis",
            "sast_results",
            "webstore_analysis",
            "summary",
            "extracted_files",
        ]

        for field in json_fields:
            if result.get(field):
                try:
                    result[field] = json.loads(result[field])
                except json.JSONDecodeError:
                    result[field] = {}

        return result


# Global database instance
db = Database()
