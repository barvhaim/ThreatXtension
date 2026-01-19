/**
 * Database Service
 *
 * Handles communication with the backend API for persistent storage
 * using SQLite database instead of localStorage.
 */

class DatabaseService {
  constructor() {
    // Use environment variable for API URL, default to empty string for same-origin (production)
    // For local development, set VITE_API_URL=http://localhost:8007 in .env.local
    this.baseURL = import.meta.env.VITE_API_URL || "";
    this.API_BASE_URL = `${this.baseURL}/api`;
  }
  /**
   * Get statistics from the database
   */
  async getStatistics() {
    try {
      const response = await fetch(`${this.API_BASE_URL}/statistics`);
      if (!response.ok) {
        throw new Error("Failed to fetch statistics");
      }
      return await response.json();
    } catch (error) {
      console.error("Error fetching statistics:", error);
      return {
        total_scans: 0,
        high_risk_extensions: 0,
        total_files_analyzed: 0,
        total_vulnerabilities: 0,
        avg_security_score: 0,
        risk_distribution: { high: 0, medium: 0, low: 0 }
      };
    }
  }

  /**
   * Get scan history from the database
   */
  async getScanHistory(limit = 50) {
    try {
      const response = await fetch(`${this.API_BASE_URL}/history?limit=${limit}`);
      if (!response.ok) {
        throw new Error("Failed to fetch scan history");
      }
      const data = await response.json();
      return data.history || [];
    } catch (error) {
      console.error("Error fetching scan history:", error);
      return [];
    }
  }

  /**
   * Get recent scans from the database
   */
  async getRecentScans(limit = 10) {
    try {
      const response = await fetch(`${this.API_BASE_URL}/recent?limit=${limit}`);
      if (!response.ok) {
        throw new Error("Failed to fetch recent scans");
      }
      const data = await response.json();
      return data.recent || [];
    } catch (error) {
      console.error("Error fetching recent scans:", error);
      return [];
    }
  }

  /**
   * Get scan result by extension ID
   */
  async getScanResult(extensionId) {
    try {
      const response = await fetch(`${this.API_BASE_URL}/scan/results/${extensionId}`);
      if (!response.ok) {
        if (response.status === 404) {
          return null;
        }
        throw new Error("Failed to fetch scan result");
      }
      return await response.json();
    } catch (error) {
      console.error("Error fetching scan result:", error);
      return null;
    }
  }

  /**
   * Delete a scan result
   */
  async deleteScanResult(extensionId) {
    try {
      const response = await fetch(`${this.API_BASE_URL}/scan/${extensionId}`, {
        method: "DELETE"
      });
      if (!response.ok) {
        throw new Error("Failed to delete scan result");
      }
      return true;
    } catch (error) {
      console.error("Error deleting scan result:", error);
      return false;
    }
  }

  /**
   * Clear all scan results
   */
  async clearAllResults() {
    try {
      const response = await fetch(`${this.API_BASE_URL}/clear`, {
        method: "POST"
      });
      if (!response.ok) {
        throw new Error("Failed to clear all results");
      }
      return true;
    } catch (error) {
      console.error("Error clearing all results:", error);
      return false;
    }
  }

  /**
   * Check if a scan result exists in the database
   */
  async hasScanResult(extensionId) {
    const result = await this.getScanResult(extensionId);
    return result !== null;
  }

  /**
   * Get scan statistics for a specific extension
   */
  async getExtensionStats(extensionId) {
    const result = await this.getScanResult(extensionId);
    if (!result) return null;

    return {
      extensionId: result.extension_id,
      extensionName: result.extension_name,
      timestamp: result.timestamp,
      securityScore: result.security_score,
      riskLevel: result.risk_level,
      totalFindings: result.total_findings,
      totalFiles: result.total_files,
      highRiskCount: result.high_risk_count,
      mediumRiskCount: result.medium_risk_count,
      lowRiskCount: result.low_risk_count
    };
  }

  /**
   * Get URLs from recent scans for autocomplete
   */
  async getRecentUrls(limit = 5) {
    const history = await this.getScanHistory(limit);
    return history
      .map(item => item.url)
      .filter(url => url && url.trim() !== "");
  }

  /**
   * Get risk distribution across all scans
   */
  async getRiskDistribution() {
    const stats = await this.getStatistics();
    return stats.risk_distribution || { high: 0, medium: 0, low: 0 };
  }

  /**
   * Get aggregated metrics for dashboard widgets
   */
  async getDashboardMetrics() {
    const stats = await this.getStatistics();
    const history = await this.getScanHistory(20);

    // Get last 7 scans for sparkline (most recent first, then reverse for chronological order)
    const recentScans = history.slice(0, 7).reverse();
    
    // If no scans, return zeros
    if (recentScans.length === 0) {
      return {
        totalScans: { value: 0, sparkline: [0] },
        highRisk: { value: 0, sparkline: [0] },
        totalFiles: { value: 0, sparkline: [0] },
        totalVulnerabilities: { value: 0, sparkline: [0] },
        avgSecurityScore: 0,
        riskDistribution: { high: 0, medium: 0, low: 0 }
      };
    }

    // Calculate actual data points (not cumulative) for sparklines
    const scanCountSparkline = recentScans.map((_, idx) => idx + 1);
    
    // High risk count at each point in time (cumulative makes sense here)
    const highRiskSparkline = [];
    let highRiskRunning = 0;
    recentScans.forEach(scan => {
      if ((scan.risk_level || "").toLowerCase() === "high") {
        highRiskRunning++;
      }
      highRiskSparkline.push(highRiskRunning);
    });
    
    // Files per scan (actual values, not cumulative)
    const filesSparkline = recentScans.map(scan => scan.total_files || 0);
    
    // Findings per scan (actual values, not cumulative)
    const findingsSparkline = recentScans.map(scan => scan.total_findings || 0);

    return {
      totalScans: {
        value: stats.total_scans || 0,
        sparkline: scanCountSparkline
      },
      highRisk: {
        value: stats.high_risk_extensions || 0,
        sparkline: highRiskSparkline.length > 0 ? highRiskSparkline : [0]
      },
      totalFiles: {
        value: stats.total_files_analyzed || 0,
        sparkline: filesSparkline.length > 0 ? filesSparkline : [0]
      },
      totalVulnerabilities: {
        value: stats.total_vulnerabilities || 0,
        sparkline: findingsSparkline.length > 0 ? findingsSparkline : [0]
      },
      avgSecurityScore: stats.avg_security_score || 0,
      riskDistribution: stats.risk_distribution || { high: 0, medium: 0, low: 0 }
    };
  }
}

export default new DatabaseService();
