class RealScanService {
  constructor() {
    this.baseURL = "http://localhost:8007";
  }

  // Extract extension ID from Chrome Web Store URL
  extractExtensionId(url) {
    const match = url.match(/\/detail\/[^\/]+\/([a-z]{32})/);
    return match ? match[1] : null;
  }

  // Trigger a scan for an extension URL
  async triggerScan(url) {
    try {
      const response = await fetch(`${this.baseURL}/api/scan/trigger`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      if (response.ok) {
        const result = await response.json();
        return result;
      } else {
        throw new Error("Failed to trigger scan");
      }
    } catch (error) {
      console.error("Failed to trigger scan:", error);
      throw error;
    }
  }

  // Get real scan results from CLI analysis
  async getRealScanResults(extensionId) {
    try {
      // Try to read the analysis file that CLI creates
      const response = await fetch(
        `${this.baseURL}/api/scan/results/${extensionId}`,
      );

      if (response.ok) {
        const results = await response.json();
        return this.formatRealResults(results);
      } else {
        throw new Error("No scan results found.");
      }
    } catch (error) {
      console.error("Failed to get real scan results:", error);
      throw error;
    }
  }

  // Check scan status
  async checkScanStatus(extensionId) {
    try {
      const response = await fetch(
        `${this.baseURL}/api/scan/status/${extensionId}`,
      );
      if (response.ok) {
        return await response.json();
      }
      return { scanned: false };
    } catch (error) {
      console.error("Failed to check scan status:", error);
      return { scanned: false };
    }
  }

  // Format real CLI results for web display
  formatRealResults(cliResults) {
    try {
      // Extract the main analysis results
      const sastResults = cliResults.sast_results || {};

      return {
        // Map CLI fields to frontend fields
        securityScore:
          cliResults.overall_security_score ||
          sastResults.overall_security_score ||
          0,
        riskLevel: this.determineRiskLevel(
          cliResults.overall_security_score ||
            sastResults.overall_security_score ||
            0,
        ),
        totalFiles: cliResults.extracted_files?.length || 0,
        totalFindings:
          cliResults.total_findings || sastResults.total_findings || 0,

        // Files information
        files: this.formatFileResults(cliResults.extracted_files || []),

        // SAST results from CLI analysis
        sastResults: this.formatSASTResults(
          sastResults.javascript_analysis || [],
        ),

        // Additional CLI data
        extensionId: cliResults.extension_id,
        url: cliResults.url,
        downloadResult: cliResults.download_result,

        // Risk distribution
        riskDistribution:
          cliResults.risk_distribution || sastResults.risk_distribution || {},

        // Overall risk assessment
        overallRisk:
          cliResults.overall_risk || sastResults.overall_risk || "unknown",
        totalRiskScore:
          cliResults.total_risk_score || sastResults.total_risk_score || 0,
      };
    } catch (error) {
      console.error("Error formatting CLI results:", error);
      return {
        securityScore: 0,
        riskLevel: "UNKNOWN",
        totalFiles: 0,
        totalFindings: 0,
        files: [],
        sastResults: [],
        error: "Failed to format results",
      };
    }
  }

  // Calculate security score from CLI results
  calculateSecurityScore(analysis) {
    if (analysis.security_score !== undefined) {
      return analysis.security_score;
    }

    // Calculate based on findings
    const totalFindings = analysis.total_findings || 0;
    const highRiskFindings = analysis.high_risk_findings || 0;

    if (totalFindings === 0) return 100;

    let score = 100;
    score -= highRiskFindings * 20; // High risk findings heavily penalize score
    score -= totalFindings * 2; // Each finding reduces score

    return Math.max(0, Math.round(score));
  }

  // Determine risk level from CLI results
  determineRiskLevel(score) {
    if (score < 30) return "HIGH";
    if (score < 70) return "MEDIUM";
    return "LOW";
  }

  // Format file analysis results
  formatFileResults(files) {
    if (!Array.isArray(files)) {
      return [];
    }

    return files.map((file, index) => {
      // Extract just the filename for display
      const fileName = file.split("/").pop();

      return {
        name: fileName,
        path: file, // Keep full path for API calls
        fullPath: file, // Store full path separately
        size: "Unknown", // CLI doesn't provide file sizes
        type: this.getFileType(fileName),
        riskLevel: this.getFileRiskLevel(fileName),
        index: index,
      };
    });
  }

  // Get file type based on extension
  getFileType(filename) {
    if (filename.endsWith(".js")) return "JavaScript";
    if (filename.endsWith(".html")) return "HTML";
    if (filename.endsWith(".css")) return "CSS";
    if (filename.endsWith(".json")) return "JSON";
    if (filename.endsWith(".xml")) return "XML";
    if (
      filename.endsWith(".png") ||
      filename.endsWith(".jpg") ||
      filename.endsWith(".gif")
    )
      return "Image";
    if (filename.endsWith(".ttf") || filename.endsWith(".woff")) return "Font";
    return "Other";
  }

  // Get file risk level based on type and name
  getFileRiskLevel(filename) {
    if (
      filename.includes("background") ||
      filename.includes("content") ||
      filename.includes("inject")
    ) {
      return "HIGH";
    }
    if (filename.endsWith(".js") || filename.endsWith(".html")) {
      return "MEDIUM";
    }
    return "LOW";
  }

  // Format SAST results
  formatSASTResults(sastResults) {
    if (!Array.isArray(sastResults)) {
      return [];
    }

    return sastResults.map((finding) => ({
      file: finding.file || "Unknown",
      line: finding.line_number || finding.line || 0,
      title: finding.pattern_name || finding.title || "Security Finding",
      description: finding.description || "No description available",
      severity: this.mapRiskLevelToSeverity(
        finding.risk_level || finding.severity || "medium",
      ),
      riskScore: finding.risk_score || 0,
      context: finding.context || "",
      matchText: finding.match_text || "",
    }));
  }

  // Map CLI risk levels to frontend severity levels
  mapRiskLevelToSeverity(riskLevel) {
    const level = riskLevel.toLowerCase();
    if (level === "high" || level === "malicious") return "HIGH";
    if (level === "medium" || level === "suspicious") return "MEDIUM";
    if (level === "low" || level === "info") return "LOW";
    return "MEDIUM";
  }

  // Get file content from extracted files
  async getFileContent(extensionId, fileName) {
    try {
      const response = await fetch(
        `${this.baseURL}/api/scan/file/${extensionId}/${encodeURIComponent(fileName)}`,
      );

      if (response.ok) {
        const result = await response.json();
        return result.content || "File content not available";
      } else {
        throw new Error("Failed to fetch file content");
      }
    } catch (error) {
      console.error("Failed to get file content:", error);
      throw error;
    }
  }

  // Get file list from extracted directory
  async getFileList(extensionId) {
    try {
      const response = await fetch(
        `${this.baseURL}/api/scan/files/${extensionId}`,
      );

      if (response.ok) {
        const result = await response.json();
        return result.files || [];
      } else {
        throw new Error("Failed to fetch file list");
      }
    } catch (error) {
      console.error("Failed to get file list:", error);
      throw error;
    }
  }
}

export default new RealScanService();
