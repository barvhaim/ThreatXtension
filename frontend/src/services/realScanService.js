class RealScanService {
  constructor() {
    // Use environment variable for API URL, default to empty string for same-origin (production)
    // For local development, set VITE_API_URL=http://localhost:8007 in .env.local
    this.baseURL = import.meta.env.VITE_API_URL || "";
  }

  extractExtensionId(url) {
    const match = url.match(/\/detail\/(?:[^/]+\/)?([a-z]{32})/);
    return match ? match[1] : null;
  }

  async triggerScan(url, force = false) {
    try {
      const response = await fetch(`${this.baseURL}/api/scan/trigger`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url, force }),
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

  async uploadAndScan(file) {
    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${this.baseURL}/api/scan/upload`, {
        method: "POST",
        body: formData,
      });

      if (response.ok) {
        const result = await response.json();
        return result;
      } else {
        const error = await response.json();
        throw new Error(error.detail || "Failed to upload file");
      }
    } catch (error) {
      console.error("Failed to upload file:", error);
      throw error;
    }
  }

  async getRealScanResults(extensionId) {
    try {
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
      if (
        error.message.includes("fetch") ||
        error.message.includes("network")
      ) {
        throw new Error(
          "Backend server unavailable. Please make sure the API server is running (make api).",
        );
      }
      return { scanned: false, status: "error", error: error.message };
    }
  }

  formatRealResults(cliResults) {
    try {
      const sastResults = cliResults.sast_results || {};

      const sastFindings = [];
      if (sastResults.sast_findings) {
        for (const [filePath, findings] of Object.entries(
          sastResults.sast_findings,
        )) {
          if (Array.isArray(findings)) {
            findings.forEach((finding) => {
              sastFindings.push({
                ...finding,
                file: finding.file || filePath,
              });
            });
          }
        }
      }

      return {
        securityScore:
          cliResults.overall_security_score ||
          sastResults.overall_security_score ||
          0,
        riskLevel: (
          cliResults.summary?.overall_risk_level ||
          cliResults.overall_risk ||
          this.determineRiskLevel(
            cliResults.overall_security_score ||
              sastResults.overall_security_score ||
              0,
          )
        ).toUpperCase(),
        totalFiles: cliResults.extracted_files?.length || 0,
        totalFindings: cliResults.total_findings || sastFindings.length || 0,

        files: this.formatFileResults(cliResults.extracted_files || []),

        sastResults: this.formatSASTResults(sastFindings),

        extensionId: cliResults.extension_id,
        url: cliResults.url,
        downloadResult: cliResults.download_result,

        name:
          cliResults.metadata?.title ||
          cliResults.manifest?.name ||
          "Unknown Extension",
        description:
          cliResults.metadata?.description ||
          cliResults.manifest?.description ||
          "",
        version:
          cliResults.metadata?.version ||
          cliResults.manifest?.version ||
          "0.0.0",
        developer:
          cliResults.metadata?.developer_name ||
          cliResults.manifest?.author ||
          "Unknown",
        lastUpdated: cliResults.metadata?.last_updated || "Unknown",

        permissions: this.formatPermissions(
          cliResults.permissions_analysis || {},
        ),

        recommendations: this.formatRecommendations(cliResults.summary || {}),

        executiveSummary: cliResults.summary?.summary || "No summary available",

        riskDistribution:
          cliResults.risk_distribution || sastResults.risk_distribution || {},

        overallRisk:
          cliResults.overall_risk || sastResults.overall_risk || "unknown",
        totalRiskScore:
          cliResults.total_risk_score || sastResults.total_risk_score || 0,

        virustotalAnalysis: cliResults.virustotal_analysis || null,

        entropyAnalysis: cliResults.entropy_analysis || null,

        chromeStatsMetadata: cliResults.chromeStatsMetadata || null,
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

  // Calculate a fallback risk score from CLI results. Higher means more dangerous.
  calculateSecurityScore(analysis) {
    if (analysis.security_score !== undefined) {
      return analysis.security_score;
    }

    const totalFindings = analysis.total_findings || 0;
    const highRiskFindings = analysis.high_risk_findings || 0;
    const score = highRiskFindings * 20 + totalFindings * 2;

    return Math.min(100, Math.round(score));
  }

  // Determine risk level from score (fallback only — prefer backend-computed value).
  // Higher scores mean greater risk.
  determineRiskLevel(score) {
    if (score >= 61) return "CRITICAL";
    if (score >= 36) return "HIGH";
    if (score >= 16) return "MEDIUM";
    return "LOW";
  }

  formatFileResults(files) {
    if (!Array.isArray(files)) {
      return [];
    }

    return files.map((file, index) => {
      const fileName = file.split("/").pop();

      return {
        name: fileName,
        path: file,
        fullPath: file,
        size: "Unknown",
        type: this.getFileType(fileName),
        riskLevel: this.getFileRiskLevel(fileName),
        index: index,
      };
    });
  }

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

  formatSASTResults(sastResults) {
    if (!Array.isArray(sastResults)) {
      return [];
    }

    return sastResults.map((finding) => {
      const extra = finding.extra || {};
      const start = finding.start || {};
      const metadata = extra.metadata || {};

      const lineNumber = start.line || finding.line_number || finding.line || 0;

      return {
        file: finding.file || finding.path || "Unknown",
        line: lineNumber,
        line_number: lineNumber,
        title:
          finding.check_id ||
          finding.pattern_name ||
          finding.title ||
          "Security Finding",
        description:
          extra.message || finding.description || "No description available",
        message: extra.message || finding.message || finding.description,
        severity: this.mapRiskLevelToSeverity(
          extra.severity || finding.risk_level || finding.severity || "medium",
        ),
        riskScore: finding.risk_score || 0,
        context: finding.context || extra.lines || "",
        matched_text:
          finding.matched_text || finding.match_text || extra.lines || "",
        check_id: finding.check_id,
        pattern_name: finding.pattern_name || finding.check_id,
        checkId: finding.check_id,
        category: metadata.category,
        mitre: metadata.mitre,
        cwe: metadata.cwe,
        owasp: metadata.owasp,
        extra: {
          ...extra,
          metadata: metadata,
        },
      };
    });
  }

  mapRiskLevelToSeverity(riskLevel) {
    const level = riskLevel.toLowerCase();
    if (level === "high" || level === "malicious") return "HIGH";
    if (level === "medium" || level === "suspicious") return "MEDIUM";
    if (level === "low" || level === "info") return "LOW";
    return "MEDIUM";
  }

  async getFileContent(extensionId, filePath) {
    try {
      // Encode each path segment separately to preserve forward slashes
      const encodedPath = filePath
        .split("/")
        .map((segment) => encodeURIComponent(segment))
        .join("/");

      const response = await fetch(
        `${this.baseURL}/api/scan/file/${extensionId}/${encodedPath}`,
      );

      if (response.ok) {
        const result = await response.json();
        return result.content || "File content not available";
      } else {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || "Failed to fetch file content");
      }
    } catch (error) {
      console.error("Failed to get file content:", error);
      throw error;
    }
  }

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

  formatPermissions(permissionsAnalysis) {
    if (!permissionsAnalysis || !permissionsAnalysis.permissions_details) {
      return [];
    }

    const details = permissionsAnalysis.permissions_details;
    return Object.keys(details).map((name) => {
      const info = details[name];
      return {
        name: name,
        description: info.justification_reasoning || "No details available",
        risk: info.is_reasonable ? "LOW" : "HIGH",
      };
    });
  }

  formatRecommendations(summary) {
    if (!summary || !summary.recommendations) {
      return [];
    }

    return summary.recommendations.map((rec) => ({
      title: rec,
      priority: "MEDIUM",
      description: "",
    }));
  }
}

export default new RealScanService();
