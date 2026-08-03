/**
 * GPT-OSS Service for Frontend
 * Integrates with the ThreatXtension backend for AI-powered security analysis
 * Supports both local (MLX) and cloud (OpenAI) GPT-OSS deployment
 */

class GPTOSSService {
  constructor() {
    this.baseURL = "http://localhost:8007";
    this.endpoints = {
      analyze: "/api/analyze/file",
      upload: "/api/analyze/file/upload",
      health: "/health",
      providers: "/api/providers/status",
      config: "/api/config",
    };
  }

  async checkBackendHealth() {
    try {
      const response = await fetch(`${this.baseURL}/health`);
      if (!response.ok) {
        throw new Error(`Backend health check failed: ${response.status}`);
      }

      const health = await response.json();
      console.log("Backend health:", health);

      const providers = await this.getProviderStatus();
      console.log("Available providers:", providers);

      return {
        healthy: true,
        providers: providers,
        recommended: providers.recommended,
      };
    } catch (error) {
      console.error("Backend health check failed:", error);
      return {
        healthy: false,
        error: error.message,
      };
    }
  }

  async getProviderStatus() {
    try {
      const response = await fetch(`${this.baseURL}/api/providers/status`);
      if (!response.ok) {
        throw new Error(`Provider status check failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Provider status check failed:", error);
      return {
        providers: {},
        recommended: null,
      };
    }
  }

  async analyzeFileContent(fileContent, fileName, fileType, provider = "auto") {
    try {
      console.log(
        `Starting file analysis: ${fileName} (${fileType}) using ${provider}`,
      );

      const formData = new FormData();
      formData.append("file_content", fileContent);
      formData.append("file_name", fileName);
      formData.append("file_type", fileType);
      formData.append("provider", provider);

      const response = await fetch(`${this.baseURL}/api/analyze/file`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(
          errorData.detail || `Analysis failed: ${response.status}`,
        );
      }

      const result = await response.json();
      console.log("Analysis completed:", result);

      return {
        success: true,
        data: result.data,
        provider: result.data.provider || "unknown",
      };
    } catch (error) {
      console.error("File analysis failed:", error);
      return {
        success: false,
        error: error.message,
        provider: provider,
      };
    }
  }

  async uploadAndAnalyzeFile(file, provider = "auto") {
    try {
      console.log(
        `Uploading file for analysis: ${file.name} using ${provider}`,
      );

      const formData = new FormData();
      formData.append("file", file);
      formData.append("provider", provider);

      const response = await fetch(`${this.baseURL}/api/upload/file`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(
          errorData.detail || `Upload analysis failed: ${response.status}`,
        );
      }

      const result = await response.json();
      console.log("Upload analysis completed:", result);

      return {
        success: true,
        data: result.data,
        provider: result.data.provider || "unknown",
      };
    } catch (error) {
      console.error("Upload analysis failed:", error);
      return {
        success: false,
        error: error.message,
        provider: provider,
      };
    }
  }

  /**
   * Generate SAST signature (Semgrep rules) from file content using AI.
   * Errors are surfaced to the caller — we never fabricate a signature on
   * failure. Note the backend endpoint already degrades to a regex-based
   * fallback, so a successful response is always grounded in real analysis.
   */
  async generateSASTSignature(fileContent, fileName, provider = "auto") {
    const formData = new FormData();
    formData.append("file_content", fileContent);
    formData.append("file_name", fileName);
    formData.append("provider", provider);

    const response = await fetch(
      `${this.baseURL}/api/analyze/generate-sast-signature`,
      {
        method: "POST",
        body: formData,
      },
    );

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(
        errorData.detail ||
          `SAST signature generation failed: ${response.status}`,
      );
    }

    const result = await response.json();
    return {
      success: true,
      data: result.data,
      provider: result.data?.provider || "unknown",
    };
  }

  async getBackendConfig() {
    try {
      const response = await fetch(`${this.baseURL}/api/config`);
      if (!response.ok) {
        throw new Error(`Config check failed: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Config check failed:", error);
      return null;
    }
  }

  simulateAnalysis(fileContent, fileName, fileType) {
    console.log("Simulating GPT-OSS analysis...");

    return new Promise((resolve) => {
      setTimeout(() => {
        const analysis = this._generateMockAnalysis(
          fileContent,
          fileName,
          fileType,
        );
        resolve({
          success: true,
          data: analysis,
          provider: "simulated-gpt-oss",
        });
      }, 2000);
    });
  }

  _generateMockAnalysis(fileContent, fileName, fileType) {
    const riskScore = this._calculateMockRiskScore(fileContent);
    const severity = this._getSeverityFromScore(riskScore);

    return {
      file: fileName,
      fileType: fileType,
      provider: "simulated-gpt-oss-20b",
      timestamp: new Date().toISOString(),
      analysis: this._generateMockAnalysisText(
        fileContent,
        fileName,
        fileType,
        riskScore,
      ),
      riskScore: riskScore,
      severity: severity,
      findings: this._generateMockFindings(fileContent, severity),
      confidence: "High",
      recommendations: this._generateMockRecommendations(severity),
      metadata: {
        model: "GPT-OSS-20B (Simulated)",
        deployment: "Development Mode",
        tokens_used: Math.floor(Math.random() * 500) + 200,
        analysis_duration: "~2 seconds (simulated)",
        memory_usage: "~8-16GB RAM (simulated)",
      },
    };
  }

  _calculateMockRiskScore(content) {
    let score = 3; // Base score

    const riskIndicators = {
      "eval(": 3,
      innerHTML: 2,
      "document.write": 2,
      setTimeout: 1,
      setInterval: 1,
      "fetch(": 1,
      XMLHttpRequest: 1,
      localStorage: 1,
      sessionStorage: 1,
      cookie: 1,
    };

    for (const [indicator, points] of Object.entries(riskIndicators)) {
      if (content.includes(indicator)) {
        score += points;
      }
    }

    return Math.min(10, Math.max(1, score));
  }

  _getSeverityFromScore(score) {
    if (score >= 8) return "High";
    if (score >= 5) return "Medium";
    return "Low";
  }

  _generateMockFindings(content, severity) {
    const findings = [];

    if (severity === "High") {
      findings.push("Potential XSS vulnerability through innerHTML assignment");
      findings.push("Use of eval() function detected - high security risk");
      findings.push("Suspicious network communication patterns");
    } else if (severity === "Medium") {
      findings.push("DOM manipulation without proper sanitization");
      findings.push("Potential data exfiltration through localStorage");
    } else {
      findings.push("Code appears to follow security best practices");
    }

    return findings;
  }

  _generateMockRecommendations(severity) {
    if (severity === "High") {
      return [
        "Immediate code review required",
        "Remove eval() usage and implement safe alternatives",
        "Implement proper input sanitization",
        "Add Content Security Policy headers",
      ];
    } else if (severity === "Medium") {
      return [
        "Review DOM manipulation patterns",
        "Implement input validation",
        "Consider security audit",
      ];
    } else {
      return [
        "Continue monitoring for security issues",
        "Maintain current security practices",
      ];
    }
  }

  _generateMockAnalysisText(content, fileName, fileType, riskScore) {
    return `## Security Analysis Report for ${fileName}

**File Type:** ${fileType}
**Risk Score:** ${riskScore}/10
**Overall Assessment:** ${this._getSeverityFromScore(riskScore)} Risk

### Key Findings:
${this._generateMockFindings(content, this._getSeverityFromScore(riskScore))
  .map((f) => `- ${f}`)
  .join("\n")}

### Recommendations:
${this._generateMockRecommendations(this._getSeverityFromScore(riskScore))
  .map((r) => `- ${r}`)
  .join("\n")}

### Analysis Details:
This ${fileType} file has been analyzed using simulated GPT-OSS-20B analysis. The model identified several security considerations that should be addressed to improve the overall security posture of this extension.

**Note:** This is a simulated analysis for development purposes. In production, this would use the actual local GPT-OSS-20B model running on your Mac via MLX.`;
  }
}

export default new GPTOSSService();
