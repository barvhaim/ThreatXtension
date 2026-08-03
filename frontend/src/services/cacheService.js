class CacheService {
  constructor() {
    this.cacheKey = "threatxtension_scan_cache";
    this.maxCacheAge = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  }

  cacheScanResult(extensionId, scanData) {
    try {
      const cache = this.getCache();
      cache[extensionId] = {
        data: scanData,
        extensionId: extensionId,
        extensionName: scanData.extensionName || extensionId,
        timestamp: Date.now(),
        scanCount: (cache[extensionId]?.scanCount || 0) + 1,
        securityScore: scanData.securityScore || 0,
        riskLevel: scanData.riskLevel || "UNKNOWN",
        totalFiles: scanData.totalFiles || 0,
        totalFindings: scanData.totalFindings || 0,
      };
      localStorage.setItem(this.cacheKey, JSON.stringify(cache));
      return true;
    } catch (error) {
      console.error("Failed to cache scan result:", error);
      return false;
    }
  }

  getCachedResult(extensionId) {
    try {
      const cache = this.getCache();
      const cached = cache[extensionId];

      if (!cached) return null;

      const age = Date.now() - cached.timestamp;
      if (age > this.maxCacheAge) {
        this.removeCachedResult(extensionId);
        return null;
      }

      return cached;
    } catch (error) {
      console.error("Failed to get cached result:", error);
      return null;
    }
  }

  hasRecentScan(extensionId) {
    const cached = this.getCachedResult(extensionId);
    if (!cached) return false;

    const age = Date.now() - cached.timestamp;
    return age <= this.maxCacheAge;
  }

  removeCachedResult(extensionId) {
    try {
      const cache = this.getCache();
      delete cache[extensionId];
      localStorage.setItem(this.cacheKey, JSON.stringify(cache));
      return true;
    } catch (error) {
      console.error("Failed to remove cached result:", error);
      return false;
    }
  }

  clearCache() {
    try {
      localStorage.removeItem(this.cacheKey);
      return true;
    } catch (error) {
      console.error("Failed to clear cache:", error);
      return false;
    }
  }

  getScanHistory() {
    try {
      const cache = this.getCache();
      const entries = Object.values(cache);

      return entries
        .sort((a, b) => b.timestamp - a.timestamp)
        .map((entry) => ({
          extensionId: entry.extensionId,
          extensionName: entry.extensionName,
          timestamp: entry.timestamp,
          scanCount: entry.scanCount,
          securityScore: entry.securityScore,
          riskLevel: entry.riskLevel,
          totalFiles: entry.totalFiles,
          totalFindings: entry.totalFindings,
        }));
    } catch (error) {
      console.error("Failed to get scan history:", error);
      return [];
    }
  }

  getCacheStats() {
    try {
      const cache = this.getCache();
      const keys = Object.keys(cache);
      const totalSize = JSON.stringify(cache).length;

      return {
        totalEntries: keys.length,
        totalSize: totalSize,
        entries: keys.map((key) => ({
          extensionId: key,
          timestamp: cache[key].timestamp,
          age: Date.now() - cache[key].timestamp,
          scanCount: cache[key].scanCount,
        })),
      };
    } catch (error) {
      console.error("Failed to get cache stats:", error);
      return { totalEntries: 0, totalSize: 0, entries: [] };
    }
  }

  getCache() {
    try {
      const cached = localStorage.getItem(this.cacheKey);
      return cached ? JSON.parse(cached) : {};
    } catch (error) {
      console.error("Failed to parse cache:", error);
      return {};
    }
  }
}

export default new CacheService();
