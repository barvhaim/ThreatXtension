import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Loader2, Copy, AlertTriangle, Code2 } from "lucide-react";

const FindingDetailsModal = ({
  isOpen,
  onClose,
  finding,
  extensionId,
  onGetFileContent,
}) => {
  const [fileContent, setFileContent] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [isPrettified, setIsPrettified] = useState(false);

  useEffect(() => {
    if (isOpen && finding && extensionId) {
      loadFileContent();
    }
  }, [isOpen, finding, extensionId]);

  const loadFileContent = async () => {
    if (!finding || !extensionId) {
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const content = await onGetFileContent(extensionId, finding.file);
      setFileContent(content);
    } catch (err) {
      setError(err.message || "Failed to load file content");
    } finally {
      setIsLoading(false);
    }
  };

  // Prettify JavaScript code
  const prettifyCode = (code) => {
    try {
      // Simple JavaScript beautifier
      let formatted = code;
      let indent = 0;
      const indentStr = '  ';
      const lines = [];
      let currentLine = '';
      
      for (let i = 0; i < code.length; i++) {
        const char = code[i];
        const nextChar = code[i + 1];
        
        currentLine += char;
        
        // Handle opening braces
        if (char === '{' || char === '[') {
          indent++;
          if (nextChar && nextChar !== '}' && nextChar !== ']') {
            lines.push(currentLine.trim());
            currentLine = indentStr.repeat(indent);
          }
        }
        // Handle closing braces
        else if (char === '}' || char === ']') {
          indent = Math.max(0, indent - 1);
          if (currentLine.trim() !== char) {
            lines.push(currentLine.slice(0, -1).trim());
            currentLine = indentStr.repeat(indent) + char;
          }
          if (nextChar && nextChar !== ';' && nextChar !== ',' && nextChar !== ')' && nextChar !== '}' && nextChar !== ']') {
            lines.push(currentLine.trim());
            currentLine = indentStr.repeat(indent);
          }
        }
        // Handle semicolons
        else if (char === ';') {
          if (nextChar && nextChar !== '}' && nextChar !== ')') {
            lines.push(currentLine.trim());
            currentLine = indentStr.repeat(indent);
          }
        }
        // Handle commas in objects/arrays
        else if (char === ',' && (code.substring(Math.max(0, i - 20), i).includes('{') || code.substring(Math.max(0, i - 20), i).includes('['))) {
          lines.push(currentLine.trim());
          currentLine = indentStr.repeat(indent);
        }
      }
      
      if (currentLine.trim()) {
        lines.push(currentLine.trim());
      }
      
      return lines.join('\n');
    } catch (err) {
      console.error('Prettify error:', err);
      return code;
    }
  };

  const handleCopy = async () => {
    try {
      const contentToCopy = isPrettified ? prettifyCode(fileContent) : fileContent;
      await navigator.clipboard.writeText(contentToCopy);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const togglePrettify = () => {
    setIsPrettified(!isPrettified);
  };

  const renderCodeWithHighlight = () => {
    if (!fileContent) return null;

    const displayContent = isPrettified ? prettifyCode(fileContent) : fileContent;
    const lines = displayContent.split('\n');
    const targetLine = finding.line_number || finding.line || 1;
    
    // Show context: 5 lines before and after
    const contextStart = Math.max(0, targetLine - 6);
    const contextEnd = Math.min(lines.length, targetLine + 5);
    const contextLines = lines.slice(contextStart, contextEnd);

    // Extract the specific code snippet that triggered the finding
    const getHighlightedSnippet = (line) => {
      // Priority 1: Use backend-provided matched_text (most accurate)
      const matchedText = finding.matched_text || finding.extra?.metadata?.matched_text;
      
      if (matchedText) {
        // Try exact match first
        if (line.includes(matchedText)) {
          const matchIndex = line.indexOf(matchedText);
          const start = Math.max(0, matchIndex - 30);
          const end = Math.min(line.length, matchIndex + matchedText.length + 30);
          return {
            before: line.substring(start, matchIndex),
            match: matchedText,
            after: line.substring(matchIndex + matchedText.length, end),
            hasMatch: true
          };
        }
        
        // Try case-insensitive match
        const lowerLine = line.toLowerCase();
        const lowerMatched = matchedText.toLowerCase();
        if (lowerLine.includes(lowerMatched)) {
          const matchIndex = lowerLine.indexOf(lowerMatched);
          const actualMatch = line.substring(matchIndex, matchIndex + matchedText.length);
          const start = Math.max(0, matchIndex - 30);
          const end = Math.min(line.length, matchIndex + matchedText.length + 30);
          return {
            before: line.substring(start, matchIndex),
            match: actualMatch,
            after: line.substring(matchIndex + matchedText.length, end),
            hasMatch: true
          };
        }
      }

      // Priority 2: Use check_id to determine the exact pattern to look for
      const checkId = finding.check_id?.toLowerCase() || '';
      
      // Map check_id patterns to their regex (more specific than keyword matching)
      const checkIdPatterns = {
        'base64_encode': /btoa\s*\(/gi,
        'base64_decode': /atob\s*\(/gi,
        'fetch_usage': /fetch\s*\(/gi,
        'xhr_usage': /XMLHttpRequest/gi,
        'formdata': /FormData/gi,
        'eval': /eval\s*\(/gi,
        'function_constructor': /Function\s*\(/gi,
        'innerhtml': /innerHTML\s*=/gi,
        'cookie': /document\.cookie/gi,
        'localstorage': /localStorage[.\[]/gi,
        'sessionstorage': /sessionStorage[.\[]/gi,
        'websocket': /WebSocket\s*\(/gi,
      };

      // Find the matching pattern based on check_id
      for (const [key, pattern] of Object.entries(checkIdPatterns)) {
        if (checkId.includes(key)) {
          const match = line.match(pattern);
          if (match) {
            const matchIndex = line.indexOf(match[0]);
            const start = Math.max(0, matchIndex - 30);
            const end = Math.min(line.length, matchIndex + match[0].length + 30);
            return {
              before: line.substring(start, matchIndex),
              match: match[0],
              after: line.substring(matchIndex + match[0].length, end),
              hasMatch: true
            };
          }
        }
      }

      // Priority 3: Fallback to pattern_name matching
      const patternName = finding.pattern_name?.toLowerCase() || '';
      for (const [key, pattern] of Object.entries(checkIdPatterns)) {
        if (patternName.includes(key)) {
          const match = line.match(pattern);
          if (match) {
            const matchIndex = line.indexOf(match[0]);
            const start = Math.max(0, matchIndex - 30);
            const end = Math.min(line.length, matchIndex + match[0].length + 30);
            return {
              before: line.substring(start, matchIndex),
              match: match[0],
              after: line.substring(matchIndex + match[0].length, end),
              hasMatch: true
            };
          }
        }
      }

      // Priority 4: Last resort - try all patterns
      for (const pattern of Object.values(checkIdPatterns)) {
        const match = line.match(pattern);
        if (match) {
          const matchIndex = line.indexOf(match[0]);
          const start = Math.max(0, matchIndex - 30);
          const end = Math.min(line.length, matchIndex + match[0].length + 30);
          return {
            before: line.substring(start, matchIndex),
            match: match[0],
            after: line.substring(matchIndex + match[0].length, end),
            hasMatch: true
          };
        }
      }

      return { before: '', match: line, after: '', hasMatch: false };
    };

    return (
      <div className="bg-muted rounded-lg overflow-hidden border">
        <div className="bg-background/50 px-4 py-2 border-b flex items-center justify-between">
          <span className="text-sm font-medium">Code Context</span>
          <div className="flex gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={togglePrettify}
              title={isPrettified ? "Show original" : "Prettify code"}
            >
              <Code2 className="h-4 w-4 mr-2" />
              {isPrettified ? "Original" : "Prettify"}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleCopy}
            >
              <Copy className="h-4 w-4 mr-2" />
              {copied ? "Copied!" : "Copy"}
            </Button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <pre className="p-4 text-xs font-mono leading-relaxed">
            {contextLines.map((line, idx) => {
              const lineNumber = contextStart + idx + 1;
              const isTargetLine = lineNumber === targetLine;
              const snippet = isTargetLine ? getHighlightedSnippet(line) : null;
              
              return (
                <div
                  key={idx}
                  className={`flex ${
                    isTargetLine
                      ? 'bg-yellow-400/20 border-l-4 border-l-yellow-500'
                      : 'hover:bg-muted/50'
                  }`}
                >
                  <span
                    className={`inline-block w-12 text-right pr-4 select-none flex-shrink-0 ${
                      isTargetLine
                        ? 'text-yellow-600 font-bold'
                        : 'text-muted-foreground'
                    }`}
                  >
                    {lineNumber}
                  </span>
                  <span className="flex-1 break-all">
                    {isTargetLine && snippet && snippet.hasMatch ? (
                      <>
                        <span className="text-muted-foreground">{snippet.before}</span>
                        <span className="bg-yellow-400/60 text-yellow-900 font-bold px-1 rounded">
                          {snippet.match}
                        </span>
                        <span className="text-muted-foreground">{snippet.after}</span>
                      </>
                    ) : (
                      <span className={isTargetLine ? 'font-semibold' : 'text-muted-foreground'}>
                        {line || ' '}
                      </span>
                    )}
                  </span>
                </div>
              );
            })}
          </pre>
        </div>
      </div>
    );
  };

  if (!finding) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[900px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-start gap-3">
            <AlertTriangle className={`h-6 w-6 mt-1 ${
              finding.severity === 'HIGH' || finding.severity === 'CRITICAL' || finding.severity === 'ERROR'
                ? 'text-red-500'
                : finding.severity === 'MEDIUM' || finding.severity === 'WARNING'
                ? 'text-yellow-500'
                : 'text-blue-500'
            }`} />
            <div className="flex-1">
              <DialogTitle className="text-xl">{finding.title || finding.pattern_name || 'Security Finding'}</DialogTitle>
              <DialogDescription className="mt-2">
                <div className="flex flex-wrap gap-2 items-center">
                  <Badge variant={
                    finding.severity === 'HIGH' || finding.severity === 'CRITICAL' || finding.severity === 'ERROR'
                      ? 'destructive'
                      : finding.severity === 'MEDIUM' || finding.severity === 'WARNING'
                      ? 'secondary'
                      : 'default'
                  }>
                    {finding.severity}
                  </Badge>
                  <span className="text-sm">•</span>
                  <span className="text-sm">{finding.file}</span>
                  <span className="text-sm">•</span>
                  <span className="text-sm">Line {finding.line_number || finding.line}</span>
                </div>
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-4">
          {/* Description */}
          <div className="bg-muted/50 rounded-lg p-4">
            <h4 className="font-semibold mb-2">Description</h4>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap">
              {finding.description || 'No description available'}
            </p>
          </div>

          {/* Additional Details */}
          {(finding.message || finding.check_id || finding.cwe || finding.owasp) && (
            <div className="bg-muted/50 rounded-lg p-4">
              <h4 className="font-semibold mb-2">Additional Details</h4>
              <div className="space-y-2 text-sm">
                {finding.message && (
                  <div>
                    <span className="text-muted-foreground">Message: </span>
                    <span>{finding.message}</span>
                  </div>
                )}
                {finding.check_id && (
                  <div>
                    <span className="text-muted-foreground">Check ID: </span>
                    <code className="bg-background px-2 py-1 rounded text-xs">{finding.check_id}</code>
                  </div>
                )}
                {finding.cwe && (
                  <div>
                    <span className="text-muted-foreground">CWE: </span>
                    <span>{Array.isArray(finding.cwe) ? finding.cwe.join(', ') : finding.cwe}</span>
                  </div>
                )}
                {finding.owasp && (
                  <div>
                    <span className="text-muted-foreground">OWASP: </span>
                    <span>{Array.isArray(finding.owasp) ? finding.owasp.join(', ') : finding.owasp}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Code Display */}
          {isLoading && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="ml-2">Loading file content...</span>
            </div>
          )}

          {error && (
            <div className="flex flex-col items-center justify-center py-8 space-y-3">
              <p className="text-destructive">❌ {error}</p>
              <Button onClick={loadFileContent} size="sm">
                🔄 Retry
              </Button>
            </div>
          )}

          {!isLoading && !error && fileContent && renderCodeWithHighlight()}

          {copied && (
            <div className="text-sm text-green-500 flex items-center gap-2">
              ✅ Content copied to clipboard!
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default FindingDetailsModal;

// Made with Bob
