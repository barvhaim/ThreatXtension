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
import { Input } from "./ui/input";
import { Textarea } from "./ui/textarea";
import { Badge } from "./ui/badge";
import { Loader2, Sparkles, Copy, Check } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";

const SASTSignatureModal = ({
  isOpen,
  onClose,
  file,
  extensionId,
  onGetFileContent,
  onGenerateSignature,
}) => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedSignatures, setGeneratedSignatures] = useState([]);
  const [selectedSignatureIndex, setSelectedSignatureIndex] = useState(0);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [signatureName, setSignatureName] = useState("");
  const [signatureDescription, setSignatureDescription] = useState("");

  useEffect(() => {
    if (isOpen && file) {
      // Reset state when modal opens
      setGeneratedSignatures([]);
      setSelectedSignatureIndex(0);
      setError(null);
      setCopied(false);
      setSignatureName("");
      setSignatureDescription("");
    }
  }, [isOpen, file]);

  // Update form when signature selection changes
  useEffect(() => {
    if (generatedSignatures.length > 0 && generatedSignatures[selectedSignatureIndex]) {
      const sig = generatedSignatures[selectedSignatureIndex];
      setSignatureName(sig.rule_id || `custom-${file?.name.replace(/\.[^/.]+$/, "")}`);
      setSignatureDescription(sig.message || "Custom SAST rule generated from file analysis");
    }
  }, [selectedSignatureIndex, generatedSignatures, file]);

  const handleGenerate = async () => {
    if (!file || !extensionId) return;

    setIsGenerating(true);
    setError(null);

    try {
      // Get file content
      const fileContent = await onGetFileContent(extensionId, file.path);

      // Generate signature using AI
      const result = await onGenerateSignature(fileContent, file.name);

      if (result.success) {
        // Handle both single signature and array of signatures
        const signatures = Array.isArray(result.data) ? result.data : [result.data];
        setGeneratedSignatures(signatures);
        setSelectedSignatureIndex(0);
        
        // Pre-fill name and description from first signature
        if (signatures.length > 0) {
          setSignatureName(signatures[0].rule_id || `custom-${file.name.replace(/\.[^/.]+$/, "")}`);
          setSignatureDescription(signatures[0].message || "Custom SAST rule generated from file analysis");
        }
      } else {
        throw new Error(result.error || "Failed to generate signature");
      }
    } catch (err) {
      console.error("Signature generation error:", err);
      let errorMessage = err.message || "Failed to generate SAST signature";
      
      // Check for specific error cases
      if (errorMessage.includes("cleaned up") || errorMessage.includes("410")) {
        errorMessage = "The extension files have been cleaned up after analysis. Please re-scan the extension to generate signatures from its files.";
      } else if (errorMessage.includes("Extension not found") || errorMessage.includes("404")) {
        errorMessage = "Extension files not found. The scan data may have expired. Please re-scan the extension.";
      }
      
      setError(errorMessage);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopySignature = async () => {
    if (generatedSignatures.length === 0) return;

    try {
      const currentSignature = generatedSignatures[selectedSignatureIndex];
      const yamlContent = formatSignatureAsYAML(currentSignature);
      await navigator.clipboard.writeText(yamlContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const handleSaveSignature = async () => {
    if (generatedSignatures.length === 0) return;

    const currentSignature = generatedSignatures[selectedSignatureIndex];
    const signature = {
      ...currentSignature,
      id: `${Date.now()}`, // Generate unique ID
      rule_id: signatureName || currentSignature.rule_id,
      message: signatureDescription || currentSignature.message,
      created_at: new Date().toISOString(),
      source_file: file.path,
    };

    // Load existing signatures from localStorage
    const stored = localStorage.getItem("sast_signatures");
    const existingSignatures = stored ? JSON.parse(stored) : [];
    
    // Add new signature
    const allSignatures = [...existingSignatures, signature];
    
    // Save to localStorage
    localStorage.setItem("sast_signatures", JSON.stringify(allSignatures));
    
    console.log("Saved signature to localStorage:", signature);
    onClose();
  };

  const handleSaveAllSignatures = async () => {
    if (generatedSignatures.length === 0) return;

    // Load existing signatures from localStorage
    const stored = localStorage.getItem("sast_signatures");
    const existingSignatures = stored ? JSON.parse(stored) : [];

    // Prepare new signatures with metadata
    const newSignatures = generatedSignatures.map((sig, index) => ({
      ...sig,
      id: `${Date.now()}-${index}`, // Generate unique ID
      created_at: new Date().toISOString(),
      source_file: file.path,
    }));

    // Merge with existing signatures
    const allSignatures = [...existingSignatures, ...newSignatures];
    
    // Save to localStorage
    localStorage.setItem("sast_signatures", JSON.stringify(allSignatures));
    
    console.log(`Saved ${newSignatures.length} signatures to localStorage`);
    newSignatures.forEach((sig, index) => {
      console.log(`Saving signature ${index + 1}:`, sig);
    });
    
    onClose();
  };

  const formatSignatureAsYAML = (sig) => {
    return `rules:
  - id: ${signatureName || sig.rule_id}
    pattern: ${sig.pattern}
    message: ${signatureDescription || sig.message}
    languages: [${sig.languages?.join(", ") || "javascript"}]
    severity: ${sig.severity || "WARNING"}
    metadata:
      category: ${sig.metadata?.category || "security"}
      cwe: ${sig.metadata?.cwe || "CWE-79"}
      confidence: ${sig.metadata?.confidence || "MEDIUM"}
      likelihood: ${sig.metadata?.likelihood || "MEDIUM"}
      impact: ${sig.metadata?.impact || "MEDIUM"}
`;
  };

  if (!file) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[900px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-purple-500" />
            Generate SAST Signature - {file.name}
          </DialogTitle>
          <DialogDescription>
            Use AI to automatically generate a custom Semgrep rule for detecting similar patterns
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* File Info */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">File Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Path:</span>
                <span className="font-mono">{file.path}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Type:</span>
                <Badge variant="outline">{file.type}</Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Risk Level:</span>
                <Badge variant={
                  file.riskLevel === "HIGH" ? "destructive" :
                  file.riskLevel === "MEDIUM" ? "secondary" : "default"
                }>
                  {file.riskLevel}
                </Badge>
              </div>
            </CardContent>
          </Card>

          {/* Generate Button */}
          {generatedSignatures.length === 0 && !isGenerating && (
            <div className="flex justify-center py-8">
              <Button onClick={handleGenerate} size="lg" className="gap-2">
                <Sparkles className="h-5 w-5" />
                Generate SAST Signatures with AI
              </Button>
            </div>
          )}

          {/* Loading State */}
          {isGenerating && (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <Loader2 className="h-12 w-12 animate-spin text-purple-500" />
              <div className="text-center">
                <p className="font-medium">Analyzing file and generating signature...</p>
                <p className="text-sm text-muted-foreground mt-2">
                  This may take a few moments
                </p>
              </div>
            </div>
          )}

          {/* Error State */}
          {error && (
            <div className="p-4 bg-destructive/10 border border-destructive rounded-lg">
              <div className="flex items-start gap-3">
                <span className="text-2xl">❌</span>
                <div className="flex-1">
                  <h4 className="font-semibold text-destructive mb-1">Generation Failed</h4>
                  <p className="text-sm">{error}</p>
                  <Button onClick={handleGenerate} variant="outline" size="sm" className="mt-3">
                    🔄 Retry
                  </Button>
                </div>
              </div>
            </div>
          )}

          {/* Generated Signatures */}
          {generatedSignatures.length > 0 && !isGenerating && (
            <div className="space-y-4">
              {/* Signature Selector */}
              {generatedSignatures.length > 1 && (
                <div className="flex items-center gap-2 p-3 bg-muted rounded-lg">
                  <span className="text-sm font-medium">Select Signature:</span>
                  <div className="flex gap-2 flex-wrap">
                    {generatedSignatures.map((_, index) => (
                      <Button
                        key={index}
                        variant={selectedSignatureIndex === index ? "default" : "outline"}
                        size="sm"
                        onClick={() => setSelectedSignatureIndex(index)}
                      >
                        {index + 1}
                      </Button>
                    ))}
                  </div>
                  <span className="text-sm text-muted-foreground ml-auto">
                    {generatedSignatures.length} signatures found
                  </span>
                </div>
              )}

              <Card className="border-purple-500/50">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">
                      Signature {selectedSignatureIndex + 1} of {generatedSignatures.length}
                    </CardTitle>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={handleCopySignature}
                      className="gap-2"
                    >
                      {copied ? (
                        <>
                          <Check className="h-4 w-4 text-green-500" />
                          Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="h-4 w-4" />
                          Copy YAML
                        </>
                      )}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Editable Fields */}
                  <div className="space-y-3">
                    <div>
                      <label className="text-sm font-medium">Rule ID</label>
                      <Input
                        value={signatureName}
                        onChange={(e) => setSignatureName(e.target.value)}
                        placeholder="custom-rule-name"
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium">Description</label>
                      <Textarea
                        value={signatureDescription}
                        onChange={(e) => setSignatureDescription(e.target.value)}
                        placeholder="Describe what this rule detects..."
                        className="mt-1"
                        rows={2}
                      />
                    </div>
                  </div>

                  {/* Pattern Preview */}
                  <div>
                    <label className="text-sm font-medium">Pattern</label>
                    <pre className="mt-1 p-3 bg-muted rounded-lg text-xs font-mono overflow-x-auto">
                      {generatedSignatures[selectedSignatureIndex]?.pattern}
                    </pre>
                  </div>

                  {/* Metadata */}
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-sm text-muted-foreground">Severity</label>
                      <div className="mt-1">
                        <Badge variant={
                          generatedSignatures[selectedSignatureIndex]?.severity === "ERROR" ? "destructive" :
                          generatedSignatures[selectedSignatureIndex]?.severity === "WARNING" ? "secondary" : "default"
                        }>
                          {generatedSignatures[selectedSignatureIndex]?.severity}
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm text-muted-foreground">Language</label>
                      <div className="mt-1 font-medium">
                        {generatedSignatures[selectedSignatureIndex]?.languages?.join(", ") || "javascript"}
                      </div>
                    </div>
                    {generatedSignatures[selectedSignatureIndex]?.metadata?.category && (
                      <div>
                        <label className="text-sm text-muted-foreground">Category</label>
                        <div className="mt-1 font-medium">{generatedSignatures[selectedSignatureIndex].metadata.category}</div>
                      </div>
                    )}
                    {generatedSignatures[selectedSignatureIndex]?.metadata?.cwe && (
                      <div>
                        <label className="text-sm text-muted-foreground">CWE</label>
                        <div className="mt-1 font-medium">{generatedSignatures[selectedSignatureIndex].metadata.cwe}</div>
                      </div>
                    )}
                  </div>

                  {/* Full YAML Preview */}
                  <div>
                    <label className="text-sm font-medium">Complete YAML Rule</label>
                    <pre className="mt-1 p-3 bg-muted rounded-lg text-xs font-mono overflow-x-auto max-h-64">
                      {formatSignatureAsYAML(generatedSignatures[selectedSignatureIndex])}
                    </pre>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          {generatedSignatures.length > 0 && (
            <>
              <Button onClick={handleSaveSignature} variant="secondary" className="gap-2">
                💾 Save This Signature
              </Button>
              {generatedSignatures.length > 1 && (
                <Button onClick={handleSaveAllSignatures} className="gap-2">
                  💾 Save All ({generatedSignatures.length})
                </Button>
              )}
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default SASTSignatureModal;

// Made with Bob
