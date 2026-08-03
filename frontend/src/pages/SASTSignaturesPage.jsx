import React, { useState, useEffect } from "react";
import { Button } from "../components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "../components/ui/card";
import { Badge } from "../components/ui/badge";
import { Input } from "../components/ui/input";
import { Textarea } from "../components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "../components/ui/dialog";
import {
  Search,
  Plus,
  Edit,
  Trash2,
  Copy,
  Check,
  FileCode,
  AlertTriangle,
} from "lucide-react";

const SASTSignaturesPage = () => {
  const [signatures, setSignatures] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSignature, setSelectedSignature] = useState(null);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [copiedId, setCopiedId] = useState(null);
  const [editForm, setEditForm] = useState({
    rule_id: "",
    pattern: "",
    message: "",
    severity: "WARNING",
    languages: "javascript",
    category: "security",
    cwe: "",
  });

  useEffect(() => {
    loadSignatures();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadSignatures = async () => {
    // TODO: Load from backend API
    // For now, load from localStorage as a temporary solution
    const stored = localStorage.getItem("sast_signatures");
    if (stored) {
      setSignatures(JSON.parse(stored));
    } else {
      setSignatures(getDefaultSignatures());
    }
  };

  const getDefaultSignatures = () => {
    return [
      {
        id: "1",
        rule_id: "custom-eval-usage",
        pattern: "eval(...)",
        message: "Dangerous use of eval() function detected",
        severity: "ERROR",
        languages: ["javascript"],
        category: "security",
        cwe: "CWE-95",
        created_at: "2024-01-15T10:00:00Z",
        source_file: "background.js",
      },
      {
        id: "2",
        rule_id: "custom-innerhtml-xss",
        pattern: "$X.innerHTML = $Y",
        message: "Potential XSS vulnerability through innerHTML",
        severity: "WARNING",
        languages: ["javascript"],
        category: "security",
        cwe: "CWE-79",
        created_at: "2024-01-16T14:30:00Z",
        source_file: "content.js",
      },
    ];
  };

  const saveSignatures = (newSignatures) => {
    localStorage.setItem("sast_signatures", JSON.stringify(newSignatures));
    setSignatures(newSignatures);
  };

  const handleCreateSignature = () => {
    setEditForm({
      rule_id: "",
      pattern: "",
      message: "",
      severity: "WARNING",
      languages: "javascript",
      category: "security",
      cwe: "",
    });
    setIsCreateModalOpen(true);
  };

  const handleEditSignature = (signature) => {
    setSelectedSignature(signature);
    setEditForm({
      rule_id: signature.rule_id,
      pattern: signature.pattern,
      message: signature.message,
      severity: signature.severity,
      languages: Array.isArray(signature.languages)
        ? signature.languages.join(", ")
        : signature.languages,
      category: signature.category || "security",
      cwe: signature.cwe || "",
    });
    setIsEditModalOpen(true);
  };

  const handleDeleteSignature = (signature) => {
    setSelectedSignature(signature);
    setIsDeleteModalOpen(true);
  };

  const confirmDelete = () => {
    const newSignatures = signatures.filter(
      (s) => s.id !== selectedSignature.id,
    );
    saveSignatures(newSignatures);
    setIsDeleteModalOpen(false);
    setSelectedSignature(null);
  };

  const handleSaveSignature = () => {
    const signatureData = {
      ...editForm,
      languages: editForm.languages.split(",").map((l) => l.trim()),
    };

    if (selectedSignature) {
      const newSignatures = signatures.map((s) =>
        s.id === selectedSignature.id
          ? { ...s, ...signatureData, updated_at: new Date().toISOString() }
          : s,
      );
      saveSignatures(newSignatures);
    } else {
      const newSignature = {
        id: Date.now().toString(),
        ...signatureData,
        created_at: new Date().toISOString(),
      };
      saveSignatures([...signatures, newSignature]);
    }

    setIsEditModalOpen(false);
    setIsCreateModalOpen(false);
    setSelectedSignature(null);
  };

  const handleCopyYAML = async (signature) => {
    const yaml = formatSignatureAsYAML(signature);
    try {
      await navigator.clipboard.writeText(yaml);
      setCopiedId(signature.id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  const formatSignatureAsYAML = (sig) => {
    return `rules:
  - id: ${sig.rule_id}
    pattern: ${sig.pattern}
    message: ${sig.message}
    languages: [${Array.isArray(sig.languages) ? sig.languages.join(", ") : sig.languages}]
    severity: ${sig.severity}
    metadata:
      category: ${sig.category || "security"}
      cwe: ${sig.cwe || "CWE-79"}
`;
  };

  const filteredSignatures = signatures.filter(
    (sig) =>
      searchQuery === "" ||
      sig.rule_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      sig.message.toLowerCase().includes(searchQuery.toLowerCase()) ||
      sig.pattern.toLowerCase().includes(searchQuery.toLowerCase()),
  );

  const getSeverityColor = (severity) => {
    if (severity === "ERROR" || severity === "CRITICAL") return "destructive";
    if (severity === "WARNING") return "secondary";
    return "default";
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <div>
          <h1 className="page-title">✨ SAST Signatures</h1>
          <p className="page-subtitle">
            Manage custom Semgrep rules for detecting security patterns
          </p>
        </div>
        <Button onClick={handleCreateSignature} className="gap-2">
          <Plus className="h-4 w-4" />
          Create New Signature
        </Button>
      </div>

      <div className="glass-card mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search signatures by ID, message, or pattern..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">
              Total Signatures
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{signatures.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Critical</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-500">
              {
                signatures.filter(
                  (s) => s.severity === "ERROR" || s.severity === "CRITICAL",
                ).length
              }
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Warnings</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-yellow-500">
              {signatures.filter((s) => s.severity === "WARNING").length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Info</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-blue-500">
              {signatures.filter((s) => s.severity === "INFO").length}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        {filteredSignatures.length === 0 ? (
          <Card>
            <CardContent className="text-center py-12">
              <FileCode className="h-12 w-12 mx-auto mb-4 text-muted-foreground opacity-50" />
              <h3 className="text-lg font-semibold mb-2">
                No Signatures Found
              </h3>
              <p className="text-muted-foreground mb-4">
                {searchQuery
                  ? "Try adjusting your search query"
                  : "Create your first SAST signature to get started"}
              </p>
              {!searchQuery && (
                <Button onClick={handleCreateSignature} className="gap-2">
                  <Plus className="h-4 w-4" />
                  Create Signature
                </Button>
              )}
            </CardContent>
          </Card>
        ) : (
          filteredSignatures.map((signature) => (
            <Card key={signature.id} className="border-l-4 border-l-primary">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <CardTitle className="text-lg">
                        {signature.rule_id}
                      </CardTitle>
                      <Badge variant={getSeverityColor(signature.severity)}>
                        {signature.severity}
                      </Badge>
                      {signature.cwe && (
                        <Badge variant="outline">{signature.cwe}</Badge>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {signature.message}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleCopyYAML(signature)}
                      title="Copy YAML"
                    >
                      {copiedId === signature.id ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleEditSignature(signature)}
                      title="Edit"
                    >
                      <Edit className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDeleteSignature(signature)}
                      title="Delete"
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Pattern
                    </label>
                    <pre className="mt-1 p-3 bg-muted rounded-lg text-xs font-mono overflow-x-auto">
                      {signature.pattern}
                    </pre>
                  </div>
                  <div className="flex gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">Languages: </span>
                      <span className="font-medium">
                        {Array.isArray(signature.languages)
                          ? signature.languages.join(", ")
                          : signature.languages}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Category: </span>
                      <span className="font-medium">
                        {signature.category || "security"}
                      </span>
                    </div>
                    {signature.source_file && (
                      <div>
                        <span className="text-muted-foreground">Source: </span>
                        <span className="font-medium">
                          {signature.source_file}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      <Dialog
        open={isEditModalOpen || isCreateModalOpen}
        onOpenChange={(open) => {
          setIsEditModalOpen(open);
          setIsCreateModalOpen(open);
        }}
      >
        <DialogContent className="sm:max-w-[700px] max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {selectedSignature
                ? "Edit SAST Signature"
                : "Create New SAST Signature"}
            </DialogTitle>
            <DialogDescription>
              Define a custom Semgrep rule for detecting security patterns
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Rule ID *</label>
              <Input
                value={editForm.rule_id}
                onChange={(e) =>
                  setEditForm({ ...editForm, rule_id: e.target.value })
                }
                placeholder="custom-rule-name"
                className="mt-1"
              />
            </div>

            <div>
              <label className="text-sm font-medium">Pattern *</label>
              <Textarea
                value={editForm.pattern}
                onChange={(e) =>
                  setEditForm({ ...editForm, pattern: e.target.value })
                }
                placeholder="$X = eval($Y)"
                className="mt-1 font-mono text-sm"
                rows={3}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Use Semgrep pattern syntax (e.g., $X for metavariables)
              </p>
            </div>

            <div>
              <label className="text-sm font-medium">Message *</label>
              <Textarea
                value={editForm.message}
                onChange={(e) =>
                  setEditForm({ ...editForm, message: e.target.value })
                }
                placeholder="Describe what this rule detects..."
                className="mt-1"
                rows={2}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Severity *</label>
                <select
                  value={editForm.severity}
                  onChange={(e) =>
                    setEditForm({ ...editForm, severity: e.target.value })
                  }
                  className="mt-1 w-full px-3 py-2 border rounded-md"
                >
                  <option value="ERROR">ERROR</option>
                  <option value="WARNING">WARNING</option>
                  <option value="INFO">INFO</option>
                </select>
              </div>

              <div>
                <label className="text-sm font-medium">Languages *</label>
                <Input
                  value={editForm.languages}
                  onChange={(e) =>
                    setEditForm({ ...editForm, languages: e.target.value })
                  }
                  placeholder="javascript, typescript"
                  className="mt-1"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Category</label>
                <Input
                  value={editForm.category}
                  onChange={(e) =>
                    setEditForm({ ...editForm, category: e.target.value })
                  }
                  placeholder="security"
                  className="mt-1"
                />
              </div>

              <div>
                <label className="text-sm font-medium">CWE</label>
                <Input
                  value={editForm.cwe}
                  onChange={(e) =>
                    setEditForm({ ...editForm, cwe: e.target.value })
                  }
                  placeholder="CWE-79"
                  className="mt-1"
                />
              </div>
            </div>
          </div>

          <DialogFooter className="gap-2">
            <Button
              variant="outline"
              onClick={() => {
                setIsEditModalOpen(false);
                setIsCreateModalOpen(false);
              }}
            >
              Cancel
            </Button>
            <Button onClick={handleSaveSignature}>
              {selectedSignature ? "Save Changes" : "Create Signature"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={isDeleteModalOpen} onOpenChange={setIsDeleteModalOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              Delete Signature
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this SAST signature? This action
              cannot be undone.
            </DialogDescription>
          </DialogHeader>

          {selectedSignature && (
            <div className="p-4 bg-muted rounded-lg">
              <div className="font-medium">{selectedSignature.rule_id}</div>
              <div className="text-sm text-muted-foreground">
                {selectedSignature.message}
              </div>
            </div>
          )}

          <DialogFooter className="gap-2">
            <Button
              variant="outline"
              onClick={() => setIsDeleteModalOpen(false)}
            >
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDelete}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default SASTSignaturesPage;
