import React, { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Input } from "./ui/input";
import { Search, Filter } from "lucide-react";

const AllFindingsModal = ({
  isOpen,
  onClose,
  findings,
  onViewFindingDetails,
}) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  if (!findings) return null;

  // Filter findings based on search and severity
  const filteredFindings = findings.filter((finding) => {
    const matchesSearch =
      searchQuery === "" ||
      finding.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      finding.file?.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity =
      severityFilter === "ALL" || finding.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  // Group findings by severity
  const groupedFindings = {
    HIGH: filteredFindings.filter((f) => f.severity === "HIGH" || f.severity === "CRITICAL" || f.severity === "ERROR"),
    MEDIUM: filteredFindings.filter((f) => f.severity === "MEDIUM" || f.severity === "WARNING"),
    LOW: filteredFindings.filter((f) => f.severity === "LOW" || f.severity === "INFO"),
  };

  const getSeverityColor = (severity) => {
    if (severity === "HIGH" || severity === "CRITICAL" || severity === "ERROR") return "destructive";
    if (severity === "MEDIUM" || severity === "WARNING") return "secondary";
    return "default";
  };

  const getSeverityBorderColor = (severity) => {
    if (severity === "HIGH" || severity === "CRITICAL" || severity === "ERROR") return "border-l-red-500";
    if (severity === "MEDIUM" || severity === "WARNING") return "border-l-yellow-500";
    return "border-l-blue-500";
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[1000px] max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="text-2xl">
            All Security Findings ({filteredFindings.length})
          </DialogTitle>
          <DialogDescription>
            Complete list of security issues detected in this extension
          </DialogDescription>
        </DialogHeader>

        {/* Search and Filter Controls */}
        <div className="space-y-3 pb-4 border-b">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search findings by title, description, or file..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">Filter by severity:</span>
            <div className="flex gap-2">
              <Button
                variant={severityFilter === "ALL" ? "default" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("ALL")}
              >
                All ({findings.length})
              </Button>
              <Button
                variant={severityFilter === "HIGH" ? "destructive" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("HIGH")}
              >
                High ({groupedFindings.HIGH.length})
              </Button>
              <Button
                variant={severityFilter === "MEDIUM" ? "secondary" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("MEDIUM")}
              >
                Medium ({groupedFindings.MEDIUM.length})
              </Button>
              <Button
                variant={severityFilter === "LOW" ? "default" : "outline"}
                size="sm"
                onClick={() => setSeverityFilter("LOW")}
              >
                Low ({groupedFindings.LOW.length})
              </Button>
            </div>
          </div>
        </div>

        {/* Findings List */}
        <div className="flex-1 overflow-y-auto space-y-3 pr-2">
          {filteredFindings.length === 0 ? (
            <div className="text-center text-muted-foreground py-12">
              <p className="text-lg mb-2">No findings match your search</p>
              <p className="text-sm">Try adjusting your search query or filters</p>
            </div>
          ) : (
            filteredFindings.map((finding, index) => (
              <Card
                key={index}
                className={`border-l-4 ${getSeverityBorderColor(finding.severity)} hover:shadow-md transition-shadow`}
              >
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap gap-2 text-sm text-muted-foreground mb-2">
                        <span className="truncate">{finding.file}</span>
                        <span>•</span>
                        <span>Line {finding.line_number || finding.line}</span>
                      </div>
                      <CardTitle className="text-base leading-tight">
                        {finding.title || finding.pattern_name || "Security Finding"}
                      </CardTitle>
                    </div>
                    <Badge variant={getSeverityColor(finding.severity)}>
                      {finding.severity}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <p className="text-sm text-muted-foreground mb-3 line-clamp-2">
                    {finding.description || "No description available"}
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      onViewFindingDetails(finding);
                      onClose();
                    }}
                  >
                    📋 View Details
                  </Button>
                </CardContent>
              </Card>
            ))
          )}
        </div>

        {/* Footer with summary */}
        <div className="pt-4 border-t flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            Showing {filteredFindings.length} of {findings.length} findings
          </div>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default AllFindingsModal;

// Made with Bob
