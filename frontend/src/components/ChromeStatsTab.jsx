import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { ChevronDown, ChevronUp, ExternalLink, Star, Users, TrendingUp, Shield, AlertTriangle } from "lucide-react";

/**
 * Chrome Stats Tab Component
 * Displays comprehensive metadata from chrome-stats.com API
 */
const ChromeStatsTab = ({ metadata, toggleSection, isSectionCollapsed }) => {
  if (!metadata) {
    return (
      <div className="text-center text-muted-foreground py-8">
        <p>No Chrome Stats data available</p>
        <p className="text-sm mt-2">This data is only available when analyzing via extension ID</p>
      </div>
    );
  }

  const formatNumber = (num) => {
    if (!num) return "0";
    return num.toLocaleString();
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return "N/A";
    return new Date(dateStr).toLocaleDateString();
  };

  return (
    <div className="space-y-4">
      {/* Basic Information */}
      <Card className="border-l-4 border-l-blue-500">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Extension Information
            </CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => toggleSection("chromestats-basic")}
            >
              {isSectionCollapsed("chromestats-basic") ? <ChevronDown /> : <ChevronUp />}
            </Button>
          </div>
        </CardHeader>
        {!isSectionCollapsed("chromestats-basic") && (
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div>
                <div className="text-sm text-muted-foreground">Name</div>
                <div className="font-medium">{metadata.name || "N/A"}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Version</div>
                <div className="font-medium">{metadata.version || "N/A"}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Category</div>
                <div className="font-medium">{metadata.category || "N/A"}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Platform</div>
                <div className="font-medium">{metadata.platform || "N/A"}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Payment Type</div>
                <div className="font-medium">{metadata.payment_type || "N/A"}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Size</div>
                <div className="font-medium">{metadata.size ? `${(metadata.size / 1024).toFixed(2)} KB` : "N/A"}</div>
              </div>
            </div>
            {metadata.description && (
              <div>
                <div className="text-sm text-muted-foreground mb-2">Description</div>
                <div className="text-sm">{metadata.description}</div>
              </div>
            )}
            {metadata.full_summary && (
              <div>
                <div className="text-sm text-muted-foreground mb-2">Full Summary</div>
                <div className="text-sm">{metadata.full_summary}</div>
              </div>
            )}
          </CardContent>
        )}
      </Card>

      {/* User Metrics */}
      <Card className="border-l-4 border-l-green-500">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              User Metrics
            </CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => toggleSection("chromestats-metrics")}
            >
              {isSectionCollapsed("chromestats-metrics") ? <ChevronDown /> : <ChevronUp />}
            </Button>
          </div>
        </CardHeader>
        {!isSectionCollapsed("chromestats-metrics") && (
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold">{formatNumber(metadata.user_count)}</div>
                <div className="text-sm text-muted-foreground">Total Users</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold flex items-center justify-center gap-1">
                  <Star className="h-5 w-5 fill-yellow-400 text-yellow-400" />
                  {metadata.rating_value || "N/A"}
                </div>
                <div className="text-sm text-muted-foreground">Rating</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <div className="text-2xl font-bold">{formatNumber(metadata.rating_count)}</div>
                <div className="text-sm text-muted-foreground">Ratings</div>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <Badge variant={metadata.is_featured ? "default" : "secondary"}>
                  {metadata.is_featured ? "Featured" : "Not Featured"}
                </Badge>
                <div className="text-sm text-muted-foreground mt-2">Status</div>
              </div>
            </div>

            {/* Deltas */}
            {(metadata.one_day_delta || metadata.one_week_delta) && (
              <div className="mt-4 grid grid-cols-2 gap-4">
                {metadata.one_day_delta && (
                  <div className="p-3 border rounded-lg">
                    <div className="text-sm font-medium mb-2">24-Hour Change</div>
                    <div className="text-sm space-y-1">
                      <div className="flex justify-between">
                        <span>Users:</span>
                        <span className={metadata.one_day_delta.userCount > 0 ? "text-green-500" : "text-red-500"}>
                          {metadata.one_day_delta.userCount > 0 ? "+" : ""}{formatNumber(metadata.one_day_delta.userCount)}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
                {metadata.one_week_delta && (
                  <div className="p-3 border rounded-lg">
                    <div className="text-sm font-medium mb-2">7-Day Change</div>
                    <div className="text-sm space-y-1">
                      <div className="flex justify-between">
                        <span>Users:</span>
                        <span className={metadata.one_week_delta.userCount > 0 ? "text-green-500" : "text-red-500"}>
                          {metadata.one_week_delta.userCount > 0 ? "+" : ""}{formatNumber(metadata.one_week_delta.userCount)}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        )}
      </Card>

      {/* Publisher Information */}
      <Card className="border-l-4 border-l-purple-500">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Publisher Information</CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => toggleSection("chromestats-publisher")}
            >
              {isSectionCollapsed("chromestats-publisher") ? <ChevronDown /> : <ChevronUp />}
            </Button>
          </div>
        </CardHeader>
        {!isSectionCollapsed("chromestats-publisher") && (
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-sm text-muted-foreground">Author</div>
                <div className="font-medium">{metadata.author || "N/A"}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Trusted Publisher</div>
                <Badge variant={metadata.is_trusted_publisher ? "default" : "secondary"}>
                  {metadata.is_trusted_publisher === null ? "Unknown" : metadata.is_trusted_publisher ? "Yes" : "No"}
                </Badge>
              </div>
              {metadata.email && (
                <div>
                  <div className="text-sm text-muted-foreground">Email</div>
                  <div className="font-medium">{metadata.email}</div>
                </div>
              )}
              {metadata.website && (
                <div>
                  <div className="text-sm text-muted-foreground">Website</div>
                  <a href={metadata.website} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline flex items-center gap-1">
                    Visit <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              )}
              {metadata.publisher_country && (
                <div>
                  <div className="text-sm text-muted-foreground">Country</div>
                  <div className="font-medium">{metadata.publisher_country}</div>
                </div>
              )}
              {metadata.publisher_address && (
                <div className="col-span-2">
                  <div className="text-sm text-muted-foreground">Address</div>
                  <div className="font-medium">{metadata.publisher_address}</div>
                </div>
              )}
            </div>
            {metadata.privacy_policy_url && (
              <div>
                <a href={metadata.privacy_policy_url} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline flex items-center gap-1">
                  Privacy Policy <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            )}
          </CardContent>
        )}
      </Card>

      {/* Risk Assessment */}
      {metadata.risk && (
        <Card className="border-l-4 border-l-red-500">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5" />
                Risk Assessment
              </CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => toggleSection("chromestats-risk")}
              >
                {isSectionCollapsed("chromestats-risk") ? <ChevronDown /> : <ChevronUp />}
              </Button>
            </div>
          </CardHeader>
          {!isSectionCollapsed("chromestats-risk") && (
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="text-center p-4 bg-muted rounded-lg">
                  <div className="text-3xl font-bold">{metadata.risk.riskImpact || 0}/4</div>
                  <div className="text-sm text-muted-foreground">Risk Impact</div>
                </div>
                <div className="text-center p-4 bg-muted rounded-lg">
                  <div className="text-3xl font-bold">{metadata.risk.riskLikelihood || 0}/4</div>
                  <div className="text-sm text-muted-foreground">Risk Likelihood</div>
                </div>
              </div>

              {metadata.risk.riskImpactReasons && metadata.risk.riskImpactReasons.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Impact Reasons:</div>
                  <div className="space-y-2">
                    {metadata.risk.riskImpactReasons.map((reason, idx) => (
                      <div key={idx} className="p-2 border rounded text-sm">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-medium">{reason.reason}</span>
                          <Badge variant={reason.severity === "high" ? "destructive" : "secondary"}>
                            {reason.severity}
                          </Badge>
                        </div>
                        <div className="text-muted-foreground">{reason.description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {metadata.risk.riskLikelihoodReasons && metadata.risk.riskLikelihoodReasons.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Likelihood Reasons:</div>
                  <div className="space-y-2">
                    {metadata.risk.riskLikelihoodReasons.map((reason, idx) => (
                      <div key={idx} className="p-2 border rounded text-sm">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-medium">{reason.reason}</span>
                          <Badge variant={reason.severity === "high" ? "destructive" : "secondary"}>
                            {reason.severity}
                          </Badge>
                        </div>
                        <div className="text-muted-foreground">{reason.description}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          )}
        </Card>
      )}

      {/* Reviews Summary */}
      {metadata.review_summary && (
        <Card className="border-l-4 border-l-yellow-500">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>User Reviews Summary</CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => toggleSection("chromestats-reviews")}
              >
                {isSectionCollapsed("chromestats-reviews") ? <ChevronDown /> : <ChevronUp />}
              </Button>
            </div>
          </CardHeader>
          {!isSectionCollapsed("chromestats-reviews") && (
            <CardContent className="space-y-4">
              {metadata.review_summary.summary && (
                <div>
                  <div className="text-sm font-medium mb-2">Overall Summary</div>
                  <div className="text-sm text-muted-foreground">{metadata.review_summary.summary}</div>
                </div>
              )}
              <div className="grid grid-cols-2 gap-4">
                {metadata.review_summary.pros && metadata.review_summary.pros.length > 0 && (
                  <div>
                    <div className="text-sm font-medium mb-2 text-green-600">Pros</div>
                    <ul className="text-sm space-y-1">
                      {metadata.review_summary.pros.map((pro, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-green-500">✓</span>
                          <span>{pro}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {metadata.review_summary.cons && metadata.review_summary.cons.length > 0 && (
                  <div>
                    <div className="text-sm font-medium mb-2 text-red-600">Cons</div>
                    <ul className="text-sm space-y-1">
                      {metadata.review_summary.cons.map((con, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-red-500">✗</span>
                          <span>{con}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </CardContent>
          )}
        </Card>
      )}

      {/* Dates */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Timeline</CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => toggleSection("chromestats-dates")}
            >
              {isSectionCollapsed("chromestats-dates") ? <ChevronDown /> : <ChevronUp />}
            </Button>
          </div>
        </CardHeader>
        {!isSectionCollapsed("chromestats-dates") && (
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <div className="text-sm text-muted-foreground">Created</div>
                <div className="font-medium">{formatDate(metadata.creation_date)}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Last Updated</div>
                <div className="font-medium">{formatDate(metadata.last_update)}</div>
              </div>
              <div>
                <div className="text-sm text-muted-foreground">Data As Of</div>
                <div className="font-medium">{formatDate(metadata.as_of_date)}</div>
              </div>
            </div>
          </CardContent>
        )}
      </Card>

      {/* Manifest Summary */}
      {metadata.manifest_summary && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Manifest Details</CardTitle>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => toggleSection("chromestats-manifest")}
              >
                {isSectionCollapsed("chromestats-manifest") ? <ChevronDown /> : <ChevronUp />}
              </Button>
            </div>
          </CardHeader>
          {!isSectionCollapsed("chromestats-manifest") && (
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-muted-foreground">Manifest Version</div>
                  <div className="font-medium">{metadata.manifest_summary.manifest_version || "N/A"}</div>
                </div>
                <div>
                  <div className="text-sm text-muted-foreground">Has Content Scripts</div>
                  <Badge variant={metadata.manifest_summary.has_content_scripts ? "default" : "secondary"}>
                    {metadata.manifest_summary.has_content_scripts ? "Yes" : "No"}
                  </Badge>
                </div>
              </div>
              {metadata.manifest_summary.permissions && metadata.manifest_summary.permissions.length > 0 && (
                <div>
                  <div className="text-sm text-muted-foreground mb-2">Permissions</div>
                  <div className="flex flex-wrap gap-2">
                    {metadata.manifest_summary.permissions.map((perm, idx) => (
                      <Badge key={idx} variant="outline">{perm}</Badge>
                    ))}
                  </div>
                </div>
              )}
              {metadata.manifest_summary.host_permissions && metadata.manifest_summary.host_permissions.length > 0 && (
                <div>
                  <div className="text-sm text-muted-foreground mb-2">Host Permissions</div>
                  <div className="flex flex-wrap gap-2">
                    {metadata.manifest_summary.host_permissions.map((host, idx) => (
                      <Badge key={idx} variant="outline">{host}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          )}
        </Card>
      )}

      {/* Additional Info */}
      {metadata.supported_languages && metadata.supported_languages.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Supported Languages ({metadata.supported_languages.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {metadata.supported_languages.slice(0, 20).map((lang, idx) => (
                <Badge key={idx} variant="outline">{lang}</Badge>
              ))}
              {metadata.supported_languages.length > 20 && (
                <Badge variant="secondary">+{metadata.supported_languages.length - 20} more</Badge>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default ChromeStatsTab;

// Made with Bob
