import React from "react";
import { Modal, Button, TextInput, TextArea } from "@carbon/react";
import "./CacheConfirmationModal.scss";

const CacheConfirmationModal = ({
  isOpen,
  onClose,
  onViewCached,
  onReScan,
  cachedData,
  extensionId,
}) => {
  if (!isOpen || !cachedData) return null;

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  const formatAge = (timestamp) => {
    const age = Date.now() - timestamp;
    const hours = Math.floor(age / (1000 * 60 * 60));
    const minutes = Math.floor((age % (1000 * 60 * 60)) / (1000 * 60));

    if (hours > 0) {
      return `${hours}h ${minutes}m ago`;
    }
    return `${minutes}m ago`;
  };

  return (
    <Modal
      open={isOpen}
      modalHeading="Extension Previously Scanned"
      primaryButtonText="View Cached Results"
      secondaryButtonText="Re-scan Extension"
      onRequestClose={onClose}
      onRequestSubmit={onViewCached}
      size="md"
      className="cache-confirmation-modal"
    >
      <div className="cache-info">
        <div className="cache-header">
          <h3>This extension has been scanned before</h3>
        </div>

        <div className="cache-details">
          <div className="detail-row">
            <span className="label">Extension ID:</span>
            <span className="value">{extensionId}</span>
          </div>

          <div className="detail-row">
            <span className="label">Last Scanned:</span>
            <span className="value">
              {formatTimestamp(cachedData.timestamp)}
            </span>
          </div>

          <div className="detail-row">
            <span className="label">Age:</span>
            <span className="value">{formatAge(cachedData.timestamp)}</span>
          </div>

          <div className="detail-row">
            <span className="label">Times Scanned:</span>
            <span className="value">{cachedData.scanCount}</span>
          </div>
        </div>

        <div className="cache-summary">
          <h4>Previous Scan Summary:</h4>
          {cachedData.data && (
            <div className="summary-details">
              <div className="summary-item">
                <span className="label">Security Score:</span>
                <span
                  className={`value score-${cachedData.data.securityScore < 50 ? "low" : cachedData.data.securityScore < 80 ? "medium" : "high"}`}
                >
                  {cachedData.data.securityScore || "N/A"}/100
                </span>
              </div>

              <div className="summary-item">
                <span className="label">Total Files:</span>
                <span className="value">
                  {cachedData.data.totalFiles || "N/A"}
                </span>
              </div>

              <div className="summary-item">
                <span className="label">Security Findings:</span>
                <span className="value">
                  {cachedData.data.totalFindings || "N/A"}
                </span>
              </div>

              <div className="summary-item">
                <span className="label">Risk Level:</span>
                <span
                  className={`value risk-${cachedData.data.riskLevel?.toLowerCase() || "unknown"}`}
                >
                  {cachedData.data.riskLevel || "N/A"}
                </span>
              </div>
            </div>
          )}
        </div>

        <div className="action-buttons">
          <Button
            kind="tertiary"
            onClick={onViewCached}
            className="view-cached-btn"
          >
            View Cached Results
          </Button>

          <Button kind="danger" onClick={onReScan} className="rescan-btn">
            Re-scan Extension
          </Button>
        </div>

        <div className="cache-note">
          <p>
            <strong>Note:</strong> Cached results are stored locally and expire
            after 24 hours. Re-scanning will download and analyze the latest
            version of the extension.
          </p>
        </div>
      </div>
    </Modal>
  );
};

export default CacheConfirmationModal;
