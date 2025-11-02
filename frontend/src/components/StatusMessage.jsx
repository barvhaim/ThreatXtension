import React from "react";

const StatusMessage = ({
  type = "info",
  message,
  onDismiss,
  persistent = false,
  className = "",
}) => {
  if (!message) return null;

  const getIcon = () => {
    switch (type) {
      case "success":
        return "✅";
      case "error":
        return "❌";
      case "warning":
        return "⚠️";
      case "loading":
        return "🔄";
      case "info":
      default:
        return "ℹ️";
    }
  };

  const messageClasses = [
    "status-message",
    `status-message--${type}`,
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={messageClasses}>
      <div className="status-message__content">
        <span className="status-message__icon">{getIcon()}</span>
        <span className="status-message__text">{message}</span>
      </div>
      {!persistent && onDismiss && (
        <button
          className="status-message__dismiss"
          onClick={onDismiss}
          aria-label="Dismiss"
        >
          ✕
        </button>
      )}
    </div>
  );
};

export default StatusMessage;
