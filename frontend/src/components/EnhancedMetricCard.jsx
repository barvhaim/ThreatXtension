import React from "react";
import { Tooltip } from "@carbon/react";
import { Information } from "@carbon/icons-react";
import "./EnhancedMetricCard.scss";

/**
 * Enhanced Metric Card Component with trend indicators and sparkline charts
 *
 * @param {Object} props
 * @param {string} props.icon - Emoji or icon to display
 * @param {string} props.title - Card title
 * @param {string} props.subtitle - Card subtitle
 * @param {number|string} props.value - Main value to display
 * @param {string} props.label - Label for the value
 * @param {string} props.variant - Card variant (primary, success, warning, danger)
 * @param {number} props.trend - Trend percentage (positive or negative)
 * @param {Array<number>} props.sparklineData - Array of numbers for sparkline chart
 * @param {string} props.helpText - Help text for the tooltip
 * @param {string} props.className - Additional CSS classes
 */
const EnhancedMetricCard = ({
  icon,
  title,
  subtitle,
  value,
  label,
  variant = "default",
  trend = null,
  sparklineData = [],
  helpText = "",
  className = "",
  ...props
}) => {
  const cardClasses = [
    "enhanced-metric-card",
    `enhanced-metric-card--${variant}`,
    className,
  ]
    .filter(Boolean)
    .join(" ");

  // Determine trend direction and class
  const trendDirection = trend > 0 ? "up" : trend < 0 ? "down" : "neutral";
  const trendClass = `trend-${trendDirection}`;
  const trendIcon = trend > 0 ? "↑" : trend < 0 ? "↓" : "→";

  // Format trend value for display
  const trendDisplay = trend ? `${trendIcon} ${Math.abs(trend)}%` : "";

  // Generate sparkline SVG path if data is provided
  const generateSparklinePath = () => {
    if (!sparklineData || sparklineData.length < 2) return "";

    const width = 100;
    const height = 30;
    const padding = 2;

    const max = Math.max(...sparklineData);
    const min = Math.min(...sparklineData);
    const range = max - min || 1;

    const xStep = (width - padding * 2) / (sparklineData.length - 1);

    const points = sparklineData.map((value, index) => {
      const x = padding + index * xStep;
      const y =
        height - padding - ((value - min) / range) * (height - padding * 2);
      return `${x},${y}`;
    });

    return `M${points.join(" L")}`;
  };

  return (
    <div className={cardClasses} {...props}>
      <div className="enhanced-metric-card__header">
        {icon && <span className="enhanced-metric-card__icon">{icon}</span>}
        <div className="enhanced-metric-card__header-content">
          <div className="enhanced-metric-card__title-row">
            <h3 className="enhanced-metric-card__title">{title}</h3>
            {helpText && (
              <Tooltip align="top" label={helpText}>
                <button
                  className="enhanced-metric-card__help-icon"
                  aria-label="More information"
                >
                  <Information size={16} />
                </button>
              </Tooltip>
            )}
          </div>
          {subtitle && (
            <p className="enhanced-metric-card__subtitle">{subtitle}</p>
          )}
        </div>
      </div>

      <div className="enhanced-metric-card__body">
        <div className="enhanced-metric-card__value-container">
          <div className="enhanced-metric-card__value">{value}</div>
          {trend !== null && (
            <div className={`enhanced-metric-card__trend ${trendClass}`}>
              {trendDisplay}
            </div>
          )}
        </div>
        <div className="enhanced-metric-card__label">{label}</div>

        {sparklineData.length > 1 && (
          <div className="enhanced-metric-card__sparkline">
            <svg
              width="100%"
              height="30"
              viewBox="0 0 100 30"
              preserveAspectRatio="none"
            >
              <path
                d={generateSparklinePath()}
                className={`sparkline-path sparkline-path--${variant}`}
                fill="none"
                strokeWidth="2"
              />
            </svg>
          </div>
        )}
      </div>
    </div>
  );
};

export default EnhancedMetricCard;

// Made with Bob
