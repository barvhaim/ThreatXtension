import React from "react";
import "./ModernCard.scss";

const ModernCard = ({
  children,
  className = "",
  variant = "default",
  hoverable = true,
  gradient = false,
  ...props
}) => {
  const cardClasses = [
    "modern-card",
    `modern-card--${variant}`,
    hoverable && "modern-card--hoverable",
    gradient && "modern-card--gradient",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={cardClasses} {...props}>
      {children}
    </div>
  );
};

const ModernCardHeader = ({
  children,
  className = "",
  icon,
  title,
  subtitle,
}) => {
  return (
    <div className={`modern-card__header ${className}`}>
      {icon && <span className="modern-card__icon">{icon}</span>}
      <div className="modern-card__header-content">
        {title && <h3 className="modern-card__title">{title}</h3>}
        {subtitle && <p className="modern-card__subtitle">{subtitle}</p>}
        {children}
      </div>
    </div>
  );
};

const ModernCardBody = ({ children, className = "" }) => {
  return <div className={`modern-card__body ${className}`}>{children}</div>;
};

const ModernCardFooter = ({ children, className = "" }) => {
  return <div className={`modern-card__footer ${className}`}>{children}</div>;
};

export { ModernCard, ModernCardHeader, ModernCardBody, ModernCardFooter };
export default ModernCard;
