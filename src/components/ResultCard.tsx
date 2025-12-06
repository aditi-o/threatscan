import { cn } from "@/lib/utils";
import { AlertTriangle, CheckCircle, Info, XCircle } from "lucide-react";
import { ReactNode } from "react";

interface ResultCardProps {
  type: "safe" | "warning" | "danger" | "info";
  title: string;
  description: string;
  details?: string[];
  children?: ReactNode;
}

const ResultCard = ({ type, title, description, details, children }: ResultCardProps) => {
  const config = {
    safe: {
      icon: CheckCircle,
      iconColor: "text-success",
      bgColor: "bg-success/5",
      borderColor: "border-success/30",
      glowClass: "glow-success",
    },
    warning: {
      icon: AlertTriangle,
      iconColor: "text-warning",
      bgColor: "bg-warning/5",
      borderColor: "border-warning/30",
      glowClass: "glow-warning",
    },
    danger: {
      icon: XCircle,
      iconColor: "text-destructive",
      bgColor: "bg-destructive/5",
      borderColor: "border-destructive/30",
      glowClass: "glow-destructive",
    },
    info: {
      icon: Info,
      iconColor: "text-primary",
      bgColor: "bg-primary/5",
      borderColor: "border-primary/30",
      glowClass: "glow-primary",
    },
  };

  const { icon: Icon, iconColor, bgColor, borderColor, glowClass } = config[type];

  return (
    <div
      className={cn(
        "glass-card p-6 rounded-xl border transition-all duration-300",
        bgColor,
        borderColor,
        glowClass
      )}
    >
      <div className="flex items-start gap-4">
        <div className={cn("p-3 rounded-lg", bgColor)}>
          <Icon className={cn("w-6 h-6", iconColor)} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="font-display font-semibold text-lg text-foreground mb-1">
            {title}
          </h3>
          <p className="text-muted-foreground text-sm">{description}</p>

          {details && details.length > 0 && (
            <ul className="mt-4 space-y-2">
              {details.map((detail, index) => (
                <li
                  key={index}
                  className="flex items-center gap-2 text-sm text-muted-foreground"
                >
                  <span className={cn("w-1.5 h-1.5 rounded-full", iconColor.replace("text-", "bg-"))} />
                  {detail}
                </li>
              ))}
            </ul>
          )}

          {children}
        </div>
      </div>
    </div>
  );
};

export default ResultCard;
