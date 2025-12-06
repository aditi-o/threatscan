import { cn } from "@/lib/utils";

interface RiskMeterProps {
  score: number;
  size?: "sm" | "md" | "lg";
}

const RiskMeter = ({ score, size = "md" }: RiskMeterProps) => {
  const getColor = () => {
    if (score <= 30) return "text-success";
    if (score <= 60) return "text-warning";
    return "text-destructive";
  };

  const getGlow = () => {
    if (score <= 30) return "glow-success";
    if (score <= 60) return "glow-warning";
    return "glow-destructive";
  };

  const getLabel = () => {
    if (score <= 30) return "Safe";
    if (score <= 60) return "Suspicious";
    return "High Risk";
  };

  const getBgGradient = () => {
    if (score <= 30) return "from-success/20 to-success/5";
    if (score <= 60) return "from-warning/20 to-warning/5";
    return "from-destructive/20 to-destructive/5";
  };

  const sizeClasses = {
    sm: "w-24 h-24",
    md: "w-36 h-36",
    lg: "w-48 h-48",
  };

  const textSize = {
    sm: "text-2xl",
    md: "text-4xl",
    lg: "text-5xl",
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-4">
      <div className={cn("relative", sizeClasses[size])}>
        {/* Background glow */}
        <div
          className={cn(
            "absolute inset-0 rounded-full bg-gradient-radial opacity-50 blur-xl",
            getBgGradient()
          )}
        />

        {/* SVG Circle */}
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
          {/* Background circle */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="currentColor"
            strokeWidth="8"
            className="text-muted/30"
          />
          {/* Progress circle */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="currentColor"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className={cn("transition-all duration-1000 ease-out", getColor())}
          />
        </svg>

        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={cn(
              "font-display font-bold transition-colors",
              textSize[size],
              getColor()
            )}
          >
            {score}
          </span>
          <span className="text-muted-foreground text-xs">/ 100</span>
        </div>
      </div>

      {/* Label */}
      <div
        className={cn(
          "px-4 py-2 rounded-full font-medium text-sm",
          getGlow(),
          score <= 30 && "bg-success/10 text-success",
          score > 30 && score <= 60 && "bg-warning/10 text-warning",
          score > 60 && "bg-destructive/10 text-destructive"
        )}
      >
        {getLabel()}
      </div>
    </div>
  );
};

export default RiskMeter;
