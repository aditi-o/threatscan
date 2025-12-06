import { cn } from "@/lib/utils";
import { Shield } from "lucide-react";

interface ScanningAnimationProps {
  className?: string;
}

const ScanningAnimation = ({ className }: ScanningAnimationProps) => {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-6", className)}>
      {/* Animated shield */}
      <div className="relative">
        {/* Outer ring */}
        <div className="absolute inset-0 w-32 h-32 rounded-full border-2 border-primary/30 animate-ping" />
        
        {/* Middle ring */}
        <div className="absolute inset-2 w-28 h-28 rounded-full border-2 border-primary/50 animate-pulse" />
        
        {/* Inner circle with shield */}
        <div className="relative w-32 h-32 rounded-full bg-primary/10 flex items-center justify-center animate-pulse-glow">
          <Shield className="w-12 h-12 text-primary" />
        </div>

        {/* Scanning line */}
        <div className="absolute inset-0 overflow-hidden rounded-full">
          <div className="w-full h-1 bg-gradient-to-r from-transparent via-primary to-transparent animate-scan-line" />
        </div>
      </div>

      {/* Text */}
      <div className="text-center">
        <p className="font-display font-semibold text-lg text-foreground">
          Analyzing...
        </p>
        <p className="text-sm text-muted-foreground mt-1">
          Checking for threats and vulnerabilities
        </p>
      </div>

      {/* Loading dots */}
      <div className="flex gap-1.5">
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            className="w-2 h-2 rounded-full bg-primary animate-bounce"
            style={{ animationDelay: `${i * 0.15}s` }}
          />
        ))}
      </div>
    </div>
  );
};

export default ScanningAnimation;
