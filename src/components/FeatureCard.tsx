import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";

interface FeatureCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  href: string;
  gradient?: string;
}

const FeatureCard = ({
  icon: Icon,
  title,
  description,
  href,
  gradient = "from-primary/20 to-primary/5",
}: FeatureCardProps) => {
  return (
    <Link to={href} className="group block">
      <div className="glass-card p-6 rounded-xl border border-border/30 transition-all duration-300 hover:border-primary/50 hover:scale-[1.02] hover:shadow-lg">
        {/* Icon with gradient background */}
        <div
          className={cn(
            "w-14 h-14 rounded-xl flex items-center justify-center mb-4 bg-gradient-to-br transition-transform duration-300 group-hover:scale-110",
            gradient
          )}
        >
          <Icon className="w-7 h-7 text-primary" />
        </div>

        {/* Content */}
        <h3 className="font-display font-semibold text-lg text-foreground mb-2 group-hover:text-primary transition-colors">
          {title}
        </h3>
        <p className="text-sm text-muted-foreground leading-relaxed">
          {description}
        </p>

        {/* Arrow indicator */}
        <div className="mt-4 flex items-center gap-2 text-primary text-sm font-medium opacity-0 group-hover:opacity-100 transition-opacity">
          <span>Get Started</span>
          <span className="transform group-hover:translate-x-1 transition-transform">→</span>
        </div>
      </div>
    </Link>
  );
};

export default FeatureCard;
