import { useLocation, Link } from "react-router-dom";
import { useEffect } from "react";
import { Shield, Home } from "lucide-react";
import { Button } from "@/components/ui/button";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  return (
    <div className="min-h-screen flex items-center justify-center pt-16">
      <div className="text-center px-4">
        {/* Animated 404 */}
        <div className="relative mb-8">
          <div className="text-[10rem] font-display font-bold text-muted/20 leading-none">
            404
          </div>
          <div className="absolute inset-0 flex items-center justify-center">
            <Shield className="w-24 h-24 text-primary animate-pulse-glow" />
          </div>
        </div>

        <h1 className="font-display text-3xl font-bold mb-4">
          Page Not <span className="text-gradient">Found</span>
        </h1>
        <p className="text-muted-foreground mb-8 max-w-md mx-auto">
          The page you're looking for doesn't exist or has been moved. 
          Let's get you back to safety.
        </p>

        <Link to="/">
          <Button variant="hero" size="lg" className="gap-2">
            <Home className="w-4 h-4" />
            Back to Home
          </Button>
        </Link>
      </div>
    </div>
  );
};

export default NotFound;
