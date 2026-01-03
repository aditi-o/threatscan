import { Component, ErrorInfo, ReactNode } from "react";
import { AlertTriangle, RefreshCw, Home } from "lucide-react";
import { Button } from "@/components/ui/button";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

/**
 * Error Boundary component for catching runtime errors.
 * Prevents the entire app from crashing when a component fails.
 */
class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log error for debugging (in production, send to error tracking service)
    console.error("ErrorBoundary caught an error:", error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleRefresh = () => {
    window.location.reload();
  };

  private handleGoHome = () => {
    window.location.href = "/";
  };

  private handleRetry = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  public render() {
    if (this.state.hasError) {
      // Custom fallback UI
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
          <div className="max-w-md w-full text-center">
            {/* Error Icon */}
            <div className="mb-8">
              <div className="relative inline-block">
                <div className="w-24 h-24 rounded-full bg-destructive/10 flex items-center justify-center mx-auto">
                  <AlertTriangle className="w-12 h-12 text-destructive" />
                </div>
              </div>
            </div>

            {/* Error Message */}
            <h1 className="font-display text-2xl md:text-3xl font-bold mb-4 text-foreground">
              Something went wrong
            </h1>
            <p className="text-muted-foreground mb-8">
              We're sorry, but something unexpected happened. Please try refreshing the page or go back to the home page.
            </p>

            {/* Action Buttons */}
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Button variant="default" onClick={this.handleRetry} className="gap-2">
                <RefreshCw className="w-4 h-4" />
                Try Again
              </Button>
              <Button variant="outline" onClick={this.handleGoHome} className="gap-2">
                <Home className="w-4 h-4" />
                Go Home
              </Button>
            </div>

            {/* Error Details (dev only) */}
            {process.env.NODE_ENV === "development" && this.state.error && (
              <div className="mt-8 p-4 bg-secondary/30 rounded-lg text-left">
                <p className="text-xs text-muted-foreground font-mono mb-2">
                  Error Details (dev only):
                </p>
                <pre className="text-xs text-destructive overflow-auto max-h-32">
                  {this.state.error.toString()}
                </pre>
              </div>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
