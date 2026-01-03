import { AlertCircle, WifiOff, Clock, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api";

interface ApiErrorDisplayProps {
  error: Error | ApiError | null;
  onRetry?: () => void;
  className?: string;
}

/**
 * Displays user-friendly error messages for API errors.
 * Shows appropriate icons and retry options based on error type.
 */
export function ApiErrorDisplay({ error, onRetry, className = "" }: ApiErrorDisplayProps) {
  if (!error) return null;

  const isApiError = error instanceof ApiError;
  const isTimeout = isApiError && error.isTimeout;
  const isNetworkError = isApiError && error.isNetworkError;
  const isRateLimited = isApiError && error.isRateLimited;

  // Choose appropriate icon
  let Icon = AlertCircle;
  let title = "Something went wrong";
  let description = error.message;

  if (isTimeout) {
    Icon = Clock;
    title = "Request timed out";
    description = "The server took too long to respond. Please try again.";
  } else if (isNetworkError) {
    Icon = WifiOff;
    title = "Connection error";
    description = "Unable to connect to the server. Please check your internet connection.";
  } else if (isRateLimited) {
    Icon = Clock;
    title = "Too many requests";
    description = "Please wait a moment before trying again.";
  }

  return (
    <div className={`p-6 rounded-xl bg-destructive/5 border border-destructive/20 text-center ${className}`}>
      <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-destructive/10 mb-4">
        <Icon className="w-6 h-6 text-destructive" />
      </div>
      
      <h3 className="font-display font-semibold text-lg text-foreground mb-2">
        {title}
      </h3>
      
      <p className="text-sm text-muted-foreground mb-4">
        {description}
      </p>

      {onRetry && (
        <Button 
          variant="outline" 
          onClick={onRetry}
          className="gap-2"
        >
          <RefreshCw className="w-4 h-4" />
          Try Again
        </Button>
      )}
    </div>
  );
}

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
}

/**
 * Displays an empty state with optional action.
 */
export function EmptyState({ 
  icon, 
  title, 
  description, 
  action, 
  className = "" 
}: EmptyStateProps) {
  return (
    <div className={`p-8 rounded-xl bg-secondary/30 text-center ${className}`}>
      {icon && (
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-muted mb-4">
          {icon}
        </div>
      )}
      
      <h3 className="font-display font-semibold text-lg text-foreground mb-2">
        {title}
      </h3>
      
      <p className="text-sm text-muted-foreground mb-4 max-w-sm mx-auto">
        {description}
      </p>

      {action && (
        <Button variant="default" onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  );
}

interface LoadingStateProps {
  message?: string;
  className?: string;
}

/**
 * Displays a loading state with spinner.
 */
export function LoadingState({ message = "Loading...", className = "" }: LoadingStateProps) {
  return (
    <div className={`flex flex-col items-center justify-center p-8 ${className}`}>
      <div className="w-8 h-8 border-2 border-primary/30 border-t-primary rounded-full animate-spin mb-4" />
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );
}
