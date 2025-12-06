import { useState } from "react";
import { Link as LinkIcon, Shield, ExternalLink, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import RiskMeter from "@/components/RiskMeter";
import ResultCard from "@/components/ResultCard";
import ScanningAnimation from "@/components/ScanningAnimation";
import { toast } from "sonner";

interface ScanResult {
  riskScore: number;
  label: string;
  url: string;
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
  suggestedAction: string;
}

// URL heuristic analysis
const analyzeUrl = (url: string): ScanResult => {
  let riskScore = 0;
  const heuristics: ScanResult["heuristics"] = [];

  try {
    const urlObj = new URL(url);

    // Check for HTTPS
    if (urlObj.protocol !== "https:") {
      riskScore += 25;
      heuristics.push({
        name: "No HTTPS",
        score: 25,
        description: "This URL does not use secure HTTPS protocol",
      });
    }

    // Check for IP address in host
    const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(urlObj.hostname)) {
      riskScore += 30;
      heuristics.push({
        name: "IP Address Host",
        score: 30,
        description: "URL uses an IP address instead of a domain name",
      });
    }

    // Check for suspicious TLDs
    const suspiciousTlds = [".xyz", ".top", ".work", ".click", ".link", ".tk", ".ml", ".ga", ".cf"];
    if (suspiciousTlds.some((tld) => urlObj.hostname.endsWith(tld))) {
      riskScore += 20;
      heuristics.push({
        name: "Suspicious TLD",
        score: 20,
        description: "Domain uses a top-level domain commonly associated with spam",
      });
    }

    // Check for very long URL
    if (url.length > 100) {
      riskScore += 10;
      heuristics.push({
        name: "Long URL",
        score: 10,
        description: "Unusually long URL may indicate URL obfuscation",
      });
    }

    // Check for suspicious keywords
    const suspiciousKeywords = ["login", "verify", "update", "secure", "account", "banking", "password", "confirm", "suspend"];
    const hasKeywords = suspiciousKeywords.some((kw) => url.toLowerCase().includes(kw));
    if (hasKeywords) {
      riskScore += 15;
      heuristics.push({
        name: "Suspicious Keywords",
        score: 15,
        description: "URL contains keywords commonly used in phishing attacks",
      });
    }

    // Check for multiple subdomains
    const subdomains = urlObj.hostname.split(".").length - 2;
    if (subdomains > 2) {
      riskScore += 15;
      heuristics.push({
        name: "Multiple Subdomains",
        score: 15,
        description: "URL has many subdomains, which can be used to hide the real domain",
      });
    }

    // Check for special characters in domain
    if (/[@\-_]/.test(urlObj.hostname)) {
      riskScore += 10;
      heuristics.push({
        name: "Special Characters",
        score: 10,
        description: "Domain contains unusual special characters",
      });
    }

  } catch {
    riskScore = 75;
    heuristics.push({
      name: "Invalid URL",
      score: 75,
      description: "The URL format is invalid or malformed",
    });
  }

  // Cap score at 100
  riskScore = Math.min(riskScore, 100);

  // Determine label and action
  let label: string;
  let suggestedAction: string;

  if (riskScore <= 30) {
    label = "Safe";
    suggestedAction = "This URL appears to be safe to visit. Always remain cautious with personal information.";
  } else if (riskScore <= 60) {
    label = "Suspicious";
    suggestedAction = "Proceed with caution. Verify the source before entering any personal information.";
  } else {
    label = "High Risk";
    suggestedAction = "Do not visit this URL. It shows multiple signs of being a phishing or malicious website.";
  }

  return {
    riskScore,
    label,
    url,
    heuristics,
    suggestedAction,
  };
};

const UrlScanner = () => {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleScan = async () => {
    if (!url.trim()) {
      toast.error("Please enter a URL to scan");
      return;
    }

    // Add protocol if missing
    let urlToScan = url.trim();
    if (!urlToScan.startsWith("http://") && !urlToScan.startsWith("https://")) {
      urlToScan = "https://" + urlToScan;
    }

    setIsScanning(true);
    setResult(null);

    // Simulate analysis delay
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const scanResult = analyzeUrl(urlToScan);
    setResult(scanResult);
    setIsScanning(false);

    if (scanResult.riskScore > 60) {
      toast.warning("High risk URL detected! Be careful.");
    } else if (scanResult.riskScore > 30) {
      toast.info("Some suspicious patterns detected.");
    } else {
      toast.success("URL appears to be safe!");
    }
  };

  const getResultType = () => {
    if (!result) return "info";
    if (result.riskScore <= 30) return "safe";
    if (result.riskScore <= 60) return "warning";
    return "danger";
  };

  return (
    <div className="min-h-screen pt-24 pb-12">
      <div className="container mx-auto px-4">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10 mb-6">
            <LinkIcon className="w-8 h-8 text-primary" />
          </div>
          <h1 className="font-display text-3xl md:text-4xl font-bold mb-4">
            URL <span className="text-gradient">Scanner</span>
          </h1>
          <p className="text-muted-foreground max-w-xl mx-auto">
            Check if a URL is safe before clicking. Our AI analyzes links for phishing 
            attempts, malware, and other threats.
          </p>
        </div>

        {/* Scanner Input */}
        <div className="max-w-2xl mx-auto mb-12">
          <div className="glass-card p-6 rounded-xl">
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="flex-1 relative">
                <LinkIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  type="text"
                  placeholder="Enter URL to scan (e.g., example.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleScan()}
                  className="pl-12"
                  disabled={isScanning}
                />
              </div>
              <Button
                variant="hero"
                onClick={handleScan}
                disabled={isScanning}
                className="sm:w-auto w-full"
              >
                <Shield className="w-4 h-4 mr-2" />
                {isScanning ? "Scanning..." : "Scan URL"}
              </Button>
            </div>

            {/* Example URLs */}
            <div className="mt-4 flex flex-wrap gap-2">
              <span className="text-xs text-muted-foreground">Try:</span>
              {["google.com", "suspicious-login.tk", "192.168.1.1/verify-account"].map((example) => (
                <button
                  key={example}
                  onClick={() => setUrl(example)}
                  className="text-xs text-primary hover:underline"
                >
                  {example}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Scanning Animation */}
        {isScanning && (
          <div className="max-w-2xl mx-auto">
            <ScanningAnimation />
          </div>
        )}

        {/* Results */}
        {result && !isScanning && (
          <div className="max-w-2xl mx-auto space-y-6">
            {/* Risk Score */}
            <div className="glass-card p-8 rounded-xl text-center">
              <RiskMeter score={result.riskScore} size="lg" />
              
              <div className="mt-6 p-4 bg-secondary/50 rounded-lg">
                <div className="flex items-center gap-2 mb-2 justify-center">
                  <ExternalLink className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">Scanned URL:</span>
                </div>
                <code className="text-sm text-foreground break-all">{result.url}</code>
              </div>
            </div>

            {/* Analysis Details */}
            <ResultCard
              type={getResultType()}
              title={result.label}
              description={result.suggestedAction}
              details={result.heuristics.map((h) => `${h.name}: ${h.description}`)}
            />

            {/* Heuristics Breakdown */}
            {result.heuristics.length > 0 && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-warning" />
                  Risk Factors Detected
                </h3>
                <div className="space-y-3">
                  {result.heuristics.map((h, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-secondary/30 rounded-lg">
                      <div>
                        <div className="font-medium text-sm">{h.name}</div>
                        <div className="text-xs text-muted-foreground">{h.description}</div>
                      </div>
                      <div className="text-sm font-medium text-destructive">+{h.score}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Scan Another */}
            <div className="text-center">
              <Button
                variant="outline"
                onClick={() => {
                  setResult(null);
                  setUrl("");
                }}
              >
                Scan Another URL
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UrlScanner;
