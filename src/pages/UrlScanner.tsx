import { useState } from "react";
import { Link as LinkIcon, Shield, ExternalLink, AlertTriangle, Globe, Lightbulb, Tag, Languages } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import RiskMeter from "@/components/RiskMeter";
import ResultCard from "@/components/ResultCard";
import ScanningAnimation from "@/components/ScanningAnimation";
import { toast } from "sonner";
import { API_ENDPOINTS, apiRequest } from "@/lib/api";

interface UrlBreakdown {
  full_host: string;
  subdomain: string;
  domain: string;
  tld: string;
  is_ip: boolean;
  registered_domain: string;
  path: string;
  port: string;
}

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
  attackPatterns: string[];
  urlBreakdown: UrlBreakdown | null;
  explanation: string;
  safetyTip: string;
  reasons: string[];
}

// Language options
const LANGUAGES = [
  { code: "en", name: "English", flag: "🇺🇸" },
  { code: "hi", name: "हिंदी", flag: "🇮🇳" },
  { code: "mr", name: "मराठी", flag: "🇮🇳" },
];

// URL heuristic analysis (local fallback)
const analyzeUrl = (url: string): ScanResult => {
  let riskScore = 0;
  const heuristics: ScanResult["heuristics"] = [];
  const attackPatterns: string[] = [];
  const reasons: string[] = [];

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const parts = hostname.split(".");

    // Check for HTTPS
    if (urlObj.protocol !== "https:") {
      riskScore += 25;
      heuristics.push({
        name: "No HTTPS",
        score: 25,
        description: "This URL does not use secure HTTPS protocol",
      });
      reasons.push("The link does not use secure HTTPS - your data may not be protected");
    }

    // Check for IP address in host
    const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
      riskScore += 30;
      heuristics.push({
        name: "IP Address Host",
        score: 30,
        description: "URL uses an IP address instead of a domain name",
      });
      attackPatterns.push("IP Address Instead of Domain");
      reasons.push("Using an IP address instead of a domain name is unusual and often malicious");
    }

    // Check for suspicious TLDs
    const suspiciousTlds = [".xyz", ".top", ".work", ".click", ".link", ".tk", ".ml", ".ga", ".cf"];
    if (suspiciousTlds.some((tld) => hostname.endsWith(tld))) {
      riskScore += 20;
      heuristics.push({
        name: "Suspicious TLD",
        score: 20,
        description: "Domain uses a top-level domain commonly associated with spam",
      });
      attackPatterns.push("Suspicious TLD");
      reasons.push("The domain uses a top-level domain commonly associated with spam or abuse");
    }

    // Check for double TLD
    const tldExtensions = ["com", "net", "org", "edu", "gov", "co"];
    const tldCount = parts.filter(p => tldExtensions.includes(p)).length;
    if (tldCount >= 2) {
      riskScore += 25;
      heuristics.push({
        name: "Double TLD",
        score: 25,
        description: "URL contains multiple TLD extensions like .com.com",
      });
      attackPatterns.push("Double TLD Deception");
      reasons.push("The link contains more than one extension (like .com.com), which is commonly used in phishing");
    }

    // Check for very long URL
    if (url.length > 100) {
      riskScore += 10;
      heuristics.push({
        name: "Long URL",
        score: 10,
        description: "Unusually long URL may indicate URL obfuscation",
      });
      reasons.push("Unusually long URLs may be trying to hide malicious parts");
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
    const subdomains = parts.length - 2;
    if (subdomains > 2) {
      riskScore += 15;
      heuristics.push({
        name: "Multiple Subdomains",
        score: 15,
        description: "URL has many subdomains, which can be used to hide the real domain",
      });
      attackPatterns.push("Excessive Dots");
      reasons.push("Excessive dots suggest an attempt to hide the real domain");
    }

    // Check for excessive hyphens
    if (hostname.split("-").length > 3) {
      riskScore += 10;
      heuristics.push({
        name: "Excessive Hyphens",
        score: 10,
        description: "Domain contains many hyphens which is suspicious",
      });
      attackPatterns.push("Excessive Hyphens");
      reasons.push("Too many hyphens in the domain make it look suspicious");
    }

    // Check for brand in subdomain
    const brands = ["google", "facebook", "amazon", "microsoft", "paypal", "netflix", "apple"];
    const domain = parts.length >= 2 ? parts[parts.length - 2] : "";
    const subdomain = parts.slice(0, -2).join(".");
    
    for (const brand of brands) {
      if (subdomain.includes(brand) && !domain.includes(brand)) {
        riskScore += 30;
        heuristics.push({
          name: "Brand Impersonation",
          score: 30,
          description: `Brand "${brand}" appears in subdomain but not in main domain`,
        });
        attackPatterns.push("Brand Impersonation");
        reasons.push("The brand name appears in the subdomain, not the real domain - this is a common trick");
        break;
      }
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
  let explanation: string;
  let safetyTip: string;

  if (riskScore <= 30) {
    label = "Safe";
    suggestedAction = "This URL appears to be safe to visit. Always remain cautious with personal information.";
    explanation = "This link appears to be legitimate with no obvious signs of deception.";
    safetyTip = "Verify the URL by hovering over links before clicking, and look for the lock icon in your browser.";
  } else if (riskScore <= 60) {
    label = "Suspicious";
    suggestedAction = "Proceed with caution. Verify the source before entering any personal information.";
    explanation = "This link shows some signs of being potentially misleading or unsafe.";
    safetyTip = "When in doubt, go directly to the official website by typing the address yourself.";
  } else {
    label = "High Risk";
    suggestedAction = "Do not visit this URL. It shows multiple signs of being a phishing or malicious website.";
    explanation = "This link is designed to look legitimate but is actually controlled by a different domain.";
    safetyTip = "If a link uses a brand name but does not end with the official domain, avoid clicking it.";
  }

  // Build URL breakdown
  let urlBreakdown: UrlBreakdown | null = null;
  try {
    const urlObj = new URL(url);
    const parts = urlObj.hostname.split(".");
    urlBreakdown = {
      full_host: urlObj.hostname,
      subdomain: parts.length > 2 ? parts.slice(0, -2).join(".") : "",
      domain: parts.length >= 2 ? parts[parts.length - 2] : parts[0],
      tld: parts.length >= 2 ? parts[parts.length - 1] : "",
      is_ip: /^(?:\d{1,3}\.){3}\d{1,3}$/.test(urlObj.hostname),
      registered_domain: parts.length >= 2 ? `${parts[parts.length - 2]}.${parts[parts.length - 1]}` : urlObj.hostname,
      path: urlObj.pathname,
      port: urlObj.port,
    };
  } catch {
    // Leave as null
  }

  return {
    riskScore,
    label,
    url,
    heuristics,
    suggestedAction,
    attackPatterns,
    urlBreakdown,
    explanation,
    safetyTip,
    reasons: reasons.length > 0 ? reasons : ["No suspicious patterns detected"],
  };
};

const UrlScanner = () => {
  const [url, setUrl] = useState("");
  const [language, setLanguage] = useState("en");
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

    try {
      const data = await apiRequest<{
        risk_score: number;
        label: string;
        input_text: string;
        reasons: string[];
        suggestions: string[];
        is_safe: boolean;
        attack_patterns: string[];
        url_breakdown: UrlBreakdown | null;
        explanation: string;
        safety_tip: string;
      }>(API_ENDPOINTS.scanUrl, {
        method: "POST",
        body: JSON.stringify({ content: urlToScan, language }),
      });

      // Convert backend response to frontend format
      const scanResult: ScanResult = {
        riskScore: data.risk_score,
        label: data.label,
        url: data.input_text,
        heuristics: data.reasons.map((reason, idx) => ({
          name: reason.split(":")[0] || `Finding ${idx + 1}`,
          score: Math.round(data.risk_score / Math.max(data.reasons.length, 1)),
          description: reason,
        })),
        suggestedAction: data.suggestions[0] || 
          (data.risk_score > 60 
            ? "Do not visit this URL. It shows multiple signs of being malicious."
            : data.risk_score > 30 
            ? "Proceed with caution. Verify the source before entering personal information."
            : "This URL appears to be safe to visit."),
        attackPatterns: data.attack_patterns || [],
        urlBreakdown: data.url_breakdown,
        explanation: data.explanation || "",
        safetyTip: data.safety_tip || "",
        reasons: data.reasons,
      };

      setResult(scanResult);

      if (scanResult.riskScore > 60) {
        toast.warning("High risk URL detected! Be careful.");
      } else if (scanResult.riskScore > 30) {
        toast.info("Some suspicious patterns detected.");
      } else {
        toast.success("URL appears to be safe!");
      }
    } catch (error) {
      console.error("Scan error:", error);
      // Fallback to local analysis if backend is unavailable
      const localResult = analyzeUrl(urlToScan);
      setResult(localResult);
      toast.info("Using local analysis (backend unavailable)");
    } finally {
      setIsScanning(false);
    }
  };

  const getResultType = () => {
    if (!result) return "info";
    if (result.riskScore <= 30) return "safe";
    if (result.riskScore <= 60) return "warning";
    return "danger";
  };

  const getPatternBadgeVariant = (pattern: string) => {
    const highRisk = ["Double TLD", "Brand Impersonation", "IP Address"];
    const mediumRisk = ["Excessive", "Suspicious TLD"];
    
    if (highRisk.some(p => pattern.includes(p))) return "destructive";
    if (mediumRisk.some(p => pattern.includes(p))) return "secondary";
    return "outline";
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
            <div className="flex flex-col gap-4">
              {/* Language Selector */}
              <div className="flex items-center gap-2">
                <Languages className="w-4 h-4 text-muted-foreground" />
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Language" />
                  </SelectTrigger>
                  <SelectContent>
                    {LANGUAGES.map((lang) => (
                      <SelectItem key={lang.code} value={lang.code}>
                        <span className="flex items-center gap-2">
                          <span>{lang.flag}</span>
                          <span>{lang.name}</span>
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* URL Input */}
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
            </div>

            {/* Example URLs */}
            <div className="mt-4 flex flex-wrap gap-2">
              <span className="text-xs text-muted-foreground">Try:</span>
              {["google.com", "google.com.com", "paypal.secure-login.tk", "192.168.1.1/verify-account"].map((example) => (
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

            {/* URL Breakdown */}
            {result.urlBreakdown && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
                  <Globe className="w-5 h-5 text-primary" />
                  URL Breakdown
                </h3>
                <div className="flex flex-wrap items-center gap-1 text-sm font-mono bg-secondary/30 p-4 rounded-lg">
                  {result.urlBreakdown.subdomain && (
                    <>
                      <span className="px-2 py-1 bg-warning/20 text-warning rounded border border-warning/30">
                        {result.urlBreakdown.subdomain}
                      </span>
                      <span className="text-muted-foreground">.</span>
                    </>
                  )}
                  <span className="px-2 py-1 bg-primary/20 text-primary rounded border border-primary/30 font-bold">
                    {result.urlBreakdown.domain}
                  </span>
                  <span className="text-muted-foreground">.</span>
                  <span className="px-2 py-1 bg-secondary text-foreground rounded border">
                    {result.urlBreakdown.tld}
                  </span>
                  {result.urlBreakdown.port && (
                    <>
                      <span className="text-muted-foreground">:</span>
                      <span className="px-2 py-1 bg-destructive/20 text-destructive rounded border border-destructive/30">
                        {result.urlBreakdown.port}
                      </span>
                    </>
                  )}
                  {result.urlBreakdown.path && result.urlBreakdown.path !== "/" && (
                    <span className="text-muted-foreground ml-1">{result.urlBreakdown.path}</span>
                  )}
                </div>
                <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted-foreground">
                  <div className="flex items-center gap-1">
                    <span className="w-3 h-3 bg-warning/20 border border-warning/30 rounded" />
                    <span>Subdomain</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="w-3 h-3 bg-primary/20 border border-primary/30 rounded" />
                    <span>Real Domain</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="w-3 h-3 bg-secondary border rounded" />
                    <span>TLD</span>
                  </div>
                </div>
              </div>
            )}

            {/* Attack Patterns */}
            {result.attackPatterns && result.attackPatterns.length > 0 && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
                  <Tag className="w-5 h-5 text-destructive" />
                  Attack Patterns Detected
                </h3>
                <div className="flex flex-wrap gap-2">
                  {result.attackPatterns.map((pattern, index) => (
                    <Badge 
                      key={index} 
                      variant={getPatternBadgeVariant(pattern)}
                      className="text-sm py-1.5 px-3"
                    >
                      {pattern}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Explanation */}
            {result.explanation && (
              <div className="glass-card p-6 rounded-xl border-l-4 border-primary">
                <p className="text-foreground">{result.explanation}</p>
              </div>
            )}

            {/* Analysis Details */}
            <ResultCard
              type={getResultType()}
              title={result.label}
              description={result.suggestedAction}
              details={result.reasons}
            />

            {/* Safety Tip */}
            {result.safetyTip && (
              <div className="glass-card p-6 rounded-xl bg-primary/5 border border-primary/20">
                <h3 className="font-display font-semibold text-lg mb-3 flex items-center gap-2">
                  <Lightbulb className="w-5 h-5 text-primary" />
                  Safety Tip
                </h3>
                <p className="text-muted-foreground">{result.safetyTip}</p>
              </div>
            )}

            {/* Heuristics Breakdown */}
            {result.heuristics.length > 0 && result.riskScore > 0 && (
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
