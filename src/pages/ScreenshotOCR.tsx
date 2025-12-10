import { useState, useRef } from "react";
import { Image, Shield, AlertTriangle, CheckCircle, Upload, ScanLine } from "lucide-react";
import { Button } from "@/components/ui/button";
import RiskMeter from "@/components/RiskMeter";
import ResultCard from "@/components/ResultCard";
import ScanningAnimation from "@/components/ScanningAnimation";
import { toast } from "sonner";

// Backend API base URL
const API_BASE_URL = "http://localhost:8000";

interface ScanResult {
  riskScore: number;
  scamType: string;
  extractedText: string;
  indicators: string[];
  suggestedAction: string;
  safetyTips: string[];
  modelVersion: string;
}

// Scam pattern keywords for OCR text analysis
const scamPatterns = {
  digitalArrest: {
    keywords: ["police", "arrest", "warrant", "cyber crime", "money laundering", "verify identity", "legal action", "court", "aadhaar", "suspended", "cbi", "enforcement directorate"],
    label: "Digital Arrest Scam",
    tips: ["Government agencies never send arrest notices via WhatsApp", "Don't respond to threatening messages", "Report to cybercrime.gov.in"],
  },
  upiScam: {
    keywords: ["upi", "payment", "refund", "cashback", "gpay", "paytm", "phonepe", "send money", "receive money", "wrong transfer", "accidental", "qr code"],
    label: "UPI/Payment Scam",
    tips: ["Never scan QR codes from unknown sources", "You don't need to 'receive' money - it comes automatically", "Don't share UPI PIN with anyone"],
  },
  jobScam: {
    keywords: ["work from home", "job offer", "earn daily", "part time", "guaranteed income", "no experience", "easy money", "registration fee", "typing job", "data entry"],
    label: "Job Scam",
    tips: ["Legitimate jobs never ask for upfront payment", "Research the company before applying", "Be wary of 'too good to be true' offers"],
  },
  lotteryScam: {
    keywords: ["lottery", "winner", "prize", "congratulations", "selected", "claim", "million", "processing fee", "lucky draw", "jackpot"],
    label: "Lottery/Prize Scam",
    tips: ["You can't win a lottery you didn't enter", "Never pay 'processing fees' to claim prizes", "Legitimate prizes don't require advance payment"],
  },
  bankingScam: {
    keywords: ["bank", "account blocked", "kyc", "update", "expire", "otp", "cvv", "card number", "verify", "suspended", "deactivate", "credit limit"],
    label: "Banking Scam",
    tips: ["Banks never ask for OTP, CVV, or passwords", "Visit your bank branch for KYC updates", "Don't click links in SMS - use official app"],
  },
  investmentScam: {
    keywords: ["investment", "guaranteed returns", "double money", "stock tips", "trading group", "forex", "crypto", "bitcoin", "profit guarantee", "telegram group"],
    label: "Investment Scam",
    tips: ["No investment can guarantee fixed returns", "Check SEBI registration before investing", "Be wary of social media investment groups"],
  },
};

// Analyze extracted text for scam patterns
const analyzeExtractedText = (text: string): ScanResult => {
  const lowerText = text.toLowerCase();
  let maxScore = 0;
  let detectedType = "Unknown";
  let detectedIndicators: string[] = [];
  let safetyTips: string[] = [];

  // Check each scam pattern
  for (const [_, pattern] of Object.entries(scamPatterns)) {
    const matchedKeywords = pattern.keywords.filter((keyword) => lowerText.includes(keyword));
    const score = (matchedKeywords.length / pattern.keywords.length) * 100;

    if (score > maxScore && matchedKeywords.length >= 2) {
      maxScore = score;
      detectedType = pattern.label;
      detectedIndicators = matchedKeywords.map((k) => `Found: "${k}"`);
      safetyTips = pattern.tips;
    }
  }

  // Additional risk factors
  const urgencyWords = ["urgent", "immediately", "now", "today", "expires", "last chance", "hurry", "24 hours"];
  const hasUrgency = urgencyWords.some((w) => lowerText.includes(w));
  if (hasUrgency) {
    maxScore += 15;
    detectedIndicators.push("Creates false urgency");
  }

  // Check for phone numbers
  const phonePattern = /\+?\d{10,13}/g;
  if (phonePattern.test(text)) {
    maxScore += 10;
    detectedIndicators.push("Contains phone number");
  }

  // Check for links
  const urlPattern = /(https?:\/\/|www\.|bit\.ly|tinyurl)/gi;
  if (urlPattern.test(text)) {
    maxScore += 15;
    detectedIndicators.push("Contains suspicious links");
  }

  // Check for money mentions
  const moneyPattern = /₹|rs\.?|rupees?|\$|usd|lakhs?|crores?/gi;
  if (moneyPattern.test(text)) {
    maxScore += 10;
    detectedIndicators.push("Mentions money amounts");
  }

  // Check for action demands
  const actionWords = ["click here", "call now", "send money", "pay immediately", "transfer", "share otp"];
  const hasAction = actionWords.some((a) => lowerText.includes(a));
  if (hasAction) {
    maxScore += 20;
    detectedIndicators.push("Demands immediate action");
  }

  const riskScore = Math.min(Math.round(maxScore), 100);

  let suggestedAction: string;
  if (riskScore <= 30) {
    suggestedAction = "This screenshot appears to be safe. No major scam indicators detected.";
    if (!detectedType || detectedType === "Unknown") {
      detectedType = "Likely Safe";
    }
    safetyTips = ["Always verify sender identity", "Don't share personal info with strangers", "When in doubt, don't engage"];
  } else if (riskScore <= 60) {
    suggestedAction = "This screenshot has suspicious patterns. Do not respond or click any links. Verify through official channels.";
  } else {
    suggestedAction = "DANGER! This is very likely a scam message. Do NOT respond, click links, or share any information. Block and report immediately.";
  }

  return {
    riskScore,
    scamType: detectedType,
    extractedText: text,
    indicators: detectedIndicators,
    suggestedAction,
    safetyTips,
    modelVersion: "SafeLink-OCR-v1.0",
  };
};

// Demo screenshots with simulated extracted text
const demoScreenshots = {
  digitalArrest: "⚠️ URGENT NOTICE\n\nDear Citizen,\n\nThis is to inform you that your Aadhaar number is linked to illegal money laundering activities.\n\nA non-bailable arrest warrant has been issued against you by the Cyber Crime Division.\n\nTo verify your identity and avoid arrest, contact our officer immediately at +91-98XXXXXXXX.\n\nWarning: Do not share this message. Your case is under surveillance.\n\n- CBI Cyber Crime Cell",
  upiScam: "Hello! 🙏\n\nI accidentally sent ₹5,000 to your GPay account by mistake.\n\nPlease scan this QR code to refund the money immediately.\n\nI really need this money urgently for my mother's treatment 😢\n\nPlease help! Call me: +91-87XXXXXXXX\n\nThank you 🙏",
  safe: "📢 Reminder\n\nYour electricity bill of ₹1,250 for December 2024 is due on 15th.\n\nPay online at www.bescom.karnataka.gov.in or visit any authorized payment center.\n\nConsumer Number: 123456789\n\nThank you for being a valued customer.\n\n- BESCOM",
};

const ScreenshotOCR = () => {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (!selectedFile.type.startsWith("image/")) {
        toast.error("Please upload an image file");
        return;
      }
      if (selectedFile.size > 10 * 1024 * 1024) {
        toast.error("File size must be less than 10MB");
        return;
      }
      setFile(selectedFile);
      setPreview(URL.createObjectURL(selectedFile));
      setResult(null);
      setDemoMode(false);
    }
  };

  const handleDemoAnalysis = async (type: keyof typeof demoScreenshots) => {
    setIsAnalyzing(true);
    setResult(null);
    setFile(null);
    setPreview(null);
    setDemoMode(true);

    await new Promise((resolve) => setTimeout(resolve, 2000));

    const extractedText = demoScreenshots[type];
    const scanResult = analyzeExtractedText(extractedText);
    setResult(scanResult);
    setIsAnalyzing(false);

    if (scanResult.riskScore > 60) {
      toast.error("Scam detected! This screenshot contains dangerous content.");
    } else if (scanResult.riskScore > 30) {
      toast.warning("Suspicious content detected in screenshot.");
    } else {
      toast.success("Screenshot content appears to be safe.");
    }
  };

  const handleAnalyze = async () => {
    if (!file) {
      toast.error("Please upload a screenshot to analyze");
      return;
    }

    setIsAnalyzing(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_BASE_URL}/scan/screenshot`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server error: ${response.status}`);
      }

      const data = await response.json();
      
      const scanResult: ScanResult = {
        riskScore: data.risk_score ?? 0,
        scamType: data.label ?? "Unknown",
        extractedText: data.text ?? "",
        indicators: data.reasons ?? [],
        suggestedAction: data.risk_score > 60 
          ? "DANGER! This is very likely a scam message. Do NOT respond or click any links."
          : data.risk_score > 30 
          ? "This screenshot has suspicious patterns. Verify through official channels."
          : "This screenshot appears to be safe. No major scam indicators detected.",
        safetyTips: ["Don't click links in suspicious messages", "Verify sender through official channels", "Report scams at cybercrime.gov.in"],
        modelVersion: data.model_version ?? "SafeLink-OCR-v1.0",
      };

      setResult(scanResult);
      setDemoMode(true); // Show extracted text

      if (scanResult.riskScore > 60) {
        toast.error("Scam detected! This screenshot contains dangerous content.");
      } else if (scanResult.riskScore > 30) {
        toast.warning("Suspicious content detected in screenshot.");
      } else {
        toast.success("Screenshot content appears to be safe.");
      }
    } catch (error) {
      console.error("Analysis error:", error);
      toast.error(error instanceof Error ? error.message : "Failed to analyze screenshot. Is the backend running?");
    } finally {
      setIsAnalyzing(false);
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
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-accent/10 mb-6">
            <Image className="w-8 h-8 text-accent" />
          </div>
          <h1 className="font-display text-3xl md:text-4xl font-bold mb-4">
            Screenshot <span className="text-gradient">OCR Scanner</span>
          </h1>
          <p className="text-muted-foreground max-w-xl mx-auto">
            Upload a screenshot of suspicious messages to extract and analyze text. 
            Detect scams in WhatsApp, SMS, emails, and more.
          </p>
        </div>

        {/* Upload Section */}
        <div className="max-w-2xl mx-auto mb-12">
          <div className="glass-card p-6 rounded-xl">
            {/* File Upload Area */}
            <div 
              className="border-2 border-dashed border-border/50 rounded-xl p-8 text-center hover:border-primary/50 transition-colors cursor-pointer"
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileChange}
                className="hidden"
              />
              
              {preview ? (
                <div className="flex flex-col items-center gap-4">
                  <img 
                    src={preview} 
                    alt="Screenshot preview" 
                    className="max-h-48 rounded-lg border border-border/30 object-contain"
                  />
                  <div>
                    <p className="font-medium text-foreground">{file?.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {file && (file.size / (1024 * 1024)).toFixed(2)} MB
                    </p>
                  </div>
                  <Button variant="outline" size="sm" onClick={(e) => { 
                    e.stopPropagation(); 
                    setFile(null); 
                    setPreview(null);
                    if (preview) URL.revokeObjectURL(preview);
                  }}>
                    Remove Image
                  </Button>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-3">
                  <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                    <Upload className="w-8 h-8 text-primary" />
                  </div>
                  <div>
                    <p className="font-medium text-foreground">Click to upload screenshot</p>
                    <p className="text-sm text-muted-foreground">PNG, JPG, WEBP (max 10MB)</p>
                  </div>
                </div>
              )}
            </div>

            {/* Analyze Button */}
            <div className="mt-6">
              <Button
                variant="hero"
                onClick={handleAnalyze}
                disabled={isAnalyzing || !file}
                className="w-full"
              >
                <ScanLine className="w-4 h-4 mr-2" />
                {isAnalyzing ? "Scanning Screenshot..." : "Scan Screenshot"}
              </Button>
            </div>

            {/* Demo Examples */}
            <div className="mt-6 pt-6 border-t border-border/30">
              <span className="text-xs text-muted-foreground block mb-3">Or try demo examples:</span>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => handleDemoAnalysis("digitalArrest")}
                  disabled={isAnalyzing}
                  className="text-xs px-3 py-1.5 rounded-full bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors disabled:opacity-50"
                >
                  Digital Arrest Notice
                </button>
                <button
                  onClick={() => handleDemoAnalysis("upiScam")}
                  disabled={isAnalyzing}
                  className="text-xs px-3 py-1.5 rounded-full bg-warning/10 text-warning hover:bg-warning/20 transition-colors disabled:opacity-50"
                >
                  UPI Refund Scam
                </button>
                <button
                  onClick={() => handleDemoAnalysis("safe")}
                  disabled={isAnalyzing}
                  className="text-xs px-3 py-1.5 rounded-full bg-success/10 text-success hover:bg-success/20 transition-colors disabled:opacity-50"
                >
                  Legitimate Notice
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Scanning Animation */}
        {isAnalyzing && (
          <div className="max-w-2xl mx-auto">
            <ScanningAnimation />
          </div>
        )}

        {/* Results */}
        {result && !isAnalyzing && (
          <div className="max-w-2xl mx-auto space-y-6">
            {/* Risk Score */}
            <div className="glass-card p-8 rounded-xl text-center">
              <RiskMeter score={result.riskScore} size="lg" />
              
              <div className="mt-6">
                <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-full ${
                  result.riskScore > 60 
                    ? "bg-destructive/10 text-destructive" 
                    : result.riskScore > 30 
                    ? "bg-warning/10 text-warning"
                    : "bg-success/10 text-success"
                }`}>
                  {result.riskScore > 30 ? (
                    <AlertTriangle className="w-4 h-4" />
                  ) : (
                    <CheckCircle className="w-4 h-4" />
                  )}
                  <span className="font-medium">{result.scamType}</span>
                </div>
              </div>

              <div className="mt-4 text-xs text-muted-foreground">
                Model: {result.modelVersion}
              </div>
            </div>

            {/* Extracted Text */}
            {demoMode && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
                  <ScanLine className="w-5 h-5 text-primary" />
                  Extracted Text (OCR)
                </h3>
                <div className="p-4 bg-secondary/30 rounded-lg">
                  <pre className="text-sm text-muted-foreground whitespace-pre-wrap font-mono">
                    {result.extractedText}
                  </pre>
                </div>
              </div>
            )}

            {/* Analysis Result */}
            <ResultCard
              type={getResultType()}
              title={result.scamType}
              description={result.suggestedAction}
              details={result.indicators}
            />

            {/* Indicators */}
            {result.indicators.length > 0 && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="font-display font-semibold text-lg mb-4">
                  Detection Analysis
                </h3>
                <div className="grid gap-3">
                  {result.indicators.map((indicator, index) => (
                    <div
                      key={index}
                      className="flex items-center gap-3 p-3 bg-secondary/30 rounded-lg"
                    >
                      <div className={`w-2 h-2 rounded-full ${
                        result.riskScore > 60 ? "bg-destructive" : "bg-warning"
                      }`} />
                      <span className="text-sm">{indicator}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Safety Tips */}
            <div className="glass-card p-6 rounded-xl bg-primary/5 border-primary/20">
              <h3 className="font-display font-semibold text-lg mb-4 text-primary flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Safety Actions
              </h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                {result.safetyTips.map((tip, index) => (
                  <li key={index} className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                    {tip}
                  </li>
                ))}
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  Report scam messages at cybercrime.gov.in
                </li>
              </ul>
            </div>

            {/* Scan Another */}
            <div className="text-center">
              <Button
                variant="outline"
                onClick={() => {
                  setResult(null);
                  setFile(null);
                  if (preview) URL.revokeObjectURL(preview);
                  setPreview(null);
                  setDemoMode(false);
                }}
              >
                Scan Another Screenshot
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ScreenshotOCR;
