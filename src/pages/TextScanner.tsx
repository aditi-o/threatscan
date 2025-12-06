import { useState } from "react";
import { MessageSquare, Shield, AlertTriangle, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import RiskMeter from "@/components/RiskMeter";
import ResultCard from "@/components/ResultCard";
import ScanningAnimation from "@/components/ScanningAnimation";
import { toast } from "sonner";

interface ScanResult {
  riskScore: number;
  scamType: string;
  confidence: number;
  indicators: string[];
  suggestedAction: string;
}

// Scam pattern keywords
const scamPatterns = {
  digitalArrest: {
    keywords: ["police", "arrest", "warrant", "cyber crime", "money laundering", "verify identity", "legal action", "court", "aadhaar", "suspended"],
    label: "Digital Arrest Scam",
    description: "This appears to be a digital arrest scam where fraudsters impersonate law enforcement.",
  },
  upiScam: {
    keywords: ["upi", "payment", "refund", "cashback", "gpay", "paytm", "phonepe", "send money", "receive money", "wrong transfer", "accidental"],
    label: "UPI/Payment Scam",
    description: "This looks like a UPI payment scam designed to steal your money.",
  },
  jobScam: {
    keywords: ["work from home", "job offer", "earn daily", "part time", "guaranteed income", "no experience", "easy money", "registration fee", "typing job"],
    label: "Job Scam",
    description: "This appears to be a fake job offer scam asking for money or personal details.",
  },
  lottery: {
    keywords: ["lottery", "winner", "prize", "congratulations", "selected", "claim", "million", "processing fee", "lucky draw"],
    label: "Lottery/Prize Scam",
    description: "This is a lottery or prize scam designed to extract money from you.",
  },
  threatScam: {
    keywords: ["video", "recording", "leak", "expose", "embarrassing", "bitcoin", "pay now", "24 hours", "deadline", "compromising"],
    label: "Threat/Extortion Scam",
    description: "This is an extortion or sextortion scam trying to blackmail you.",
  },
  bankScam: {
    keywords: ["bank", "account blocked", "kyc", "update", "expire", "otp", "cvv", "card number", "verify", "suspended", "deactivate"],
    label: "Banking Scam",
    description: "This appears to be a banking phishing scam trying to steal your credentials.",
  },
};

const analyzeText = (text: string): ScanResult => {
  const lowerText = text.toLowerCase();
  let maxScore = 0;
  let detectedType = "Unknown";
  let detectedIndicators: string[] = [];
  let detectedDescription = "";

  // Check each scam pattern
  for (const [type, pattern] of Object.entries(scamPatterns)) {
    const matchedKeywords = pattern.keywords.filter((keyword) => lowerText.includes(keyword));
    const score = (matchedKeywords.length / pattern.keywords.length) * 100;

    if (score > maxScore && matchedKeywords.length >= 2) {
      maxScore = score;
      detectedType = pattern.label;
      detectedIndicators = matchedKeywords.map((k) => `Contains "${k}"`);
      detectedDescription = pattern.description;
    }
  }

  // Additional risk factors
  const urgencyWords = ["urgent", "immediately", "now", "today", "asap", "hurry", "quick"];
  const hasUrgency = urgencyWords.some((w) => lowerText.includes(w));
  if (hasUrgency) {
    maxScore += 15;
    detectedIndicators.push("Creates sense of urgency");
  }

  // Check for phone numbers
  const phonePattern = /\+?\d{10,13}/g;
  if (phonePattern.test(text)) {
    maxScore += 10;
    detectedIndicators.push("Contains phone number");
  }

  // Check for links
  const urlPattern = /(https?:\/\/|www\.)/gi;
  if (urlPattern.test(text)) {
    maxScore += 10;
    detectedIndicators.push("Contains external link");
  }

  // Check for money mentions
  const moneyPattern = /₹|rs\.?|rupees?|\$|usd/gi;
  if (moneyPattern.test(text)) {
    maxScore += 10;
    detectedIndicators.push("Mentions money");
  }

  // Cap score
  const riskScore = Math.min(Math.round(maxScore), 100);

  let suggestedAction: string;
  if (riskScore <= 30) {
    suggestedAction = "This message appears to be safe. However, always be cautious with unsolicited messages.";
    if (!detectedType || detectedType === "Unknown") {
      detectedType = "Safe";
    }
  } else if (riskScore <= 60) {
    suggestedAction = "This message has some suspicious patterns. Do not share personal information or make payments.";
  } else {
    suggestedAction = "This is likely a scam! Do not respond, click any links, or share any information. Block the sender.";
  }

  return {
    riskScore,
    scamType: detectedType,
    confidence: Math.min(riskScore + 20, 100),
    indicators: detectedIndicators,
    suggestedAction,
  };
};

const exampleMessages = [
  {
    label: "Digital Arrest",
    text: "URGENT: This is from Cyber Crime Department. Your Aadhaar is linked to money laundering. Arrest warrant issued. Verify identity immediately by calling this number or face legal action.",
  },
  {
    label: "UPI Scam",
    text: "Hi, I accidentally sent ₹5000 to your GPay. Please refund to this UPI ID immediately. I'm in urgent need. Check your account.",
  },
  {
    label: "Safe Message",
    text: "Hey! Hope you're doing well. Want to catch up for coffee this weekend? Let me know what works for you.",
  },
];

const TextScanner = () => {
  const [text, setText] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);

  const handleScan = async () => {
    if (!text.trim()) {
      toast.error("Please enter a message to analyze");
      return;
    }

    if (text.length < 10) {
      toast.error("Please enter a longer message for accurate analysis");
      return;
    }

    setIsScanning(true);
    setResult(null);

    // Simulate analysis delay
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const scanResult = analyzeText(text);
    setResult(scanResult);
    setIsScanning(false);

    if (scanResult.riskScore > 60) {
      toast.error("Scam detected! Do not respond to this message.");
    } else if (scanResult.riskScore > 30) {
      toast.warning("Suspicious patterns detected. Be careful!");
    } else {
      toast.success("Message appears to be safe!");
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
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-warning/10 mb-6">
            <MessageSquare className="w-8 h-8 text-warning" />
          </div>
          <h1 className="font-display text-3xl md:text-4xl font-bold mb-4">
            Text <span className="text-gradient">Scanner</span>
          </h1>
          <p className="text-muted-foreground max-w-xl mx-auto">
            Analyze suspicious messages, SMS, or WhatsApp texts for scam patterns. 
            Detect digital arrest scams, UPI fraud, and more.
          </p>
        </div>

        {/* Scanner Input */}
        <div className="max-w-2xl mx-auto mb-12">
          <div className="glass-card p-6 rounded-xl">
            <Textarea
              placeholder="Paste the suspicious message here..."
              value={text}
              onChange={(e) => setText(e.target.value)}
              className="min-h-[150px] mb-4"
              disabled={isScanning}
            />
            
            <div className="flex flex-col sm:flex-row gap-4">
              <Button
                variant="hero"
                onClick={handleScan}
                disabled={isScanning}
                className="flex-1"
              >
                <Shield className="w-4 h-4 mr-2" />
                {isScanning ? "Analyzing..." : "Analyze Message"}
              </Button>
              <Button
                variant="outline"
                onClick={() => setText("")}
                disabled={isScanning}
              >
                Clear
              </Button>
            </div>

            {/* Example Messages */}
            <div className="mt-6 pt-6 border-t border-border/30">
              <span className="text-xs text-muted-foreground block mb-3">Try example messages:</span>
              <div className="flex flex-wrap gap-2">
                {exampleMessages.map((example, index) => (
                  <button
                    key={index}
                    onClick={() => setText(example.text)}
                    className="text-xs px-3 py-1.5 rounded-full bg-secondary hover:bg-secondary/80 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {example.label}
                  </button>
                ))}
              </div>
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
            </div>

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
              <h3 className="font-display font-semibold text-lg mb-4 text-primary">
                Safety Tips
              </h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5" />
                  Never share OTPs, passwords, or bank details with anyone
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5" />
                  Government agencies never ask for money over phone/message
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5" />
                  If in doubt, contact the official organization directly
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5" />
                  Report scam messages to cybercrime.gov.in
                </li>
              </ul>
            </div>

            {/* Scan Another */}
            <div className="text-center">
              <Button
                variant="outline"
                onClick={() => {
                  setResult(null);
                  setText("");
                }}
              >
                Analyze Another Message
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TextScanner;
