import { useState, useRef } from "react";
import { Phone, Shield, AlertTriangle, CheckCircle, Upload, Mic, FileAudio } from "lucide-react";
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
  transcript: string;
  indicators: string[];
  suggestedAction: string;
  safetyTips: string[];
  modelVersion: string;
}

// Scam pattern keywords for audio transcript analysis
const scamPatterns = {
  digitalArrest: {
    keywords: ["police", "arrest", "warrant", "cyber crime", "money laundering", "verify identity", "legal action", "court", "aadhaar", "suspended", "cbi", "ed", "enforcement"],
    label: "Digital Arrest Scam",
    tips: ["Government agencies never call threatening arrest", "Never share personal details over phone", "Hang up and verify through official channels"],
  },
  techSupport: {
    keywords: ["microsoft", "computer", "virus", "infected", "remote access", "anydesk", "teamviewer", "hacked", "compromised", "tech support"],
    label: "Tech Support Scam",
    tips: ["Tech companies don't make unsolicited calls", "Never give remote access to strangers", "Don't share OTPs or passwords"],
  },
  bankingScam: {
    keywords: ["bank", "account blocked", "kyc", "otp", "cvv", "card number", "verify", "suspended", "deactivate", "rbi", "credit card", "debit card"],
    label: "Banking Scam",
    tips: ["Banks never ask for OTP or CVV", "Don't share card details on call", "Visit bank branch if in doubt"],
  },
  insuranceScam: {
    keywords: ["insurance", "policy", "matured", "bonus", "claim", "lapsed", "premium", "surrender", "lic", "irda"],
    label: "Insurance Scam",
    tips: ["Verify caller through official IRDA website", "Don't pay advance fees for claims", "Contact your insurance company directly"],
  },
  investmentScam: {
    keywords: ["investment", "guaranteed returns", "double money", "stock tips", "trading", "forex", "crypto", "bitcoin", "profit"],
    label: "Investment Scam",
    tips: ["No investment guarantees high returns", "Research before investing", "Check SEBI registration"],
  },
  impersonation: {
    keywords: ["relative", "son", "daughter", "accident", "hospital", "emergency", "help", "send money", "nephew", "grandson"],
    label: "Impersonation Scam",
    tips: ["Verify by calling the person directly", "Ask personal questions only they know", "Don't act in panic"],
  },
};

// Simulated transcript analysis (in production, this would use Whisper API)
const analyzeTranscript = (transcript: string): ScanResult => {
  const lowerText = transcript.toLowerCase();
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
      detectedIndicators = matchedKeywords.map((k) => `Detected keyword: "${k}"`);
      safetyTips = pattern.tips;
    }
  }

  // Additional risk factors
  const urgencyPhrases = ["urgent", "immediately", "right now", "today only", "last chance", "hurry"];
  const hasUrgency = urgencyPhrases.some((w) => lowerText.includes(w));
  if (hasUrgency) {
    maxScore += 15;
    detectedIndicators.push("Creates sense of urgency");
  }

  // Check for pressure tactics
  const pressurePhrases = ["don't tell anyone", "keep this secret", "don't hang up", "stay on the line"];
  const hasPressure = pressurePhrases.some((p) => lowerText.includes(p));
  if (hasPressure) {
    maxScore += 20;
    detectedIndicators.push("Uses pressure tactics");
  }

  // Check for money demands
  const moneyPhrases = ["transfer money", "send money", "pay now", "wire transfer", "gift card"];
  const hasMoney = moneyPhrases.some((m) => lowerText.includes(m));
  if (hasMoney) {
    maxScore += 25;
    detectedIndicators.push("Demands money transfer");
  }

  const riskScore = Math.min(Math.round(maxScore), 100);

  let suggestedAction: string;
  if (riskScore <= 30) {
    suggestedAction = "This call appears to be legitimate. However, always verify caller identity before sharing sensitive information.";
    if (!detectedType || detectedType === "Unknown") {
      detectedType = "Likely Safe";
    }
    safetyTips = ["Always verify unknown callers", "Don't share personal info unsolicited", "Trust your instincts"];
  } else if (riskScore <= 60) {
    suggestedAction = "This call has suspicious patterns. Do not share any personal or financial information. Verify the caller through official channels.";
  } else {
    suggestedAction = "HIGH ALERT! This is very likely a scam call. Hang up immediately. Do not share ANY information. Report to cyber crime helpline 1930.";
  }

  return {
    riskScore,
    scamType: detectedType,
    transcript,
    indicators: detectedIndicators,
    suggestedAction,
    safetyTips,
    modelVersion: "SafeLink-Audio-v1.0",
  };
};

// Simulated transcripts for demo purposes
const demoTranscripts = {
  digitalArrest: "Hello, this is officer Sharma from CBI cyber crime division. Your Aadhaar card has been linked to money laundering activities. There is an arrest warrant against you. You must verify your identity immediately by transferring a security deposit. Don't tell anyone about this call or you will be arrested today.",
  techSupport: "Hi, this is calling from Microsoft Windows support. Your computer has been infected with a dangerous virus. We detected suspicious activity from your IP address. Please install AnyDesk so we can remove the virus remotely. This is urgent, your data is at risk.",
  safe: "Hello, this is Dr. Patel's clinic calling to confirm your appointment scheduled for tomorrow at 3 PM. Please bring your previous reports. Let us know if you need to reschedule.",
};

const CallAnalyzer = () => {
  const [file, setFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      const validTypes = ["audio/wav", "audio/mp3", "audio/mpeg", "audio/m4a", "audio/aac", "audio/ogg", "audio/webm"];
      if (!validTypes.some(type => selectedFile.type.includes(type.split("/")[1]))) {
        toast.error("Please upload a valid audio file (WAV, MP3, M4A, AAC)");
        return;
      }
      if (selectedFile.size > 25 * 1024 * 1024) {
        toast.error("File size must be less than 25MB");
        return;
      }
      setFile(selectedFile);
      setResult(null);
      setDemoMode(false);
    }
  };

  const handleDemoAnalysis = async (type: keyof typeof demoTranscripts) => {
    setIsAnalyzing(true);
    setResult(null);
    setFile(null);
    setDemoMode(true);

    await new Promise((resolve) => setTimeout(resolve, 2500));

    const transcript = demoTranscripts[type];
    const scanResult = analyzeTranscript(transcript);
    setResult(scanResult);
    setIsAnalyzing(false);

    if (scanResult.riskScore > 60) {
      toast.error("Scam call detected! This call shows dangerous patterns.");
    } else if (scanResult.riskScore > 30) {
      toast.warning("Suspicious patterns detected in this call.");
    } else {
      toast.success("This call appears to be safe.");
    }
  };

  const handleAnalyze = async () => {
    if (!file) {
      toast.error("Please upload an audio file to analyze");
      return;
    }

    setIsAnalyzing(true);
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_BASE_URL}/scan/audio`, {
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
        transcript: data.transcript ?? "",
        indicators: data.reasons ?? [],
        suggestedAction: data.risk_score > 60 
          ? "HIGH ALERT! This is very likely a scam call. Hang up immediately. Report to cyber crime helpline 1930."
          : data.risk_score > 30 
          ? "This call has suspicious patterns. Do not share any personal or financial information."
          : "This call appears to be legitimate. However, always verify caller identity.",
        safetyTips: ["Never share OTP or passwords", "Verify caller through official channels", "Report suspicious calls to 1930"],
        modelVersion: data.model_version ?? "SafeLink-Audio-v1.0",
      };

      setResult(scanResult);
      setDemoMode(true); // Show transcript

      if (scanResult.riskScore > 60) {
        toast.error("Scam call detected! This call shows dangerous patterns.");
      } else if (scanResult.riskScore > 30) {
        toast.warning("Suspicious patterns detected in this call.");
      } else {
        toast.success("This call appears to be safe.");
      }
    } catch (error) {
      console.error("Analysis error:", error);
      toast.error(error instanceof Error ? error.message : "Failed to analyze audio. Is the backend running?");
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
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-destructive/10 mb-6">
            <Phone className="w-8 h-8 text-destructive" />
          </div>
          <h1 className="font-display text-3xl md:text-4xl font-bold mb-4">
            Call <span className="text-gradient">Analyzer</span>
          </h1>
          <p className="text-muted-foreground max-w-xl mx-auto">
            Upload a recorded call to detect scam patterns. Our AI transcribes and analyzes 
            conversations for digital arrest scams, banking fraud, and more.
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
                accept=".wav,.mp3,.m4a,.aac,.ogg,.webm,audio/*"
                onChange={handleFileChange}
                className="hidden"
              />
              
              {file ? (
                <div className="flex flex-col items-center gap-3">
                  <FileAudio className="w-12 h-12 text-primary" />
                  <div>
                    <p className="font-medium text-foreground">{file.name}</p>
                    <p className="text-sm text-muted-foreground">
                      {(file.size / (1024 * 1024)).toFixed(2)} MB
                    </p>
                  </div>
                  <Button variant="outline" size="sm" onClick={(e) => { e.stopPropagation(); setFile(null); }}>
                    Remove File
                  </Button>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-3">
                  <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                    <Upload className="w-8 h-8 text-primary" />
                  </div>
                  <div>
                    <p className="font-medium text-foreground">Click to upload audio file</p>
                    <p className="text-sm text-muted-foreground">WAV, MP3, M4A, AAC (max 25MB)</p>
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
                <Mic className="w-4 h-4 mr-2" />
                {isAnalyzing ? "Analyzing Call..." : "Analyze Call"}
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
                  Digital Arrest Scam
                </button>
                <button
                  onClick={() => handleDemoAnalysis("techSupport")}
                  disabled={isAnalyzing}
                  className="text-xs px-3 py-1.5 rounded-full bg-warning/10 text-warning hover:bg-warning/20 transition-colors disabled:opacity-50"
                >
                  Tech Support Scam
                </button>
                <button
                  onClick={() => handleDemoAnalysis("safe")}
                  disabled={isAnalyzing}
                  className="text-xs px-3 py-1.5 rounded-full bg-success/10 text-success hover:bg-success/20 transition-colors disabled:opacity-50"
                >
                  Safe Call
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

            {/* Transcript */}
            {demoMode && (
              <div className="glass-card p-6 rounded-xl">
                <h3 className="font-display font-semibold text-lg mb-4 flex items-center gap-2">
                  <FileAudio className="w-5 h-5 text-primary" />
                  Call Transcript
                </h3>
                <div className="p-4 bg-secondary/30 rounded-lg">
                  <p className="text-sm text-muted-foreground italic">"{result.transcript}"</p>
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
                  Report suspicious calls to Cyber Crime Helpline: 1930
                </li>
              </ul>
            </div>

            {/* Analyze Another */}
            <div className="text-center">
              <Button
                variant="outline"
                onClick={() => {
                  setResult(null);
                  setFile(null);
                  setDemoMode(false);
                }}
              >
                Analyze Another Call
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CallAnalyzer;
