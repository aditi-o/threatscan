import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { ThumbsUp, ThumbsDown, Flag, CheckCircle, Loader2 } from "lucide-react";
import { API_ENDPOINTS, apiRequest } from "@/lib/api";
import { toast } from "@/hooks/use-toast";

interface FeedbackFormProps {
  inputType: string;
  inputText: string;
  originalVerdict: string;
  scanId?: number;
  language?: string;
}

const LABELS = {
  en: {
    title: "Was this analysis correct?",
    correct: "Yes, correct",
    incorrect: "No, it's wrong",
    falsePositive: "This is actually safe",
    falseNegative: "This is actually dangerous",
    comment: "Additional comments (optional)",
    submit: "Submit Feedback",
    submitting: "Submitting...",
    thanks: "Thank you for your feedback!",
    thanksDesc: "Your input helps improve our detection accuracy.",
    error: "Failed to submit feedback",
  },
  hi: {
    title: "क्या यह विश्लेषण सही था?",
    correct: "हाँ, सही",
    incorrect: "नहीं, गलत है",
    falsePositive: "यह वास्तव में सुरक्षित है",
    falseNegative: "यह वास्तव में खतरनाक है",
    comment: "अतिरिक्त टिप्पणियाँ (वैकल्पिक)",
    submit: "प्रतिक्रिया जमा करें",
    submitting: "जमा हो रहा है...",
    thanks: "आपकी प्रतिक्रिया के लिए धन्यवाद!",
    thanksDesc: "आपका इनपुट हमारी पहचान सटीकता को बेहतर बनाने में मदद करता है।",
    error: "प्रतिक्रिया जमा करने में विफल",
  },
  mr: {
    title: "हे विश्लेषण बरोबर होते का?",
    correct: "होय, बरोबर",
    incorrect: "नाही, चुकीचे आहे",
    falsePositive: "हे खरोखर सुरक्षित आहे",
    falseNegative: "हे खरोखर धोकादायक आहे",
    comment: "अतिरिक्त टिप्पणी (पर्यायी)",
    submit: "अभिप्राय सबमिट करा",
    submitting: "सबमिट होत आहे...",
    thanks: "तुमच्या अभिप्रायाबद्दल धन्यवाद!",
    thanksDesc: "तुमचा इनपुट आमची शोध अचूकता सुधारण्यास मदत करतो.",
    error: "अभिप्राय सबमिट करण्यात अयशस्वी",
  },
};

export function FeedbackForm({
  inputType,
  inputText,
  originalVerdict,
  scanId,
  language = "en",
}: FeedbackFormProps) {
  const [step, setStep] = useState<"initial" | "details" | "submitted">("initial");
  const [userVerdict, setUserVerdict] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const labels = LABELS[language as keyof typeof LABELS] || LABELS.en;
  const isSafe = originalVerdict === "safe";

  const handleInitialResponse = (isCorrect: boolean) => {
    if (isCorrect) {
      setUserVerdict(originalVerdict);
      submitFeedback(originalVerdict, "");
    } else {
      setStep("details");
    }
  };

  const handleVerdictSelect = (verdict: string) => {
    setUserVerdict(verdict);
  };

  const submitFeedback = async (verdict: string, feedbackComment: string) => {
    setIsSubmitting(true);
    try {
      await apiRequest(API_ENDPOINTS.feedback, {
        method: "POST",
        body: JSON.stringify({
          scan_id: scanId,
          input_type: inputType,
          input_text: inputText,
          original_verdict: originalVerdict,
          user_verdict: verdict,
          comment: feedbackComment || null,
        }),
      });
      setStep("submitted");
      toast({
        title: labels.thanks,
        description: labels.thanksDesc,
      });
    } catch (error) {
      toast({
        title: labels.error,
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (step === "submitted") {
    return (
      <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
        <CheckCircle className="h-5 w-5 text-green-500" />
        <span className="text-sm text-green-400">{labels.thanks}</span>
      </div>
    );
  }

  if (step === "initial") {
    return (
      <div className="p-4 bg-muted/30 border border-border rounded-lg space-y-3">
        <p className="text-sm font-medium text-foreground">{labels.title}</p>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleInitialResponse(true)}
            className="flex items-center gap-2 hover:bg-green-500/10 hover:border-green-500/50"
          >
            <ThumbsUp className="h-4 w-4" />
            {labels.correct}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleInitialResponse(false)}
            className="flex items-center gap-2 hover:bg-destructive/10 hover:border-destructive/50"
          >
            <ThumbsDown className="h-4 w-4" />
            {labels.incorrect}
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 bg-muted/30 border border-border rounded-lg space-y-4">
      <div className="flex items-center gap-2">
        <Flag className="h-4 w-4 text-amber-500" />
        <p className="text-sm font-medium text-foreground">
          {isSafe ? labels.falseNegative : labels.falsePositive}?
        </p>
      </div>

      <div className="flex gap-2 flex-wrap">
        <Badge
          variant={userVerdict === "safe" ? "default" : "outline"}
          className={`cursor-pointer transition-all ${
            userVerdict === "safe"
              ? "bg-green-500 hover:bg-green-600"
              : "hover:bg-green-500/20"
          }`}
          onClick={() => handleVerdictSelect("safe")}
        >
          Safe
        </Badge>
        <Badge
          variant={userVerdict === "suspicious" ? "default" : "outline"}
          className={`cursor-pointer transition-all ${
            userVerdict === "suspicious"
              ? "bg-amber-500 hover:bg-amber-600"
              : "hover:bg-amber-500/20"
          }`}
          onClick={() => handleVerdictSelect("suspicious")}
        >
          Suspicious
        </Badge>
        <Badge
          variant={userVerdict === "malicious" ? "default" : "outline"}
          className={`cursor-pointer transition-all ${
            userVerdict === "malicious"
              ? "bg-destructive hover:bg-destructive/90"
              : "hover:bg-destructive/20"
          }`}
          onClick={() => handleVerdictSelect("malicious")}
        >
          Malicious
        </Badge>
      </div>

      <Textarea
        placeholder={labels.comment}
        value={comment}
        onChange={(e) => setComment(e.target.value)}
        className="min-h-[80px] bg-background/50"
      />

      <Button
        onClick={() => userVerdict && submitFeedback(userVerdict, comment)}
        disabled={!userVerdict || isSubmitting}
        className="w-full"
      >
        {isSubmitting ? (
          <>
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            {labels.submitting}
          </>
        ) : (
          labels.submit
        )}
      </Button>
    </div>
  );
}
