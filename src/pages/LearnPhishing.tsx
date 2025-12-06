import { 
  Shield, 
  AlertTriangle, 
  Mail, 
  Link as LinkIcon, 
  Phone, 
  MessageSquare, 
  Eye, 
  Lock, 
  CheckCircle,
  XCircle,
  ArrowRight
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

const tactics = [
  {
    icon: Mail,
    title: "Email Phishing",
    description: "Fraudulent emails that appear to be from reputable companies, urging you to click links or provide personal information.",
    examples: [
      "Fake password reset requests",
      "Urgent account suspension notices",
      "Prize or lottery winning notifications",
    ],
    color: "primary",
  },
  {
    icon: MessageSquare,
    title: "SMS Phishing (Smishing)",
    description: "Text messages containing malicious links or requests for sensitive data, often impersonating banks or delivery services.",
    examples: [
      "Package delivery failure alerts",
      "Bank fraud alert texts",
      "Two-factor authentication bypass attempts",
    ],
    color: "warning",
  },
  {
    icon: Phone,
    title: "Voice Phishing (Vishing)",
    description: "Phone calls from scammers pretending to be from trusted organizations to extract personal or financial information.",
    examples: [
      "IRS or tax agency impersonation",
      "Tech support scam calls",
      "Bank security department calls",
    ],
    color: "destructive",
  },
  {
    icon: LinkIcon,
    title: "Clone Phishing",
    description: "Attackers create nearly identical copies of legitimate emails you've received, replacing links with malicious ones.",
    examples: [
      "Cloned shipping confirmations",
      "Duplicate invoice emails",
      "Copied newsletter links",
    ],
    color: "accent",
  },
];

const redFlags = [
  {
    icon: AlertTriangle,
    title: "Urgency & Threats",
    description: "Messages creating panic about account closure, legal action, or missed opportunities.",
  },
  {
    icon: Eye,
    title: "Suspicious URLs",
    description: "Hover over links to check for misspellings, extra characters, or unfamiliar domains.",
  },
  {
    icon: XCircle,
    title: "Generic Greetings",
    description: "\"Dear Customer\" instead of your actual name indicates a mass phishing attempt.",
  },
  {
    icon: Lock,
    title: "Requests for Sensitive Info",
    description: "Legitimate companies never ask for passwords or full credit card numbers via email.",
  },
];

const safetyTips = [
  "Verify sender email addresses carefully - look for subtle misspellings",
  "Never click links directly from emails - type the URL manually",
  "Enable two-factor authentication on all accounts",
  "Keep your software and antivirus up to date",
  "Report suspicious emails to your IT department or email provider",
  "Use our URL Scanner to check suspicious links before clicking",
];

const LearnPhishing = () => {
  return (
    <main className="min-h-screen pt-24 pb-16">
      {/* Hero Section */}
      <section className="relative py-12">
        <div className="absolute inset-0 hero-glow pointer-events-none" />
        <div className="container mx-auto px-4">
          <div className="text-center max-w-3xl mx-auto">
            <Badge variant="outline" className="mb-4 border-primary/50 text-primary">
              <Shield className="w-3 h-3 mr-1" />
              Security Education
            </Badge>
            <h1 className="font-display text-4xl md:text-5xl font-bold mb-6">
              Learn to Identify{" "}
              <span className="text-gradient">Phishing Scams</span>
            </h1>
            <p className="text-muted-foreground text-lg mb-8">
              Understanding common phishing tactics is your first line of defense. 
              Learn how to recognize and avoid these threats to keep your data safe.
            </p>
          </div>
        </div>
      </section>

      {/* Common Tactics Section */}
      <section className="py-12">
        <div className="container mx-auto px-4">
          <h2 className="font-display text-2xl md:text-3xl font-bold text-center mb-10">
            Common Phishing Tactics
          </h2>
          <div className="grid md:grid-cols-2 gap-6">
            {tactics.map((tactic, index) => {
              const Icon = tactic.icon;
              return (
                <Card key={index} className="glass-card overflow-hidden group hover:border-primary/50 transition-all duration-300">
                  <CardHeader className="pb-3">
                    <div className="flex items-start gap-4">
                      <div className={`p-3 rounded-lg bg-${tactic.color}/10 text-${tactic.color}`}>
                        <Icon className="w-6 h-6" />
                      </div>
                      <div>
                        <CardTitle className="font-display text-xl mb-2">
                          {tactic.title}
                        </CardTitle>
                        <p className="text-muted-foreground text-sm">
                          {tactic.description}
                        </p>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="pl-16">
                      <p className="text-xs uppercase tracking-wider text-muted-foreground mb-2">
                        Common Examples:
                      </p>
                      <ul className="space-y-1">
                        {tactic.examples.map((example, i) => (
                          <li key={i} className="text-sm text-foreground/80 flex items-center gap-2">
                            <span className="w-1 h-1 rounded-full bg-primary" />
                            {example}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      {/* Red Flags Section */}
      <section className="py-12 bg-secondary/20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-10">
            <Badge variant="destructive" className="mb-4">
              <AlertTriangle className="w-3 h-3 mr-1" />
              Warning Signs
            </Badge>
            <h2 className="font-display text-2xl md:text-3xl font-bold">
              Red Flags to Watch For
            </h2>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {redFlags.map((flag, index) => {
              const Icon = flag.icon;
              return (
                <Card key={index} className="glass-card text-center p-6 hover:glow-destructive transition-all duration-300">
                  <div className="inline-flex p-3 rounded-full bg-destructive/10 text-destructive mb-4">
                    <Icon className="w-6 h-6" />
                  </div>
                  <h3 className="font-display font-semibold mb-2">{flag.title}</h3>
                  <p className="text-muted-foreground text-sm">{flag.description}</p>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      {/* Safety Tips Section */}
      <section className="py-12">
        <div className="container mx-auto px-4">
          <div className="max-w-3xl mx-auto">
            <div className="text-center mb-10">
              <Badge variant="outline" className="mb-4 border-success/50 text-success">
                <CheckCircle className="w-3 h-3 mr-1" />
                Best Practices
              </Badge>
              <h2 className="font-display text-2xl md:text-3xl font-bold">
                How to Stay Safe
              </h2>
            </div>
            <Card className="glass-card p-6 md:p-8">
              <ul className="space-y-4">
                {safetyTips.map((tip, index) => (
                  <li key={index} className="flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-success mt-0.5 shrink-0" />
                    <span className="text-foreground/90">{tip}</span>
                  </li>
                ))}
              </ul>
            </Card>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-12">
        <div className="container mx-auto px-4">
          <Card className="glass-card p-8 md:p-12 text-center max-w-2xl mx-auto glow-primary">
            <Shield className="w-12 h-12 text-primary mx-auto mb-4" />
            <h2 className="font-display text-2xl md:text-3xl font-bold mb-4">
              Ready to Check a Suspicious Link?
            </h2>
            <p className="text-muted-foreground mb-6">
              Use our free URL scanner to analyze any link before clicking. 
              Stay safe and browse with confidence.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Link to="/url-scanner">
                <Button size="lg" className="gap-2 glow-primary">
                  <LinkIcon className="w-4 h-4" />
                  Scan a URL
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
              <Link to="/text-scanner">
                <Button size="lg" variant="outline" className="gap-2">
                  <MessageSquare className="w-4 h-4" />
                  Analyze Text
                </Button>
              </Link>
            </div>
          </Card>
        </div>
      </section>
    </main>
  );
};

export default LearnPhishing;
