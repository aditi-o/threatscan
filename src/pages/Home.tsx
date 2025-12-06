import { Shield, Link as LinkIcon, MessageSquare, Mic, Image, Bot, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import FeatureCard from "@/components/FeatureCard";
import { Link } from "react-router-dom";

const features = [
  {
    icon: LinkIcon,
    title: "URL Scanner",
    description: "Instantly detect phishing links and malicious websites before you click. AI-powered analysis protects you from online threats.",
    href: "/url-scanner",
    gradient: "from-primary/20 to-accent/10",
  },
  {
    icon: MessageSquare,
    title: "Text Scanner",
    description: "Analyze suspicious messages for scam patterns. Detect UPI fraud, digital arrest scams, and threatening messages.",
    href: "/text-scanner",
    gradient: "from-warning/20 to-warning/5",
  },
  {
    icon: Mic,
    title: "Call Analyzer",
    description: "Upload call recordings to detect scam patterns. Our AI transcribes and analyzes for fraud indicators.",
    href: "/text-scanner",
    gradient: "from-destructive/20 to-destructive/5",
  },
  {
    icon: Image,
    title: "Screenshot OCR",
    description: "Extract and analyze text from screenshots. Perfect for checking suspicious messages or images.",
    href: "/text-scanner",
    gradient: "from-success/20 to-success/5",
  },
];

const stats = [
  { value: "99.2%", label: "Detection Accuracy" },
  { value: "50K+", label: "Threats Blocked" },
  { value: "<2s", label: "Scan Time" },
  { value: "24/7", label: "Protection" },
];

const Home = () => {
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        {/* Background effects */}
        <div className="absolute inset-0 hero-glow" />
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-accent/10 rounded-full blur-3xl" />

        <div className="container mx-auto px-4 relative">
          <div className="max-w-4xl mx-auto text-center">
            {/* Badge */}
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-8">
              <Shield className="w-4 h-4 text-primary" />
              <span className="text-sm font-medium text-primary">AI-Powered Protection</span>
            </div>

            {/* Main heading */}
            <h1 className="font-display text-4xl md:text-6xl lg:text-7xl font-bold mb-6 leading-tight">
              Stay Safe from
              <span className="block text-gradient">Digital Threats</span>
            </h1>

            {/* Subtitle */}
            <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-10">
              Protect yourself from phishing links, scam messages, and fraudulent calls. 
              Our AI analyzes threats in real-time to keep you secure online.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link to="/url-scanner">
                <Button variant="hero" size="xl" className="gap-2">
                  <Shield className="w-5 h-5" />
                  Start Scanning
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
              <Button variant="outline" size="xl">
                Learn How It Works
              </Button>
            </div>
          </div>

          {/* Stats */}
          <div className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-8 max-w-3xl mx-auto">
            {stats.map((stat, index) => (
              <div key={index} className="text-center">
                <div className="font-display text-3xl md:text-4xl font-bold text-gradient mb-1">
                  {stat.value}
                </div>
                <div className="text-sm text-muted-foreground">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl md:text-4xl font-bold mb-4">
              Complete Security <span className="text-gradient">Toolkit</span>
            </h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Multiple tools to protect you from various types of online scams and threats
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-6xl mx-auto">
            {features.map((feature, index) => (
              <FeatureCard key={index} {...feature} />
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 bg-secondary/30">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl md:text-4xl font-bold mb-4">
              How <span className="text-gradient">SafeLink Shield</span> Works
            </h2>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            {[
              {
                step: "01",
                title: "Input Data",
                description: "Paste a URL, message, or upload a file you want to analyze",
              },
              {
                step: "02",
                title: "AI Analysis",
                description: "Our AI models analyze patterns and compare with known threats",
              },
              {
                step: "03",
                title: "Get Results",
                description: "Receive a detailed risk assessment with actionable recommendations",
              },
            ].map((item, index) => (
              <div key={index} className="relative">
                <div className="glass-card p-6 rounded-xl text-center">
                  <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-primary/10 text-primary font-display font-bold text-lg mb-4">
                    {item.step}
                  </div>
                  <h3 className="font-display font-semibold text-lg mb-2">{item.title}</h3>
                  <p className="text-sm text-muted-foreground">{item.description}</p>
                </div>
                {index < 2 && (
                  <div className="hidden md:block absolute top-1/2 -right-4 transform -translate-y-1/2 text-muted-foreground">
                    →
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <div className="glass-card p-12 rounded-2xl text-center max-w-3xl mx-auto glow-primary">
            <Bot className="w-16 h-16 text-primary mx-auto mb-6" />
            <h2 className="font-display text-3xl font-bold mb-4">
              Ready to Stay Protected?
            </h2>
            <p className="text-muted-foreground mb-8 max-w-lg mx-auto">
              Start scanning URLs and messages right now. No signup required for basic scans.
            </p>
            <Link to="/url-scanner">
              <Button variant="hero" size="lg">
                Try URL Scanner Now
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 border-t border-border/30">
        <div className="container mx-auto px-4">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              <span className="font-display font-semibold">SafeLink Shield</span>
            </div>
            <p className="text-sm text-muted-foreground">
              © 2024 SafeLink Shield. Protecting you from online threats.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Home;
