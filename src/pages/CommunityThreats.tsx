import { useState, useEffect } from "react";
import { AlertTriangle, Shield, Globe, Send, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import { API_ENDPOINTS, apiRequest } from "@/lib/api";

interface CommunityReport {
  id: string;
  masked_url: string;
  threat_category: string;
  attack_patterns: string[];
  explanation: string;
  safety_tip: string;
  submitted_at: string;
}

const TRANSLATIONS = {
  en: {
    title: "Community Threat Reports",
    subtitle: "Report suspicious links and help protect others",
    warning: "⚠️ Do not click shared links. This is for awareness only.",
    reportTab: "Report a Link",
    viewTab: "View Reports",
    urlLabel: "Suspicious URL",
    urlPlaceholder: "Enter the suspicious URL here...",
    categoryLabel: "Threat Category",
    descriptionLabel: "Description (Optional)",
    descriptionPlaceholder: "Describe why you think this is suspicious...",
    submit: "Submit Report",
    submitting: "Submitting...",
    noReports: "No community reports yet. Be the first to contribute!",
    recentReports: "Recent Community Reports",
  },
  hi: {
    title: "समुदाय खतरा रिपोर्ट",
    subtitle: "संदिग्ध लिंक की रिपोर्ट करें और दूसरों की सुरक्षा में मदद करें",
    warning: "⚠️ साझा किए गए लिंक पर क्लिक न करें। यह केवल जागरूकता के लिए है।",
    reportTab: "लिंक रिपोर्ट करें",
    viewTab: "रिपोर्ट देखें",
    urlLabel: "संदिग्ध URL",
    submit: "रिपोर्ट जमा करें",
  },
  mr: {
    title: "समुदाय धोका अहवाल",
    subtitle: "संशयास्पद लिंक्सची तक्रार करा आणि इतरांचे संरक्षण करण्यात मदत करा",
    warning: "⚠️ शेअर केलेल्या लिंकवर क्लिक करू नका. हे फक्त जागरूकतेसाठी आहे.",
    reportTab: "लिंक तक्रार करा",
    viewTab: "अहवाल पहा",
  },
};

const CommunityThreats = () => {
  const [language, setLanguage] = useState<"en" | "hi" | "mr">("en");
  const [urlText, setUrlText] = useState("");
  const [category, setCategory] = useState("unknown");
  const [description, setDescription] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [reports, setReports] = useState<CommunityReport[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const t = { ...TRANSLATIONS.en, ...TRANSLATIONS[language] };

  useEffect(() => {
    fetchReports();
  }, [language]);

  const fetchReports = async () => {
    try {
      const data = await apiRequest<CommunityReport[]>(
        `${API_ENDPOINTS.communityReports}?language=${language}&limit=20`
      );
      setReports(data);
    } catch {
      console.log("Could not fetch community reports");
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlText.trim()) return;

    setIsSubmitting(true);
    try {
      await apiRequest(API_ENDPOINTS.communityReport, {
        method: "POST",
        body: JSON.stringify({
          url_text: urlText,
          threat_category: category,
          optional_description: description,
          language,
        }),
      });
      toast.success("Report submitted successfully!");
      setUrlText("");
      setDescription("");
      fetchReports();
    } catch (error: any) {
      toast.error(error.message || "Failed to submit report");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen pt-20 pb-12 px-4">
      <div className="container mx-auto max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center gap-2 mb-4">
            <Globe className="w-10 h-10 text-primary" />
            <Shield className="w-10 h-10 text-primary" />
          </div>
          <h1 className="text-3xl font-bold mb-2">{t.title}</h1>
          <p className="text-muted-foreground">{t.subtitle}</p>
          
          {/* Language Selector */}
          <div className="flex justify-center mt-4">
            <Select value={language} onValueChange={(v) => setLanguage(v as any)}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="en">English</SelectItem>
                <SelectItem value="hi">हिंदी</SelectItem>
                <SelectItem value="mr">मराठी</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Warning Banner */}
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 mb-6 flex items-center gap-3">
          <AlertTriangle className="w-6 h-6 text-yellow-500 shrink-0" />
          <p className="text-sm font-medium">{t.warning}</p>
        </div>

        <Tabs defaultValue="report" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="report" className="gap-2">
              <Send className="w-4 h-4" />
              {t.reportTab}
            </TabsTrigger>
            <TabsTrigger value="view" className="gap-2">
              <Eye className="w-4 h-4" />
              {t.viewTab}
            </TabsTrigger>
          </TabsList>

          {/* Report Form */}
          <TabsContent value="report">
            <Card>
              <CardContent className="pt-6">
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <label className="text-sm font-medium mb-2 block">{t.urlLabel}</label>
                    <Input
                      value={urlText}
                      onChange={(e) => setUrlText(e.target.value)}
                      placeholder={t.urlPlaceholder}
                      required
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium mb-2 block">{t.categoryLabel}</label>
                    <Select value={category} onValueChange={setCategory}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="phishing">Phishing</SelectItem>
                        <SelectItem value="scam">Scam/Fraud</SelectItem>
                        <SelectItem value="fake_login">Fake Login</SelectItem>
                        <SelectItem value="unknown">Unknown</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-sm font-medium mb-2 block">{t.descriptionLabel}</label>
                    <Textarea
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder={t.descriptionPlaceholder}
                      rows={3}
                    />
                  </div>
                  <Button type="submit" className="w-full" disabled={isSubmitting}>
                    {isSubmitting ? t.submitting : t.submit}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </TabsContent>

          {/* View Reports */}
          <TabsContent value="view">
            <div className="space-y-4">
              <h3 className="font-semibold">{t.recentReports}</h3>
              {isLoading ? (
                <p className="text-muted-foreground text-center py-8">Loading...</p>
              ) : reports.length === 0 ? (
                <p className="text-muted-foreground text-center py-8">{t.noReports}</p>
              ) : (
                reports.map((report) => (
                  <Card key={report.id} className="border-border/50">
                    <CardHeader className="pb-2">
                      <div className="flex justify-between items-start">
                        <code className="text-sm bg-destructive/10 text-destructive px-2 py-1 rounded font-mono">
                          {report.masked_url}
                        </code>
                        <Badge variant="outline">{report.threat_category}</Badge>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      {report.attack_patterns.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {report.attack_patterns.map((pattern, i) => (
                            <Badge key={i} variant="secondary" className="text-xs">
                              {pattern}
                            </Badge>
                          ))}
                        </div>
                      )}
                      <p className="text-sm text-muted-foreground">{report.explanation}</p>
                      <p className="text-sm text-primary">{report.safety_tip}</p>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default CommunityThreats;
