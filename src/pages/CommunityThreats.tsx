import { useState, useEffect } from "react";
import { AlertTriangle, Shield, Globe, Send, Calendar } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import { API_ENDPOINTS, apiRequest } from "@/lib/api";
import { LoadingState, EmptyState } from "@/components/ui/states";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";

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
    reportSection: "Report a Suspicious Link",
    urlLabel: "Suspicious URL",
    urlPlaceholder: "Enter the suspicious URL here...",
    categoryLabel: "Threat Category",
    descriptionLabel: "Description (Optional)",
    descriptionPlaceholder: "Describe why you think this is suspicious...",
    submit: "Submit Report",
    submitting: "Submitting...",
    feedTitle: "Recent Community-Reported Threats",
    feedWarning: "These examples are shared for awareness only. Do not attempt to visit them.",
    noReports: "No community reports yet. Be the first to contribute!",
    reportedOn: "Reported on",
  },
  hi: {
    title: "समुदाय खतरा रिपोर्ट",
    subtitle: "संदिग्ध लिंक की रिपोर्ट करें और दूसरों की सुरक्षा में मदद करें",
    warning: "⚠️ साझा किए गए लिंक पर क्लिक न करें। यह केवल जागरूकता के लिए है।",
    reportSection: "संदिग्ध लिंक रिपोर्ट करें",
    urlLabel: "संदिग्ध URL",
    urlPlaceholder: "यहां संदिग्ध URL दर्ज करें...",
    categoryLabel: "खतरा श्रेणी",
    descriptionLabel: "विवरण (वैकल्पिक)",
    descriptionPlaceholder: "बताएं कि आपको यह संदिग्ध क्यों लगता है...",
    submit: "रिपोर्ट जमा करें",
    submitting: "जमा कर रहे हैं...",
    feedTitle: "हाल की समुदाय-रिपोर्ट की गई धमकियां",
    feedWarning: "ये उदाहरण केवल जागरूकता के लिए साझा किए गए हैं। इन्हें देखने का प्रयास न करें।",
    noReports: "अभी तक कोई समुदाय रिपोर्ट नहीं है। योगदान देने वाले पहले बनें!",
    reportedOn: "रिपोर्ट तिथि",
  },
  mr: {
    title: "समुदाय धोका अहवाल",
    subtitle: "संशयास्पद लिंक्सची तक्रार करा आणि इतरांचे संरक्षण करण्यात मदत करा",
    warning: "⚠️ शेअर केलेल्या लिंकवर क्लिक करू नका. हे फक्त जागरूकतेसाठी आहे.",
    reportSection: "संशयास्पद लिंक तक्रार करा",
    urlLabel: "संशयास्पद URL",
    urlPlaceholder: "येथे संशयास्पद URL प्रविष्ट करा...",
    categoryLabel: "धोका श्रेणी",
    descriptionLabel: "वर्णन (पर्यायी)",
    descriptionPlaceholder: "तुम्हाला हे संशयास्पद का वाटते ते सांगा...",
    submit: "अहवाल सादर करा",
    submitting: "सादर करत आहे...",
    feedTitle: "अलीकडील समुदाय-अहवालित धोके",
    feedWarning: "हे उदाहरण केवळ जागरूकतेसाठी सामायिक केले आहेत. त्यांना भेट देण्याचा प्रयत्न करू नका.",
    noReports: "अद्याप कोणतेही समुदाय अहवाल नाहीत. योगदान देणारे पहिले व्हा!",
    reportedOn: "अहवाल तारीख",
  },
};

const ITEMS_PER_PAGE = 5;

const CommunityThreats = () => {
  const [language, setLanguage] = useState<"en" | "hi" | "mr">("en");
  const [urlText, setUrlText] = useState("");
  const [category, setCategory] = useState("unknown");
  const [description, setDescription] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [reports, setReports] = useState<CommunityReport[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);

  const t = { ...TRANSLATIONS.en, ...TRANSLATIONS[language] };

  useEffect(() => {
    fetchReports();
  }, [language]);

  const fetchReports = async () => {
    setIsLoading(true);
    try {
      const data = await apiRequest<CommunityReport[]>(
        `${API_ENDPOINTS.communityReports}?language=${language}&limit=50`
      );
      setReports(data);
      setCurrentPage(1);
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

  const formatDate = (isoString: string) => {
    try {
      return new Date(isoString).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch {
      return isoString;
    }
  };

  // Pagination
  const totalPages = Math.ceil(reports.length / ITEMS_PER_PAGE);
  const paginatedReports = reports.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

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

        {/* ======================== */}
        {/* REPORT FORM SECTION */}
        {/* ======================== */}
        <Card className="mb-10">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Send className="w-5 h-5" />
              {t.reportSection}
            </CardTitle>
          </CardHeader>
          <CardContent>
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

        {/* ======================== */}
        {/* DIVIDER */}
        {/* ======================== */}
        <div className="flex items-center gap-4 mb-6">
          <Separator className="flex-1" />
          <h2 className="text-lg font-semibold text-muted-foreground whitespace-nowrap">
            {t.feedTitle}
          </h2>
          <Separator className="flex-1" />
        </div>

        {/* ======================== */}
        {/* THREAT FEED SECTION */}
        {/* ======================== */}
        {/* Feed Warning */}
        <div className="bg-muted/50 border border-border rounded-lg p-3 mb-6 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-muted-foreground shrink-0 mt-0.5" />
          <p className="text-sm text-muted-foreground">{t.feedWarning}</p>
        </div>

        {/* Feed Content */}
        {isLoading ? (
          <LoadingState message="Loading community reports..." />
        ) : reports.length === 0 ? (
          <EmptyState
            title={t.noReports}
            description="Submit a suspicious URL above to help others stay safe."
          />
        ) : (
          <div className="space-y-4">
            {paginatedReports.map((report) => (
              <Card key={report.id} className="border-border/50 bg-card/50">
                <CardHeader className="pb-3">
                  <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-2">
                    {/* Masked URL - plain text, non-clickable */}
                    <code className="text-sm bg-destructive/10 text-destructive px-3 py-1.5 rounded font-mono select-all break-all">
                      {report.masked_url}
                    </code>
                    <Badge variant="outline" className="self-start shrink-0">
                      {report.threat_category}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Attack Pattern Tags */}
                  {report.attack_patterns.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {report.attack_patterns.map((pattern, i) => (
                        <Badge key={i} variant="secondary" className="text-xs">
                          {pattern}
                        </Badge>
                      ))}
                    </div>
                  )}

                  {/* Educational Explanation */}
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {report.explanation}
                  </p>

                  {/* Safety Tip */}
                  {report.safety_tip && (
                    <p className="text-sm text-primary/80 italic">
                      💡 {report.safety_tip}
                    </p>
                  )}

                  {/* Reported Date */}
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground pt-2 border-t border-border/30">
                    <Calendar className="w-3.5 h-3.5" />
                    <span>
                      {t.reportedOn}: {formatDate(report.submitted_at)}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}

            {/* Pagination */}
            {totalPages > 1 && (
              <Pagination className="mt-6">
                <PaginationContent>
                  <PaginationItem>
                    <PaginationPrevious
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                      className={currentPage === 1 ? "pointer-events-none opacity-50" : "cursor-pointer"}
                    />
                  </PaginationItem>
                  {Array.from({ length: totalPages }, (_, i) => i + 1)
                    .filter((page) => {
                      // Show first, last, and pages around current
                      return page === 1 || page === totalPages || Math.abs(page - currentPage) <= 1;
                    })
                    .map((page, idx, arr) => (
                      <PaginationItem key={page}>
                        {idx > 0 && arr[idx - 1] !== page - 1 && (
                          <span className="px-2 text-muted-foreground">...</span>
                        )}
                        <PaginationLink
                          onClick={() => setCurrentPage(page)}
                          isActive={currentPage === page}
                          className="cursor-pointer"
                        >
                          {page}
                        </PaginationLink>
                      </PaginationItem>
                    ))}
                  <PaginationItem>
                    <PaginationNext
                      onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                      className={currentPage === totalPages ? "pointer-events-none opacity-50" : "cursor-pointer"}
                    />
                  </PaginationItem>
                </PaginationContent>
              </Pagination>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default CommunityThreats;
