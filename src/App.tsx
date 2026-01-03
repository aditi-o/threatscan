import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Navbar from "./components/Navbar";
import ChatbotWidget from "./components/ChatbotWidget";
import ErrorBoundary from "./components/ErrorBoundary";
import Index from "./pages/Index";
import UrlScanner from "./pages/UrlScanner";
import TextScanner from "./pages/TextScanner";
import CallAnalyzer from "./pages/CallAnalyzer";
import ScreenshotOCR from "./pages/ScreenshotOCR";
import LearnPhishing from "./pages/LearnPhishing";
import CommunityThreats from "./pages/CommunityThreats";
import NotFound from "./pages/NotFound";

// Configure QueryClient with error handling defaults
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 1000 * 60 * 5, // 5 minutes
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 1,
    },
  },
});

const App = () => (
  <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner position="top-center" theme="dark" />
        <BrowserRouter>
          <div className="min-h-screen bg-background">
            <Navbar />
            <Routes>
              <Route path="/" element={<Index />} />
              <Route path="/url-scanner" element={<UrlScanner />} />
              <Route path="/text-scanner" element={<TextScanner />} />
              <Route path="/call-analyzer" element={<CallAnalyzer />} />
              <Route path="/screenshot-ocr" element={<ScreenshotOCR />} />
              <Route path="/community" element={<CommunityThreats />} />
              <Route path="/learn" element={<LearnPhishing />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
            <ChatbotWidget />
          </div>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </ErrorBoundary>
);

export default App;
