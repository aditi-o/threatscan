import { useState, useRef, useEffect } from "react";
import { MessageCircle, X, Send, Bot, User, Minimize2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { API_ENDPOINTS, apiRequest } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface ScanContext {
  url?: string;
  risk_score?: number;
  verdict?: string;
  attack_patterns?: string[];
  reasons?: string[];
  explanation?: string;
  safety_tip?: string;
}

interface ChatbotWidgetProps {
  scanContext?: ScanContext;
  language?: "en" | "hi" | "mr";
}

const TRANSLATIONS = {
  en: {
    title: "SafeBot",
    subtitle: "Your cyber safety assistant",
    placeholder: "Ask about online safety...",
    greeting: "Hi! I'm SafeBot, your cyber safety assistant. Ask me anything about phishing, suspicious URLs, or online safety tips!",
  },
  hi: {
    title: "SafeBot",
    subtitle: "आपका साइबर सुरक्षा सहायक",
    placeholder: "ऑनलाइन सुरक्षा के बारे में पूछें...",
    greeting: "नमस्ते! मैं SafeBot हूं। फ़िशिंग, संदिग्ध URLs, या ऑनलाइन सुरक्षा के बारे में कुछ भी पूछें!",
  },
  mr: {
    title: "SafeBot",
    subtitle: "तुमचा सायबर सुरक्षा सहाय्यक",
    placeholder: "ऑनलाइन सुरक्षिततेबद्दल विचारा...",
    greeting: "नमस्कार! मी SafeBot आहे। फिशिंग, संशयास्पद URLs, किंवा ऑनलाइन सुरक्षिततेबद्दल काहीही विचारा!",
  },
};

const ChatbotWidget = ({ scanContext, language = "en" }: ChatbotWidgetProps) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const t = TRANSLATIONS[language] || TRANSLATIONS.en;

  // Initialize with greeting
  useEffect(() => {
    if (messages.length === 0) {
      setMessages([{ role: "assistant", content: t.greeting }]);
    }
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const sendMessage = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage = input.trim();
    setInput("");
    setMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setIsLoading(true);

    try {
      const response = await apiRequest<{ response: string; conversation_id: string }>(
        API_ENDPOINTS.chat,
        {
          method: "POST",
          body: JSON.stringify({
            message: userMessage,
            conversation_id: conversationId,
            scan_context: scanContext,
            language,
          }),
        }
      );

      setConversationId(response.conversation_id);
      setMessages((prev) => [...prev, { role: "assistant", content: response.response }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: language === "en" 
            ? "I'm having trouble connecting. Please try again."
            : "कनेक्ट करने में समस्या हो रही है। कृपया पुनः प्रयास करें।",
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) {
    return (
      <Button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 h-14 w-14 rounded-full shadow-lg z-50"
        size="icon"
      >
        <MessageCircle className="h-6 w-6" />
      </Button>
    );
  }

  return (
    <div
      className={cn(
        "fixed bottom-6 right-6 z-50 flex flex-col bg-card border border-border rounded-xl shadow-2xl transition-all duration-300",
        isMinimized ? "w-72 h-14" : "w-80 sm:w-96 h-[500px]"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b border-border bg-primary/5 rounded-t-xl">
        <div className="flex items-center gap-2">
          <Bot className="h-5 w-5 text-primary" />
          <div>
            <h3 className="font-semibold text-sm">{t.title}</h3>
            {!isMinimized && <p className="text-xs text-muted-foreground">{t.subtitle}</p>}
          </div>
        </div>
        <div className="flex gap-1">
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setIsMinimized(!isMinimized)}>
            <Minimize2 className="h-4 w-4" />
          </Button>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setIsOpen(false)}>
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {!isMinimized && (
        <>
          {/* Messages */}
          <ScrollArea className="flex-1 p-3" ref={scrollRef}>
            <div className="space-y-3">
              {messages.map((msg, i) => (
                <div key={i} className={cn("flex gap-2", msg.role === "user" && "justify-end")}>
                  {msg.role === "assistant" && (
                    <div className="h-7 w-7 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                      <Bot className="h-4 w-4 text-primary" />
                    </div>
                  )}
                  <div
                    className={cn(
                      "rounded-lg px-3 py-2 text-sm max-w-[80%]",
                      msg.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted"
                    )}
                  >
                    {msg.content}
                  </div>
                  {msg.role === "user" && (
                    <div className="h-7 w-7 rounded-full bg-muted flex items-center justify-center shrink-0">
                      <User className="h-4 w-4" />
                    </div>
                  )}
                </div>
              ))}
              {isLoading && (
                <div className="flex gap-2">
                  <div className="h-7 w-7 rounded-full bg-primary/10 flex items-center justify-center">
                    <Bot className="h-4 w-4 text-primary animate-pulse" />
                  </div>
                  <div className="bg-muted rounded-lg px-3 py-2 text-sm">...</div>
                </div>
              )}
            </div>
          </ScrollArea>

          {/* Input */}
          <div className="p-3 border-t border-border">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                sendMessage();
              }}
              className="flex gap-2"
            >
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={t.placeholder}
                disabled={isLoading}
                className="flex-1"
              />
              <Button type="submit" size="icon" disabled={isLoading || !input.trim()}>
                <Send className="h-4 w-4" />
              </Button>
            </form>
          </div>
        </>
      )}
    </div>
  );
};

export default ChatbotWidget;
