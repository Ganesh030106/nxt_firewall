"use client";

import { useState } from "react";
import { Search, ShieldCheck, ShieldAlert, Loader2 } from "lucide-react";

export default function PhishingScan() {
  const [url, setUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<{
    scanned: boolean;
    isPhishing: boolean;
    confidence: string;
    reason: string;
  } | null>(null);
  const [error, setError] = useState("");

  const handleScan = () => {
    if (!url.trim()) {
      setError("Please paste or type a valid URL to scan!");
      return;
    }
    setError("");
    setIsLoading(true);
    setResult(null);

    fetch("http://127.0.0.1:5000/check_url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    })
      .then((r) => {
        if (!r.ok) throw new Error("Server responded with an error");
        return r.json();
      })
      .then((data) => {
        setResult({
          scanned: true,
          isPhishing: data.is_phishing,
          confidence: data.confidence,
          reason: data.reason
        });
      })
      .catch((e) => {
        setError("Failed to connect to AI Phishing Scanner. Please make sure Flask is running.");
      })
      .finally(() => {
        setIsLoading(false);
      });
  };

  return (
    <div className="glass-panel p-6 rounded-2xl flex flex-col gap-4">
      <div>
        <h3 className="text-white font-bold text-lg flex items-center gap-2">
          🎣 AI Phishing Scanner
        </h3>
        <p className="text-xs text-zinc-400 mt-1">
          Paste a suspicious URL to scan its structural properties, WHOIS status, homograph patterns, and brand mimicking vectors.
        </p>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="e.g. http://secure-login-paypal.com/update"
            className="w-full bg-[#11151b] border border-[#45a29e]/30 rounded-xl px-4 py-3 text-sm text-white placeholder-zinc-500 focus:outline-none focus:border-[#66fcf1] transition-all"
          />
        </div>
        <button
          onClick={handleScan}
          disabled={isLoading}
          className="bg-[#45a29e] hover:bg-[#66fcf1] disabled:opacity-50 text-[#0b0c10] font-bold px-6 py-3 rounded-xl flex items-center gap-2 transition-all cursor-pointer"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning
            </>
          ) : (
            <>
              <Search className="w-4 h-4" />
              Scan URL
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="bg-rose-500/10 border border-rose-500/30 p-3 rounded-xl text-rose-400 text-xs font-medium">
          ⚠️ {error}
        </div>
      )}

      {result && (
        <div className={`border p-4 rounded-xl flex gap-4 items-start animate-fade-in ${
          result.isPhishing 
            ? "bg-rose-500/10 border-rose-500/30 text-rose-400" 
            : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
        }`}>
          {result.isPhishing ? (
            <ShieldAlert className="w-10 h-10 shrink-0 text-rose-500" />
          ) : (
            <ShieldCheck className="w-10 h-10 shrink-0 text-emerald-500" />
          )}
          <div className="flex flex-col gap-1">
            <span className="font-extrabold text-sm uppercase tracking-wider">
              {result.isPhishing ? "Malicious URL Detected!" : "Verified Safe by AI"}
            </span>
            <p className="text-xs text-zinc-300 font-medium">
              {result.reason}
            </p>
            <div className="flex items-center gap-1.5 mt-2">
              <span className="text-[10px] bg-black/40 px-2.5 py-1 rounded-full font-mono text-zinc-400">
                Confidence: <strong className="text-white">{result.confidence}</strong>
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
