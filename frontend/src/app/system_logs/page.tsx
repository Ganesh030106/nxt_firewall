"use client";

import { useEffect, useState } from "react";
import Sidebar from "@/components/Sidebar";
import { Terminal, ShieldAlert, AlertTriangle, Info, RefreshCw } from "lucide-react";

export default function SystemLogsPage() {
  const [logs, setLogs] = useState<[string, string, string][]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const fetchSystemLogs = () => {
    setIsLoading(true);
    fetch("http://127.0.0.1:5000/api/system_logs")
      .then((r) => r.json())
      .then((data) => {
        setLogs(data);
        setIsLoading(false);
      })
      .catch(() => {
        setIsLoading(false);
      });
  };

  useEffect(() => {
    fetchSystemLogs();
    const interval = setInterval(fetchSystemLogs, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="flex bg-[#0b0c10] min-h-screen text-[#c5c6c7]">
      <Sidebar />

      <main className="flex-1 flex flex-col p-8 gap-6 overflow-y-auto max-h-screen">
        {/* Header Block */}
        <div className="flex items-center justify-between border-b border-zinc-800/40 pb-4">
          <div>
            <h2 className="text-white font-extrabold text-2xl tracking-tight">System Events Log</h2>
            <p className="text-xs text-zinc-400 mt-1">Audit trail of self-defense modules, integrity scans, and hardware insertions.</p>
          </div>
          <button 
            onClick={fetchSystemLogs}
            disabled={isLoading}
            className="p-2.5 bg-zinc-800/60 hover:bg-zinc-700/60 border border-zinc-700/30 rounded-xl text-[#66fcf1] transition-all hover:scale-105 cursor-pointer"
            title="Force refresh logs"
          >
            <RefreshCw className={`w-5 h-5 ${isLoading ? "animate-spin" : ""}`} />
          </button>
        </div>

        {/* Console Box Layout */}
        <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4 bg-black/40">
          <div className="flex items-center justify-between border-b border-zinc-800/40 pb-3">
            <h4 className="text-white font-bold text-sm flex items-center gap-2 font-mono">
              <Terminal className="w-4 h-4 text-[#66fcf1]" />
              sentinel-x@security-daemon:~$ tail -n 50 /var/log/sentinel.log
            </h4>
            <span className="h-2 w-2 rounded-full bg-emerald-500 heartbeat-dot"></span>
          </div>

          <div className="flex flex-col gap-2 font-mono text-xs overflow-y-auto max-h-[500px] pr-2">
            {isLoading && logs.length === 0 ? (
              Array.from({ length: 6 }).map((_, idx) => (
                <div key={idx} className="h-5 bg-zinc-800/40 rounded-md animate-pulse skeleton-shimmer w-full"></div>
              ))
            ) : logs.length === 0 ? (
              <div className="py-20 text-center text-zinc-600 font-semibold uppercase tracking-wider">
                No system log records emitted yet.
              </div>
            ) : (
              logs.map((log, index) => {
                const [timestamp, level, message] = log;
                
                let levelBadge = "text-sky-400 bg-sky-500/10";
                let Icon = Info;
                
                if (level === "CRITICAL" || level === "ERROR") {
                  levelBadge = "text-rose-400 bg-rose-500/10 font-bold";
                  Icon = ShieldAlert;
                } else if (level === "WARNING" || level === "WARN") {
                  levelBadge = "text-amber-400 bg-amber-500/10 font-bold";
                  Icon = AlertTriangle;
                }

                return (
                  <div 
                    key={index} 
                    className="flex items-start gap-3 py-2 px-3 hover:bg-zinc-800/20 rounded-lg transition-colors border-l-2 border-zinc-700/20"
                  >
                    <span className="text-zinc-500 shrink-0 select-none font-bold">[{timestamp.split(" ")[1]}]</span>
                    <span className={`px-2 py-0.5 rounded-md font-bold text-[9px] uppercase tracking-wider shrink-0 inline-flex items-center gap-1 ${levelBadge}`}>
                      <Icon className="w-3 h-3" />
                      {level}
                    </span>
                    <span className="text-zinc-300 font-medium break-all">{message}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
