"use client";

import { useState } from "react";
import { Download, Check, ShieldCheck, FileSpreadsheet, Loader2 } from "lucide-react";
import Toastify from "toastify-js";
import "toastify-js/src/toastify.css";

interface Log {
  id: number;
  time: string;
  src: string;
  dst: string;
  proto: string;
  action: string;
  conf: number;
  reason: string;
  pcap: string | null;
}

interface LogTableProps {
  logs: Log[];
  isLoading: boolean;
  onRefresh: () => void;
}

export default function LogTable({ logs, isLoading, onRefresh }: LogTableProps) {
  const [feedbackLoadingId, setFeedbackLoadingId] = useState<number | null>(null);

  const markFalsePositive = (logId: number, srcIp: string, protoStr: string) => {
    if (!confirm(`Teach AI that traffic from ${srcIp} is SAFE?`)) return;
    
    setFeedbackLoadingId(logId);
    let protoId = protoStr === "TCP" ? 1 : protoStr === "UDP" ? 2 : 0;
    
    fetch("http://127.0.0.1:5000/api/feedback/false_positive", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ src_bytes: 500, proto: protoId, service: 0, flag: 0 })
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.status === "success") {
          Toastify({
            text: "✅ AI Retrained Successfully. Traffic is now marked Safe.",
            duration: 4000,
            close: true,
            gravity: "top",
            position: "right",
            style: { background: "linear-gradient(to right, #00b09b, #96c93d)" }
          }).showToast();
          onRefresh();
        }
      })
      .catch(() => {
        alert("Failed to submit feedback to engine.");
      })
      .finally(() => {
        setFeedbackLoadingId(null);
      });
  };

  return (
    <div className="glass-panel rounded-2xl p-6 flex flex-col gap-4">
      <div className="flex items-center justify-between border-b border-zinc-700/30 pb-3">
        <h4 className="text-white font-bold text-lg flex items-center gap-2">
          📡 Real-Time Threat Stream
        </h4>
        <span className="text-[10px] bg-[#66fcf1]/10 border border-[#66fcf1]/20 text-[#66fcf1] font-bold px-3 py-1 rounded-full uppercase tracking-wider">
          Live Connection Active
        </span>
      </div>

      <div className="overflow-x-auto w-full">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-[#45a29e]/20 text-zinc-500 font-bold uppercase tracking-wider">
              <th className="py-3.5 px-4">Time</th>
              <th className="py-3.5 px-4">Source IP</th>
              <th className="py-3.5 px-4">Threat / Reason</th>
              <th className="py-3.5 px-4">Status</th>
              <th className="py-3.5 px-4 text-center">Confidence</th>
              <th className="py-3.5 px-4 text-center">Evidence</th>
              <th className="py-3.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/40">
            {isLoading ? (
              // Loading skeletons
              Array.from({ length: 5 }).map((_, idx) => (
                <tr key={idx} className="animate-pulse">
                  <td className="py-4 px-4"><div className="h-4 w-12 bg-zinc-800 rounded-md skeleton-shimmer"></div></td>
                  <td className="py-4 px-4"><div className="h-4 w-28 bg-zinc-800 rounded-md skeleton-shimmer"></div></td>
                  <td className="py-4 px-4"><div className="h-4 w-40 bg-zinc-800 rounded-md skeleton-shimmer"></div></td>
                  <td className="py-4 px-4"><div className="h-4 w-16 bg-zinc-800 rounded-md skeleton-shimmer"></div></td>
                  <td className="py-4 px-4 text-center"><div className="h-4 w-12 bg-zinc-800 rounded-md mx-auto skeleton-shimmer"></div></td>
                  <td className="py-4 px-4 text-center"><div className="h-4 w-12 bg-zinc-800 rounded-md mx-auto skeleton-shimmer"></div></td>
                  <td className="py-4 px-4 text-right"><div className="h-4 w-20 bg-zinc-800 rounded-md ml-auto skeleton-shimmer"></div></td>
                </tr>
              ))
            ) : logs.length === 0 ? (
              // Empty state
              <tr>
                <td colSpan={7} className="py-12 text-center text-zinc-500">
                  <ShieldCheck className="w-12 h-12 mx-auto mb-3 opacity-30 text-zinc-400" />
                  <p className="font-semibold text-sm">No security threats or traffic logs found</p>
                  <p className="text-xs opacity-80 mt-1">Adjust search parameters or trigger network tests.</p>
                </td>
              </tr>
            ) : (
              // Rendered log rows
              logs.map((log) => {
                const isBlocked = log.action === "BLOCKED" || log.action === "QUARANTINED" || log.action === "SINKHOLED";
                const isAlert = log.action === "ALERT";
                
                // Color tags based on threat logic
                let rowBgClass = isBlocked 
                  ? "bg-rose-950/20 hover:bg-rose-950/30 text-rose-300" 
                  : isAlert 
                    ? "bg-amber-950/20 hover:bg-amber-950/30 text-amber-300" 
                    : "hover:bg-zinc-800/20 text-[#c5c6c7]";

                let badgeColorClass = "bg-zinc-800 text-zinc-400";
                if (log.reason.includes("LSTM") || log.reason.includes("Anomaly")) badgeColorClass = "bg-sky-500/10 border border-sky-500/20 text-sky-400";
                else if (log.reason.includes("Feedback")) badgeColorClass = "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400";
                else if (log.reason.includes("DDoS") || log.reason.includes("Port") || log.reason.includes("Honeypot")) badgeColorClass = "bg-amber-500/10 border border-amber-500/20 text-amber-400";
                else if (log.reason.includes("Geo") || log.reason.includes("Foreign")) badgeColorClass = "bg-teal-500/10 border border-teal-500/20 text-teal-400";
                else if (log.reason.includes("Ransomware") || log.reason.includes("Encryption")) badgeColorClass = "bg-rose-500/10 border border-rose-500/20 text-rose-400 font-bold";
                else if (log.reason.includes("SQL") || log.reason.includes("XSS") || log.reason.includes("DPI")) badgeColorClass = "bg-orange-500/10 border border-orange-500/20 text-orange-400";

                const timeText = log.time ? log.time.split(" ")[1] : "N/A";

                return (
                  <tr key={log.id} className={`transition-colors border-b border-zinc-800/40 ${rowBgClass}`}>
                    <td className="py-3 px-4 font-mono font-bold text-zinc-500">{timeText}</td>
                    <td className="py-3 px-4 font-mono font-semibold text-white">{log.src}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2.5 py-1 rounded-md text-[10px] uppercase font-bold tracking-wider ${badgeColorClass}`}>
                        {log.reason}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-bold uppercase">
                      <span className={isBlocked ? "text-rose-500" : isAlert ? "text-amber-500" : "text-[#66fcf1]"}>
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center font-mono font-bold">{(log.conf * 100).toFixed(0)}%</td>
                    <td className="py-3 px-4 text-center">
                      {log.pcap ? (
                        <a
                          href={`http://127.0.0.1:5000/download_pcap/${log.pcap}`}
                          className="inline-flex items-center gap-1 text-cyan-400 hover:text-[#66fcf1] underline font-bold"
                          title="Download forensics capture file"
                        >
                          <Download className="w-3.5 h-3.5" />
                          PCAP
                        </a>
                      ) : (
                        <span className="text-zinc-600">-</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {isBlocked && (
                        <button
                          onClick={() => markFalsePositive(log.id, log.src, log.proto)}
                          disabled={feedbackLoadingId === log.id}
                          className="text-xs bg-emerald-500/10 border border-emerald-500/30 hover:bg-emerald-500 hover:text-[#0b0c10] text-emerald-400 font-bold px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 ml-auto cursor-pointer"
                        >
                          {feedbackLoadingId === log.id ? (
                            <Loader2 className="w-3 h-3 animate-spin" />
                          ) : (
                            <Check className="w-3.5 h-3.5" />
                          )}
                          Mark Safe
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
