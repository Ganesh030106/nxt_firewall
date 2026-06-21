"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  Shield, 
  LayoutDashboard, 
  Settings, 
  Terminal, 
  HelpCircle, 
  Activity,
  Download
} from "lucide-react";
import { useEffect, useState } from "react";

export default function Sidebar() {
  const pathname = usePathname();
  const [isOnline, setIsOnline] = useState(false);

  useEffect(() => {
    // Periodically fetch status from the Flask API
    const checkStatus = () => {
      fetch("http://127.0.0.1:5000/api/data")
        .then(r => r.json())
        .then(data => {
          setIsOnline(data.status === "ONLINE");
        })
        .catch(() => setIsOnline(false));
    };

    checkStatus();
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { name: "Dashboard", href: "/", icon: LayoutDashboard },
    { name: "System Logs", href: "/system_logs", icon: Terminal },
    { name: "Settings", href: "/settings", icon: Settings },
    { name: "Help & Docs", href: "/help", icon: HelpCircle },
  ];

  return (
    <aside className="w-64 bg-[#11151b] border-r border-[#45a29e]/30 flex flex-col justify-between p-5 min-h-screen sticky top-0">
      <div className="flex flex-col gap-8">
        {/* Brand Header */}
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-[#66fcf1]" />
          <div>
            <h1 className="text-white font-bold tracking-wider text-lg">Sentinel-X</h1>
            <p className="text-[10px] text-zinc-500 font-mono">HYBRID FIREWALL</p>
          </div>
        </div>

        {/* Navigation Section */}
        <nav className="flex flex-col gap-2">
          <h2 className="text-[11px] font-bold text-zinc-500 uppercase tracking-widest px-3 mb-2">
            Navigation
          </h2>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href;
            return (
              <Link
                key={item.name}
                href={item.href}
                className={`flex items-center gap-3 px-4 py-3 rounded-xl transition-all duration-200 group ${
                  isActive 
                    ? "bg-[#1f2833] text-[#66fcf1] border-l-2 border-[#66fcf1] font-semibold" 
                    : "text-[#c5c6c7] hover:bg-[#1f2833]/50 hover:text-white"
                }`}
              >
                <Icon className={`w-5 h-5 transition-transform duration-200 group-hover:scale-110 ${
                  isActive ? "text-[#66fcf1]" : "text-zinc-500 group-hover:text-[#66fcf1]"
                }`} />
                <span className="text-sm">{item.name}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Engine Status Block */}
      <div className="flex flex-col gap-4 bg-[#1f2833]/40 p-4 rounded-2xl border border-[#45a29e]/15">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#45a29e]" />
            <span className="text-xs text-zinc-400">Sniffer Engine</span>
          </div>
          <span className="flex h-2.5 w-2.5 relative">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
              isOnline ? "bg-emerald-400" : "bg-rose-400"
            }`}></span>
            <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
              isOnline ? "bg-emerald-500" : "bg-rose-500"
            }`}></span>
          </span>
        </div>
        <div className="flex flex-col gap-1">
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-zinc-500">Service Status</span>
            <span className={`font-mono font-bold ${
              isOnline ? "text-emerald-400" : "text-rose-400"
            }`}>
              {isOnline ? "ONLINE" : "OFFLINE"}
            </span>
          </div>
        </div>
        
        {/* Rapid PDF Audit Download */}
        <a 
          href="http://127.0.0.1:5000/download_report" 
          className="flex items-center justify-center gap-2 w-full bg-[#45a29e] hover:bg-[#66fcf1] text-[#0b0c10] font-bold text-xs py-2 rounded-xl transition-all duration-200"
        >
          <Download className="w-3.5 h-3.5" />
          Audit Report
        </a>
      </div>
    </aside>
  );
}
