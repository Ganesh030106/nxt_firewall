"use client";

import Sidebar from "@/components/Sidebar";
import { 
  HelpCircle, 
  Terminal, 
  ShieldCheck, 
  Zap, 
  Activity,
  FileCheck,
  Usb,
  FolderLock
} from "lucide-react";

export default function HelpPage() {
  const testScenarios = [
    {
      title: "Scenario 1: Large Payload Attack",
      icon: Activity,
      desc: "Triggers 'Large Payload Anomaly' because packet length exceeds standard MTU boundaries (>2000 bytes). This simulates buffer overflow vectors.",
      cmd: "python attacks/run_all.py  # Select Scenario 1"
    },
    {
      title: "Scenario 2: Suspicious Port Beaconing",
      icon: Terminal,
      desc: "Beaconing to unmapped port 9999 or 6667 is blocked by standard behavioral heuristics to prevent C2 egress beacons.",
      cmd: "python attacks/run_all.py  # Select Scenario 2"
    },
    {
      title: "Scenario 3: DDoS Flood Attack",
      icon: Zap,
      desc: "Triggers temporary IP banning because velocity exceeds the maximum threshold limit of 50 packets per second.",
      cmd: "python attacks/run_all.py  # Select Scenario 3"
    },
    {
      title: "Scenario 4: YARA Malware Scanner",
      icon: FileCheck,
      desc: "Watchdog catches files dropped into 'Simulated_Downloads', compiles rules in 'malware_rules.yar', and moves infected items to Quarantine Vault.",
      cmd: "Copy any test signature file into Simulated_Downloads/"
    },
    {
      title: "Scenario 5: USB Rubber Ducky Defense",
      icon: Usb,
      desc: "Analyzes typing speeds globally. If keystroke delays fall below 50ms (humanly impossible typing velocity), the system initiates instant LockWorkStation sequence.",
      cmd: "Typing superhuman script injections with hardware injection dongles"
    },
    {
      title: "Scenario 6: File Ransomware Guardian",
      icon: FolderLock,
      desc: "System Observer monitors file write patterns in 'senitinel_protected'. If >15 rapid modification events are triggered inside 5s, system locks down.",
      cmd: "Executing batch modifications inside senitinel_protected/"
    }
  ];

  return (
    <div className="flex bg-[#0b0c10] min-h-screen text-[#c5c6c7]">
      <Sidebar />

      <main className="flex-1 flex flex-col p-8 gap-6 overflow-y-auto max-h-screen">
        {/* Header Block */}
        <div className="flex items-center justify-between border-b border-zinc-800/40 pb-4">
          <div>
            <h2 className="text-white font-extrabold text-2xl tracking-tight">Security Diagnostic Suite</h2>
            <p className="text-xs text-zinc-400 mt-1">Audit guides and instructions to trigger and test every firewall threat scenario.</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Manuals Column */}
          <div className="lg:col-span-2 flex flex-col gap-6">
            
            {/* Guide cards */}
            <div className="glass-panel p-6 rounded-2xl flex flex-col gap-4">
              <div>
                <h3 className="text-white font-bold text-lg flex items-center gap-2">
                  🧬 Defensive Diagnostic Scenarios
                </h3>
                <p className="text-xs text-zinc-400 mt-1">
                  Sentinel-X is a full Endpoint Detection and Response (EDR) system. Use our CLI simulation suite to stress-test your defences:
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {testScenarios.map((s, idx) => {
                  const Icon = s.icon;
                  return (
                    <div key={idx} className="p-4 rounded-xl border border-zinc-800 bg-black/10 flex flex-col justify-between gap-3 hover:border-[#45a29e]/40 transition-colors">
                      <div className="flex flex-col gap-2">
                        <div className="flex items-center gap-2 text-white font-bold text-sm">
                          <Icon className="w-5 h-5 text-[#66fcf1]" />
                          {s.title}
                        </div>
                        <p className="text-xs text-zinc-400 font-medium leading-relaxed">
                          {s.desc}
                        </p>
                      </div>
                      <div className="bg-[#11151b] p-2.5 rounded-lg border border-zinc-800 font-mono text-[10px] text-teal-400 select-all overflow-x-auto whitespace-nowrap">
                        {s.cmd}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

          </div>

          {/* Quick FAQ Column */}
          <div className="flex flex-col gap-6">
            <div className="glass-panel p-6 rounded-2xl flex flex-col gap-4">
              <h3 className="text-white font-bold text-lg flex items-center gap-2">
                <HelpCircle className="w-5 h-5 text-[#66fcf1]" />
                Technical Quick Guide
              </h3>

              <div className="flex flex-col gap-4 text-xs font-medium">
                <div className="flex flex-col gap-1 border-b border-zinc-800/60 pb-3">
                  <span className="text-white font-bold">1. How do manual rules work?</span>
                  <p className="text-zinc-400">Manual rules are injected directly into SQLite. When Scapy parses incoming TCP headers, they are checked against memory rule buffers for O(1) microsecond blocking loops.</p>
                </div>
                
                <div className="flex flex-col gap-1 border-b border-zinc-800/60 pb-3">
                  <span className="text-white font-bold">2. What are the active engines?</span>
                  <p className="text-zinc-400">Random Forest evaluates header flags, while Keras LSTM monitors traffic packet volume variations in time-series trends to capture zero-day DDoS signatures.</p>
                </div>

                <div className="flex flex-col gap-1">
                  <span className="text-white font-bold">3. How are PCAPs created?</span>
                  <p className="text-zinc-400">When DPI detects SQLi or XSS payloads inside Scapy Raw layers, the raw packet binary structure is saved into an isolated pcap file for forensic evidence.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
