"use client";

import { useEffect, useState } from "react";
import Sidebar from "@/components/Sidebar";
import { 
  Settings, 
  Trash2, 
  Plus, 
  ShieldAlert, 
  Activity, 
  Save, 
  Loader2,
  CheckCircle2
} from "lucide-react";
import Toastify from "toastify-js";
import "toastify-js/src/toastify.css";

interface Rule {
  id: number;
  type: string;
  value: string;
  time: string;
}

export default function SettingsPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [ruleType, setRuleType] = useState("IP");
  const [ruleValue, setRuleValue] = useState("");
  const [blockingMode, setBlockingMode] = useState("ON");
  const [sensitivity, setSensitivity] = useState(0.80);
  const [mounted, setMounted] = useState(false);
  
  const [isRulesLoading, setIsRulesLoading] = useState(true);
  const [isSaveLoading, setIsSaveLoading] = useState(false);

  // 1. Fetch rules from database
  const loadRules = () => {
    setIsRulesLoading(true);
    fetch("http://127.0.0.1:5000/api/rules")
      .then((r) => r.json())
      .then((data) => {
        setRules(data);
        setIsRulesLoading(false);
      })
      .catch(() => {
        setIsRulesLoading(false);
      });
  };

  // 2. Fetch active settings on load
  useEffect(() => {
    setMounted(true);
    loadRules();
    
    fetch("http://127.0.0.1:5000/api/settings")
      .then((r) => r.json())
      .then((data) => {
        setBlockingMode(data.blocking_mode || "ON");
        setSensitivity(parseFloat(data.sensitivity) || 0.80);
      })
      .catch(() => {});
  }, []);

  // 3. Add block rule
  const addRule = () => {
    if (!ruleValue.trim()) {
      alert("Please enter a valid IP address or Port number!");
      return;
    }

    fetch("http://127.0.0.1:5000/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: ruleType, value: ruleValue })
    })
      .then((r) => r.json())
      .then(() => {
        setRuleValue("");
        loadRules();
        Toastify({
          text: "✅ Custom rule added successfully.",
          duration: 3000,
          close: true,
          gravity: "top",
          position: "right",
          style: { background: "linear-gradient(to right, #45a29e, #66fcf1)", color: "#0b0c10" }
        }).showToast();
      })
      .catch(() => {
        alert("Failed to add custom rule.");
      });
  };

  // 4. Remove block rule
  const deleteRule = (id: number) => {
    if (!confirm("Remove this custom rule?")) return;

    fetch("http://127.0.0.1:5000/api/rules", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    })
      .then((r) => r.json())
      .then(() => {
        loadRules();
        Toastify({
          text: "🗑️ Rule removed successfully.",
          duration: 3000,
          close: true,
          gravity: "top",
          position: "right",
          style: { background: "linear-gradient(to right, #ff416c, #ff4b2b)" }
        }).showToast();
      })
      .catch(() => {
        alert("Failed to remove rule.");
      });
  };

  // 5. Save settings configuration
  const saveSettings = () => {
    setIsSaveLoading(true);
    fetch("http://127.0.0.1:5000/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        blocking_mode: blockingMode,
        sensitivity: sensitivity.toString()
      })
    })
      .then(() => {
        Toastify({
          text: "💾 Configuration saved! Changes applied dynamically.",
          duration: 4000,
          close: true,
          gravity: "top",
          position: "right",
          style: { background: "linear-gradient(to right, #00b09b, #96c93d)" }
        }).showToast();
      })
      .catch(() => {
        alert("Failed to save settings.");
      })
      .finally(() => {
        setIsSaveLoading(false);
      });
  };

  if (!mounted) {
    return null;
  }

  return (
    <div className="flex bg-[#0b0c10] min-h-screen text-[#c5c6c7]">
      <Sidebar />

      <main className="flex-1 flex flex-col p-8 gap-6 overflow-y-auto max-h-screen">
        {/* Header Block */}
        <div className="flex items-center justify-between border-b border-zinc-800/40 pb-4">
          <div>
            <h2 className="text-white font-extrabold text-2xl tracking-tight">System Configuration</h2>
            <p className="text-xs text-zinc-400 mt-1">Configure active firewall blocking policies and customize threshold parameters.</p>
          </div>
          <button
            onClick={saveSettings}
            disabled={isSaveLoading}
            className="bg-[#45a29e] hover:bg-[#66fcf1] disabled:opacity-50 text-[#0b0c10] font-extrabold px-5 py-2.5 rounded-xl flex items-center gap-2 transition-all hover:scale-105 cursor-pointer"
          >
            {isSaveLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            Save Configuration
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Settings Panel */}
          <div className="lg:col-span-2 flex flex-col gap-6">
            
            {/* Custom Rules block */}
            <div className="glass-panel p-6 rounded-2xl flex flex-col gap-4">
              <div>
                <h3 className="text-white font-bold text-lg flex items-center gap-2">
                  ⛔ Custom Blocking Rules
                </h3>
                <p className="text-xs text-zinc-400 mt-1">
                  Inject manual policies to blacklist specific network addresses or closed ports instantly.
                </p>
              </div>

              <div className="flex flex-col sm:flex-row gap-3">
                <select
                  value={ruleType}
                  onChange={(e) => setRuleType(e.target.value)}
                  className="bg-[#11151b] border border-[#45a29e]/30 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-[#66fcf1] cursor-pointer"
                >
                  <option value="IP">Block IP Address</option>
                  <option value="PORT">Block Port</option>
                </select>
                <input
                  type="text"
                  value={ruleValue}
                  onChange={(e) => setRuleValue(e.target.value)}
                  placeholder={ruleType === "IP" ? "e.g. 192.168.1.105" : "e.g. 8080"}
                  className="flex-1 bg-[#11151b] border border-[#45a29e]/30 rounded-xl px-4 py-3 text-sm text-white placeholder-zinc-600 focus:outline-none focus:border-[#66fcf1]"
                />
                <button
                  onClick={addRule}
                  className="bg-rose-500/10 border border-rose-500/30 hover:bg-rose-600 text-rose-400 hover:text-white font-bold px-6 py-3 rounded-xl flex items-center justify-center gap-2 transition-all cursor-pointer"
                >
                  <Plus className="w-4 h-4" />
                  Add Rule
                </button>
              </div>

              {/* Rules List Table */}
              <div className="overflow-x-auto w-full border border-zinc-800/40 rounded-xl bg-black/20">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-[#45a29e]/15 text-zinc-500 font-bold uppercase tracking-widest bg-zinc-800/20">
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Value</th>
                      <th className="py-3 px-4">Date Added</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800/40">
                    {isRulesLoading ? (
                      Array.from({ length: 3 }).map((_, idx) => (
                        <tr key={idx} className="animate-pulse">
                          <td className="py-3.5 px-4"><div className="h-4 w-12 bg-zinc-800 rounded-md"></div></td>
                          <td className="py-3.5 px-4"><div className="h-4 w-28 bg-zinc-800 rounded-md"></div></td>
                          <td className="py-3.5 px-4"><div className="h-4 w-20 bg-zinc-800 rounded-md"></div></td>
                          <td className="py-3.5 px-4 text-right"><div className="h-4 w-6 bg-zinc-800 rounded-md ml-auto"></div></td>
                        </tr>
                      ))
                    ) : rules.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="py-8 text-center text-zinc-500 font-medium">
                          No custom blacklists injected. All manual routes are open.
                        </td>
                      </tr>
                    ) : (
                      rules.map((rule) => (
                        <tr key={rule.id} className="hover:bg-zinc-800/10 text-zinc-300 transition-colors">
                          <td className="py-3.5 px-4">
                            <span className={`px-2 py-0.5 rounded-md font-bold text-[9px] uppercase tracking-wider ${
                              rule.type === "IP" ? "bg-rose-500/10 text-rose-400" : "bg-sky-500/10 text-sky-400"
                            }`}>
                              {rule.type}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 font-mono font-bold text-white">{rule.value}</td>
                          <td className="py-3.5 px-4 text-zinc-500 font-mono text-[10px]">{rule.time}</td>
                          <td className="py-3.5 px-4 text-right">
                            <button
                              onClick={() => deleteRule(rule.id)}
                              className="text-zinc-500 hover:text-rose-500 transition-colors p-1.5 hover:bg-rose-500/10 rounded-lg cursor-pointer"
                              title="Delete rule"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

          </div>

          {/* Sidebar Settings Panel */}
          <div className="flex flex-col gap-6">
            
            {/* Active Defense Block */}
            <div className="glass-panel p-6 rounded-2xl flex flex-col gap-4">
              <div>
                <h3 className="text-white font-bold text-lg flex items-center gap-2">
                  🔥 Firewall Parameters
                </h3>
                <p className="text-xs text-zinc-400 mt-1">Adjust real-time prevention boundaries and classifier thresholds.</p>
              </div>

              {/* Toggle Switch */}
              <div className="p-4 rounded-xl border border-zinc-800/60 bg-black/10 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white uppercase tracking-wider">Active Defense Mode</span>
                  <button
                    onClick={() => setBlockingMode(blockingMode === "ON" ? "OFF" : "ON")}
                    className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                      blockingMode === "ON" ? "bg-rose-500" : "bg-emerald-500"
                    }`}
                  >
                    <span
                      className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                        blockingMode === "ON" ? "translate-x-5" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>
                <div className="flex items-center gap-1.5 mt-1">
                  <span className={`text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-md ${
                    blockingMode === "ON" ? "bg-rose-500/10 text-rose-400" : "bg-emerald-500/10 text-emerald-400"
                  }`}>
                    {blockingMode === "ON" ? "Active Blocking Mode" : "Passive Monitor Only"}
                  </span>
                </div>
                <p className="text-[10px] text-zinc-500 mt-2 font-medium">
                  {blockingMode === "ON" 
                    ? "Threats will be automatically isolated and TCP connections reset." 
                    : "Threats will generate alerts on the stream, but packets are allowed to pass."}
                </p>
              </div>

              {/* Slider Block */}
              <div className="p-4 rounded-xl border border-zinc-800/60 bg-black/10 flex flex-col gap-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-white uppercase tracking-wider">AI Sensitivity Threshold</span>
                  <span className="font-mono font-extrabold text-[#66fcf1] bg-[#66fcf1]/10 px-2 py-0.5 rounded border border-[#66fcf1]/20">
                    {(sensitivity * 100).toFixed(0)}%
                  </span>
                </div>
                <input
                  type="range"
                  min="0.50"
                  max="0.99"
                  step="0.01"
                  value={sensitivity}
                  onChange={(e) => setSensitivity(parseFloat(e.target.value))}
                  className="w-full h-1 bg-zinc-800 rounded-lg appearance-none cursor-pointer accent-[#66fcf1]"
                />
                <div className="flex justify-between text-[10px] text-zinc-500 font-medium">
                  <span>Balanced (Low FP)</span>
                  <span>Paranoid (High FP)</span>
                </div>
              </div>
            </div>

          </div>
        </div>
      </main>
    </div>
  );
}
