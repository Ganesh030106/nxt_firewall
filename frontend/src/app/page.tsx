"use client";

import { useEffect, useState, useRef } from "react";
import Sidebar from "@/components/Sidebar";
import MetricCard from "@/components/MetricCard";
import PhishingScan from "@/components/PhishingScan";
import LogTable from "@/components/LogTable";
import { io } from "socket.io-client";
import Toastify from "toastify-js";
import "toastify-js/src/toastify.css";
import { 
  ShieldAlert, 
  Activity, 
  Binary, 
  FolderLock, 
  Search, 
  AlertCircle,
  RefreshCw
} from "lucide-react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from "chart.js";

// Register ChartJS elements
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export default function Dashboard() {
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("ALL");
  const [isLoading, setIsLoading] = useState(true);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({
    blocked_count: 0,
    total_events: 0,
    ai_detections: 0,
    dpi_alerts: 0,
    ransomware_detections: 0
  });
  const [chartData, setChartData] = useState<{
    labels: string[];
    values: number[];
  }>({ labels: [], values: [] });
  const [systemStatus, setSystemStatus] = useState("OFFLINE");
  const [ransomwareAlert, setRansomwareAlert] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const visContainerRef = useRef<HTMLDivElement>(null);
  const networkInstanceRef = useRef<any>(null);

  const handleBlockNode = (ip: string) => {
    if (!confirm(`Are you sure you want to block IP address ${ip}?`)) return;
    fetch("http://127.0.0.1:5000/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "IP", value: ip })
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.status === "added" || data.status === "success") {
          Toastify({
            text: `🚫 IP Address ${ip} has been blocked successfully!`,
            duration: 4000,
            close: true,
            gravity: "top",
            position: "right",
            style: { background: "linear-gradient(to right, #ff4d4d, #cc0000)" }
          }).showToast();
          fetchDashboardData();
          setSelectedNode(null);
        }
      })
      .catch((err) => {
        console.error("Failed to block IP:", err);
      });
  };

  const handleWhitelistNode = (ip: string) => {
    if (!confirm(`Are you sure you want to whitelist IP address ${ip}?`)) return;
    fetch("http://127.0.0.1:5000/api/whitelist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.status === "added" || data.status === "success") {
          Toastify({
            text: `🟢 IP Address ${ip} whitelisted successfully!`,
            duration: 4000,
            close: true,
            gravity: "top",
            position: "right",
            style: { background: "linear-gradient(to right, #00b09b, #96c93d)" }
          }).showToast();
          fetchDashboardData();
          setSelectedNode(null);
        }
      })
      .catch((err) => {
        console.error("Failed to whitelist IP:", err);
      });
  };

  // Fetch Dashboard Telemetry Data
  const fetchDashboardData = () => {
    fetch(`http://127.0.0.1:5000/api/data?search=${encodeURIComponent(search)}&action=${encodeURIComponent(actionFilter)}`)
      .then((r) => r.json())
      .then((data) => {
        setLogs(data.logs);
        setStats(data.stats);
        setChartData(data.chart_data);
        setSystemStatus(data.status);
        
        // Detect Ransomware Alert
        const hasRansomware = data.logs.some((log: any) => 
          log.reason.includes("Rapid Encryption") || log.reason.includes("Ransomware")
        );
        setRansomwareAlert(hasRansomware);
        setIsLoading(false);
      })
      .catch(() => {
        setSystemStatus("OFFLINE");
        setIsLoading(false);
      });
  };

  // 1. Initial Load and Socket.IO Connection
  useEffect(() => {
    setMounted(true);
    fetchDashboardData();

    // Establish WebSocket Connection with Flask
    const socket = io("http://127.0.0.1:5000");

    socket.on("connect", () => {
      console.log("✅ WebSocket Stream Established");
    });

    socket.on("force_update", () => {
      console.log("⚡ Signal Received: Syncing Dashboard");
      fetchDashboardData();
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  // 2. Refresh on search/filter changes
  useEffect(() => {
    fetchDashboardData();
  }, [search, actionFilter]);

  // 3. Dynamic vis-network Loader & Graph Initializer
  useEffect(() => {
    let active = true;
    let topologyInterval: NodeJS.Timeout;

    import("vis-network").then((visModule: any) => {
      if (!active) return;

      const initGraph = () => {
        if (!visContainerRef.current || !active) return;

        fetch("http://127.0.0.1:5000/api/graph_data")
          .then((r) => r.json())
          .then((graphData) => {
            if (!active) return;
            
            const nodes = new visModule.DataSet(graphData.nodes);
            const edges = new visModule.DataSet(
              graphData.edges.map((e: any) => ({
                ...e,
                id: `${e.from}-${e.to}`
              }))
            );

            const data = { nodes, edges };
            const options = {
              physics: { stabilization: false },
              nodes: {
                font: { color: "#ffffff", size: 12 },
                borderWidth: 2,
                shadow: true
              },
              edges: {
                width: 1.5,
                shadow: true
              }
            };

            if (networkInstanceRef.current) {
              try {
                networkInstanceRef.current.destroy();
              } catch (e) {
                console.error("Error destroying network:", e);
              }
            }

            networkInstanceRef.current = new visModule.Network(
              visContainerRef.current,
              data,
              options
            );

            // Add click event listener to inspect threat node
            networkInstanceRef.current.on("click", (params: any) => {
              if (params.nodes && params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                if (nodeId !== "You") {
                  setSelectedNode(nodeId);
                } else {
                  setSelectedNode(null);
                }
              } else {
                setSelectedNode(null);
              }
            });
          })
          .catch((err) => {
            console.error("Error fetching graph data:", err);
          });
      };

      initGraph();

      // Refresh Topology every 6 seconds
      topologyInterval = setInterval(() => {
        initGraph();
      }, 6000);
    }).catch((err) => {
      console.error("Failed to load vis-network dynamically:", err);
    });

    return () => {
      active = false;
      if (topologyInterval) {
        clearInterval(topologyInterval);
      }
      if (networkInstanceRef.current) {
        try {
          networkInstanceRef.current.destroy();
        } catch (e) {
          console.error("Error destroying network on unmount:", e);
        }
        networkInstanceRef.current = null;
      }
    };
  }, []);

  // Line Chart styling & configurations
  const chartConfigs = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false }
    },
    scales: {
      y: {
        ticks: { color: "#c5c6c7" },
        grid: { color: "rgba(69, 162, 158, 0.15)" }
      },
      x: {
        ticks: { color: "#c5c6c7" },
        grid: { color: "rgba(69, 162, 158, 0.15)" }
      }
    }
  };

  const lineChartData = {
    labels: chartData.labels.length > 0 ? chartData.labels : ["00:00"],
    datasets: [
      {
        label: "Packets Sniffed",
        data: chartData.values.length > 0 ? chartData.values : [0],
        borderColor: "#66fcf1",
        backgroundColor: "rgba(102, 252, 241, 0.08)",
        borderWidth: 2,
        tension: 0.4,
        fill: true,
        pointBackgroundColor: "#66fcf1"
      }
    ]
  };

  if (!mounted) {
    return (
      <div className="flex bg-[#0b0c10] min-h-screen text-[#c5c6c7] items-center justify-center font-mono">
        <div className="flex flex-col items-center gap-3">
          <Activity className="w-8 h-8 text-[#66fcf1] animate-spin" />
          <span>Synchronizing Sentinel-X Secure Session...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex bg-[#0b0c10] min-h-screen text-[#c5c6c7]">
      <Sidebar />

      {/* Main Panel Content */}
      <main className="flex-1 flex flex-col p-8 gap-6 overflow-y-auto max-h-screen">
        {/* Top Header Shell */}
        <div className="flex items-center justify-between border-b border-zinc-800/40 pb-4">
          <div>
            <h2 className="text-white font-extrabold text-2xl tracking-tight">Security Command Center</h2>
            <p className="text-xs text-zinc-400 mt-1">Real-time threat telemetry dashboard and self-healing active defenses.</p>
          </div>
          <div className="flex items-center gap-3">
            <button 
              onClick={fetchDashboardData}
              className="p-2.5 bg-zinc-800/60 hover:bg-zinc-700/60 border border-zinc-700/30 rounded-xl text-[#66fcf1] transition-all hover:scale-105"
              title="Force Sync"
            >
              <RefreshCw className="w-5 h-5" />
            </button>
            <div className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border font-bold text-xs ${
              systemStatus === "ONLINE" 
                ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" 
                : "bg-rose-500/10 border-rose-500/20 text-rose-400"
            }`}>
              <span className={`h-2 w-2 rounded-full ${
                systemStatus === "ONLINE" ? "bg-emerald-400 heartbeat-dot" : "bg-rose-400"
              }`} />
              System Status: {systemStatus}
            </div>
          </div>
        </div>

        {/* Ransomware Alert Banner */}
        {ransomwareAlert && (
          <div className="bg-rose-500/15 border border-rose-500/30 p-4 rounded-2xl flex items-center gap-3 text-rose-400 font-bold justify-center animate-bounce">
            <AlertCircle className="w-6 h-6 animate-pulse" />
            🚨 CRITICAL ALERT: RANSOMWARE ENCRYPTION VECTORS ISOLATED IN PROTECTED VAULT! 🚨
          </div>
        )}

        {/* 1. Threat Search Bar */}
        <div className="glass-panel p-4 rounded-2xl flex flex-col md:flex-row gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-500 w-4 h-4" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by IP, Protocol, or threat details..."
              className="w-full bg-[#11151b] border border-[#45a29e]/30 rounded-xl pl-11 pr-4 py-3 text-sm text-white focus:outline-none focus:border-[#66fcf1] placeholder-zinc-500 transition-all"
            />
          </div>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="bg-[#11151b] border border-[#45a29e]/30 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-[#66fcf1] transition-all min-w-[160px] cursor-pointer"
          >
            <option value="ALL">All Traffic Flow</option>
            <option value="BLOCKED">🚫 Blocked Only</option>
            <option value="ALERT">⚠️ Alerts Only</option>
            <option value="ALLOWED">🟢 Allowed Only</option>
          </select>
        </div>

        {/* 2. Metric Telemetry Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            title="Threats Blocked"
            value={stats.blocked_count}
            description="Total isolated flow threads"
            icon={ShieldAlert}
            borderColorClass="border-rose-500"
            textColorClass="text-rose-500"
          />
          <MetricCard
            title="AI Detections"
            value={stats.ai_detections}
            description="LSTM Sequence anomalies"
            icon={Activity}
            borderColorClass="border-sky-500"
            textColorClass="text-sky-400"
          />
          <MetricCard
            title="DPI Alerts"
            value={stats.dpi_alerts}
            description="SQL Injection & XSS logs"
            icon={Binary}
            borderColorClass="border-amber-500"
            textColorClass="text-amber-400"
          />
          <MetricCard
            title="Ransomware"
            value={stats.ransomware_detections}
            description="Rapid encryption blocks"
            icon={FolderLock}
            borderColorClass="border-rose-500"
            textColorClass="text-rose-400"
          />
        </div>

        {/* 3. Traffic chart & phishing scanner */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="glass-panel p-6 rounded-2xl lg:col-span-2 flex flex-col gap-3">
            <h4 className="text-white font-bold text-lg flex items-center gap-2">
              📈 Network Traffic Velocity
            </h4>
            <div className="h-[240px] w-full relative">
              <Line data={lineChartData} options={chartConfigs} />
            </div>
          </div>
          <div className="flex flex-col gap-6">
            <PhishingScan />
          </div>
        </div>

        {/* 4. Vis.js Network Topology Map & Active Command Control */}
        <div className="glass-panel p-6 rounded-2xl flex flex-col gap-3">
          <div>
            <h4 className="text-white font-bold text-lg flex items-center gap-2">
              🕸️ Live Threat Topology Map & Active Command Control
            </h4>
            <p className="text-xs text-zinc-500 mt-0.5">Canvas visualization of nodes routing traffic to your host network. Click any threat node to inspect and apply actions.</p>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 relative">
              <div 
                ref={visContainerRef} 
                className="w-full h-[380px] rounded-xl border border-[#45a29e]/20 bg-[#0b0c10] overflow-hidden" 
              />
            </div>
            
            {/* Threat Node Inspector Panel */}
            <div className="bg-[#11151b]/80 border border-[#45a29e]/15 rounded-xl p-5 flex flex-col justify-between h-[380px]">
              {!selectedNode ? (
                <div className="flex flex-col items-center justify-center text-center h-full gap-3 text-zinc-500">
                  <ShieldAlert className="w-12 h-12 text-[#45a29e]/40 animate-pulse" />
                  <p className="font-bold text-sm text-zinc-400">Node Inspector Idle</p>
                  <p className="text-xs max-w-[200px]">Select any peripheral network node on the map to query, block, or whitelist it.</p>
                </div>
              ) : (
                <div className="flex flex-col justify-between h-full gap-4 text-xs">
                  <div className="flex flex-col gap-3.5">
                    <div className="flex items-center justify-between border-b border-zinc-800/80 pb-2.5">
                      <span className="font-bold text-[#66fcf1] tracking-wider uppercase">Threat Inspector</span>
                      <button 
                        onClick={() => setSelectedNode(null)} 
                        className="text-zinc-500 hover:text-white font-bold px-1.5 cursor-pointer"
                      >
                        ✕
                      </button>
                    </div>
                    
                    <div className="flex flex-col gap-1">
                      <span className="text-[10px] text-zinc-500 uppercase tracking-widest font-extrabold">Node IP Address</span>
                      <span className="text-base font-mono font-extrabold text-white bg-[#0b0c10] px-3 py-2 rounded-lg border border-zinc-800/60 inline-block tracking-tight">{selectedNode}</span>
                    </div>

                    <div className="flex flex-col gap-1.5 mt-1">
                      <span className="text-[10px] text-zinc-500 uppercase tracking-widest font-extrabold">Detected Context</span>
                      <div className="flex flex-col gap-1.5 bg-zinc-900/40 p-3 rounded-lg border border-zinc-800/30">
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Threat Status:</span>
                          <span className="font-bold text-rose-400">POTENTIAL ATTACKER</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-zinc-400">Traffic Source:</span>
                          <span className="font-mono text-[#c5c6c7]">External Node</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col gap-2 mt-auto">
                    <button
                      onClick={() => handleBlockNode(selectedNode)}
                      className="w-full py-2.5 bg-rose-600 hover:bg-rose-500 border border-rose-500/30 hover:scale-[1.02] text-white font-extrabold rounded-lg transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      🚫 Block IP Address
                    </button>
                    <button
                      onClick={() => handleWhitelistNode(selectedNode)}
                      className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 border border-emerald-500/30 hover:scale-[1.02] text-white font-extrabold rounded-lg transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      🟢 Whitelist IP Address
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* 5. Real-Time Log Table */}
        <LogTable logs={logs} isLoading={isLoading} onRefresh={fetchDashboardData} />
      </main>
    </div>
  );
}
