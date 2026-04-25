"use client";

import React, { useEffect, useState } from 'react';
import SubHeader from '@/components/SubHeader';
import { API_BASE_URL } from '@/lib/config';

interface Metrics {
  technical: {
    avgMatchTimeMs: string;
    matchTimeLimitMet: boolean;
    activeSessions: number;
    totalMatchesLife: number;
    queueThroughput: number;
  };
  safety: {
    totalReports: number;
    reportRate: string;
    activeBans: number;
  };
  user: {
    verificationSuccessRate: string;
    dropOffAtVerification: number;
  };
}

export default function AdminMetricsPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/admin/metrics`);
        const data = await res.json();
        setMetrics(data);
        setLoading(false);
      } catch (e) {
        console.error("Metrics offline");
      }
    };
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return (
    <div className="min-h-screen bg-black flex items-center justify-center">
      <div className="animate-pulse text-blue-500 font-black tracking-widest uppercase">Initializing Command Center...</div>
    </div>
  );

  return (
    <div className="min-h-screen bg-black bg-mesh flex flex-col">
      <SubHeader />
      
      <div className="flex-1 max-w-6xl w-full mx-auto px-6 py-12">
        <div className="mb-12">
          <h1 className="text-4xl md:text-6xl font-black text-white tracking-tighter mb-4 uppercase">
            Platform <span className="text-blue-500">Pulse</span>
          </h1>
          <p className="text-gray-500 font-bold uppercase tracking-widest text-xs">Real-time Performance & Safety Metrics</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Technical Pillar */}
          <div className="p-8 rounded-[2.5rem] border border-white/10 space-y-8 bg-white/5 backdrop-blur-xl shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-600/20 rounded-xl flex items-center justify-center text-xl">⚡</div>
              <h2 className="text-sm font-black text-white uppercase tracking-widest">Technical Performance</h2>
            </div>
            
            <div className="space-y-6">
              <MetricCard label="Avg Match Time" value={metrics?.technical.avgMatchTimeMs} sub={metrics?.technical.matchTimeLimitMet ? "Within Target (<5s)" : "Above Target"} highlight={metrics?.technical.matchTimeLimitMet} />
              <MetricCard label="Active Sessions" value={metrics?.technical.activeSessions.toString()} sub="Live 1-to-1 rooms" />
              <MetricCard label="Total Matches" value={metrics?.technical.totalMatchesLife.toString()} sub="Lifetime sessions" />
              <MetricCard label="Queue Load" value={metrics?.technical.queueThroughput.toString()} sub="Users searching" />
            </div>
          </div>

          {/* Safety Pillar */}
          <div className="p-8 rounded-[2.5rem] border border-white/10 space-y-8 bg-white/5 backdrop-blur-xl shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-red-600/20 rounded-xl flex items-center justify-center text-xl">🛡️</div>
              <h2 className="text-sm font-black text-white uppercase tracking-widest">Safety & Trust</h2>
            </div>
            
            <div className="space-y-6">
              <MetricCard label="Total Reports" value={metrics?.safety.totalReports.toString()} sub="Community flags" />
              <MetricCard label="Report Rate" value={metrics?.safety.reportRate} sub="Of total matches" />
              <MetricCard label="Active Bans" value={metrics?.safety.activeBans.toString()} sub="Devices restricted" />
              <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center gap-4">
                 <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                 <span className="text-[10px] font-black text-red-500 uppercase tracking-widest">Anti-Spam Engine Active</span>
              </div>
            </div>
          </div>

          {/* User Pillar */}
          <div className="p-8 rounded-[2.5rem] border border-white/10 space-y-8 bg-white/5 backdrop-blur-xl shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-purple-600/20 rounded-xl flex items-center justify-center text-xl">👥</div>
              <h2 className="text-sm font-black text-white uppercase tracking-widest">User Lifecycle</h2>
            </div>
            
            <div className="space-y-6">
              <MetricCard label="Verification Success" value={metrics?.user.verificationSuccessRate} sub="AI Authenticity rate" highlight={true} />
              <MetricCard label="Verification Drop-off" value={metrics?.user.dropOffAtVerification.toString()} sub="Users failed/left" color="text-purple-400" />
              <div className="h-24 w-full bg-white/5 rounded-2xl flex items-center justify-center border border-white/5">
                 <p className="text-[8px] font-black text-gray-500 uppercase tracking-widest">Retention Metrics Coming Soon</p>
              </div>
            </div>
          </div>
        </div>

        <div className="mt-12 flex justify-between items-center text-[10px] text-gray-700 font-black uppercase tracking-[0.2em] border-t border-white/5 pt-8">
          <span>© 2026 Admin Command Center</span>
          <button onClick={() => window.location.reload()} className="hover:text-blue-500 transition-colors">Force Refresh Channel</button>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value, sub, highlight = false, color = "text-white" }: { label: string, value: any, sub: string, highlight?: boolean, color?: string }) {
  return (
    <div className="group">
      <p className="text-[8px] font-black text-gray-500 uppercase tracking-widest mb-1 group-hover:text-blue-500 transition-colors">{label}</p>
      <div className="flex items-baseline gap-2">
        <span className={`text-2xl font-black tracking-tight ${highlight ? 'text-blue-400 text-glow-small' : color}`}>{value}</span>
        <span className="text-[10px] font-bold text-gray-600 uppercase tracking-wide">{sub}</span>
      </div>
    </div>
  );
}
