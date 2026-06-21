"use client";

import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  description: string;
  icon: LucideIcon;
  borderColorClass: string;
  textColorClass: string;
}

export default function MetricCard({
  title,
  value,
  description,
  icon: Icon,
  borderColorClass,
  textColorClass
}: MetricCardProps) {
  return (
    <div className={`glass-panel p-5 rounded-2xl flex items-center justify-between border-l-4 ${borderColorClass} min-w-[220px]`}>
      <div className="flex flex-col gap-1">
        <span className="text-xs font-bold text-zinc-500 uppercase tracking-widest">{title}</span>
        <span className={`text-3xl font-extrabold tracking-tight ${textColorClass}`}>{value}</span>
        <span className="text-[11px] text-zinc-400 font-medium">{description}</span>
      </div>
      <div className={`p-3 rounded-xl bg-zinc-800/40 border border-zinc-700/30 ${textColorClass}`}>
        <Icon className="w-6 h-6 animate-pulse" />
      </div>
    </div>
  );
}
