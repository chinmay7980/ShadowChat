"use client";

import Link from 'next/link';

export default function SubHeader() {
  return (
    <header className="w-full max-w-7xl mx-auto px-6 py-6 flex justify-between items-center mb-10">
      <Link href="/" className="flex items-center gap-2 group">
        <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center font-bold text-white transition-transform group-hover:scale-110 shadow-sm shadow-green-500/20">S</div>
        <span className="text-xl font-black tracking-tighter uppercase whitespace-nowrap text-main">ShadowChat</span>
      </Link>
      <div className="flex items-center gap-3">
        <Link href="/docs" className="text-[10px] font-black uppercase tracking-widest text-gray-400 hover:text-gray-700 transition-colors">
          Documentation
        </Link>
        <div className="px-4 py-1.5 rounded-full border border-gray-100 bg-white text-[10px] font-black uppercase tracking-widest text-gray-400 flex items-center gap-2 shadow-sm">
          <span className="text-secondary">🔒</span>
          Secure Session
        </div>
      </div>
    </header>
  );
}
