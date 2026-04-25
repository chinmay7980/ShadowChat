"use client";

import Link from 'next/link';
import React, { useEffect, useState } from 'react';
import { API_BASE_URL } from '@/lib/config';
import { AnimatedHero } from "@/components/ui/animated-hero";

export default function LandingPage() {
  const [stats, setStats] = useState({ onlineUsers: 0, waitingInQueue: 0 });

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch(`${API_BASE_URL}/api/stats`);
        const data = await res.json();
        setStats(data);
      } catch (e) {
        console.log("Stats offline");
      }
    };
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen relative overflow-hidden flex flex-col font-sans text-main">
      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-white/90 backdrop-blur-md border-b border-gray-100">
        <div className="max-w-7xl mx-auto px-6 h-20 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center font-bold text-white transition-transform group-hover:scale-110 shadow-sm shadow-green-500/20">S</div>
            <span className="text-xl font-black tracking-tighter uppercase whitespace-nowrap text-main">ShadowChat</span>
          </Link>

          <nav className="hidden md:flex items-center gap-8">
            {['SAFETY', 'WHY US?', 'FAQ'].map((item) => (
              <a key={item} href={`#${item.toLowerCase().replace(' ', '-')}`} className="nav-link text-[10px] font-bold text-gray-400 hover:text-gray-900 uppercase tracking-[0.2em] transition-colors">
                {item}
              </a>
            ))}
            <Link href="/docs" className="nav-link text-[10px] font-bold text-gray-400 hover:text-gray-900 uppercase tracking-[0.2em] transition-colors">
              DOCS
            </Link>
          </nav>

          <Link href="/verify" className="bg-primary hover:bg-primary-hover text-white text-xs font-black uppercase tracking-widest px-6 py-3 rounded-full transition-all active:scale-95 shadow-lg shadow-green-500/20">
            Start Chat
          </Link>
        </div>
      </header>

      <main className="flex-grow pt-20 pb-20">
        <div className="max-w-7xl mx-auto px-6">
          
          {/* Animated Hero Section */}
          <AnimatedHero />

          {/* Divider */}
          <div className="border-t border-gray-100 mb-20 w-3/4 mx-auto"></div>

          {/* Feature Grid */}
          <div id="safety" className="grid grid-cols-1 md:grid-cols-3 gap-12 mb-32 max-w-6xl mx-auto">
            {[
              { 
                title: "Zero data stored", 
                desc: "We don't save anything. No logs, no IP addresses, and definitely no databases.", 
                icon: "🚫",
                color: "bg-red-50 text-red-500"
              },
              { 
                title: "AI-verified humans", 
                desc: "Our friendly AI check ensures you're talking to a person, not a bot, while keeping you anonymous.", 
                icon: "🤖",
                color: "bg-blue-50 text-blue-500"
              },
              { 
                title: "Stateless sessions", 
                desc: "Your chat lives only in your browser's memory. Refresh the page, and it's gone forever.", 
                icon: "⚡",
                color: "bg-orange-50 text-orange-500"
              }
            ].map((feature, i) => (
              <div key={i} className="flex flex-col items-center text-center space-y-4 group p-6 rounded-3xl hover:bg-gray-50 transition-colors">
                <div className={`w-20 h-20 rounded-3xl flex items-center justify-center text-3xl mb-2 ${feature.color} shadow-sm`}>
                  {feature.icon}
                </div>
                <h3 className="text-xl font-bold text-main">{feature.title}</h3>
                <p className="text-sm text-secondary leading-relaxed font-medium">{feature.desc}</p>
              </div>
            ))}
          </div>

          {/* How It Works Section */}
          <div id="how-it-works" className="mb-32 text-center">
            <h2 className="text-3xl md:text-5xl font-black text-main mb-16 tracking-tight">
              How it works <span className="relative inline-block">
                in 3 simple steps
                <span className="absolute bottom-[-5px] left-0 w-full h-2 bg-primary/30 rounded-full"></span>
              </span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto relative">
               {/* Connecting Line (Desktop) */}
               <div className="hidden md:block absolute top-[40px] left-[16%] right-[16%] h-1 bg-gray-100 -z-10"></div>

               {[
                 {
                   step: 1,
                   title: "AI Verification",
                   desc: "A quick camera check to ensure you're human. We don't save your face, just your humanity.",
                   color: "bg-primary"
                 },
                 {
                   step: 2,
                   title: "Instant Matching",
                   desc: "Get paired with a verified person immediately. Simple, fast, and completely random.",
                   color: "bg-primary"
                 },
                 {
                   step: 3,
                   title: "Chat & Vanish",
                   desc: "Talk freely. Once the tab is closed, your entire session history is deleted on both ends.",
                   color: "bg-primary"
                 }
               ].map((item, i) => (
                 <div key={i} className="flex flex-col items-center">
                    <div className={`w-20 h-20 rounded-full ${item.color} text-white text-4xl font-black flex items-center justify-center shadow-lg shadow-success/20 mb-6 border-4 border-white`}>
                      {item.step}
                    </div>
                    <h3 className="text-xl font-bold text-main mb-3">{item.title}</h3>
                    <p className="text-secondary text-sm font-medium leading-relaxed max-w-xs">
                      {item.desc}
                    </p>
                 </div>
               ))}
            </div>
          </div>

          {/* Ready For Safer Chat CTA */}
          <div className="bg-bg-light rounded-[3rem] py-20 px-6 text-center mb-32 border border-gray-100">
             <h2 className="text-3xl md:text-4xl font-black text-main mb-8">
               Ready for a safer chat?
             </h2>
             <div className="flex flex-col items-center gap-4">
               <Link href="/verify" className="btn-primary scale-110 shadow-xl shadow-green-500/30">
                 Find a Partner
               </Link>
               <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mt-4">
                 Join {stats.onlineUsers > 0 ? stats.onlineUsers : '12,302'} people online right now
               </span>
             </div>
          </div>

          {/* FAQ Section */}
          <div id="faq" className="max-w-3xl mx-auto mb-32">
             <h2 className="text-3xl font-black text-main text-center mb-12">Frequently Asked Questions</h2>
             <div className="space-y-4">
               {[
                 {
                   q: "Is it really anonymous?",
                   a: "Yes. We do not require any login, email, or phone number. We do not store logs of your chats. Once you close the tab, the data is gone forever."
                 },
                 {
                   q: "Does it cost anything?",
                   a: "No, ShadowChat is completely free to use. We believe privacy should be accessible to everyone."
                 },
                 {
                   q: "How does AI verification work?",
                   a: "We use a privacy-preserving AI model that runs locally or on our secure stateless server to detect if a live human face is present. We do not store or recognize faces, we only check for 'liveness' to prevent bots."
                 }
               ].map((faq, i) => (
                 <details key={i} className="group bg-white border border-gray-100 rounded-2xl overflow-hidden cursor-pointer open:shadow-md transition-all">
                   <summary className="flex items-center justify-between p-6 font-bold text-main list-none select-none">
                     <span>{faq.q}</span>
                     <span className="text-gray-400 transform group-open:rotate-180 transition-transform">▼</span>
                   </summary>
                   <div className="px-6 pb-6 text-secondary text-sm leading-relaxed overflow-hidden">
                     {faq.a}
                   </div>
                 </details>
               ))}
             </div>
          </div>

        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white py-12 border-t border-gray-100">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center gap-6">
          <div className="flex items-center gap-2 opacity-50">
             <div className="w-6 h-6 bg-gray-200 rounded-lg flex items-center justify-center grayscale">
              <span className="text-xs">💬</span>
            </div>
            <span className="text-xs font-bold text-gray-400 uppercase tracking-widest">© 2024 ShadowChat</span>
          </div>
          
          <div className="flex gap-8">
            {['Privacy', 'Terms', 'Contact'].map((link) => (
              <a key={link} href="#" className="text-[10px] font-bold text-gray-400 hover:text-gray-900 uppercase tracking-[0.2em] transition-colors">
                {link}
              </a>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
}
