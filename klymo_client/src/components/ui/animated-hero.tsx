"use client";

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { MoveRight, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import Link from 'next/link';

function AnimatedHero() {
  const [titleNumber, setTitleNumber] = useState(0);
  const titles = useMemo(
    () => ["secure", "private", "anonymous", "ephemeral", "safe"],
    []
  );

  useEffect(() => {
    const timeoutId = setTimeout(() => {
      if (titleNumber === titles.length - 1) {
        setTitleNumber(0);
      } else {
        setTitleNumber(titleNumber + 1);
      }
    }, 2000);
    return () => clearTimeout(timeoutId);
  }, [titleNumber, titles]);

  return (
    <div className="w-full relative z-20">
      <div className="container mx-auto px-4">
        <div className="flex gap-4 pt-2 pb-20 lg:pt-4 lg:pb-32 items-center justify-center flex-col">
          <div>
            <Button variant="secondary" size="sm" className="gap-2 rounded-full px-4 h-8 text-xs font-bold tracking-wider uppercase border-green-100 bg-green-50 text-green-600 hover:bg-green-100">
               <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
               Join 12,302 people online <MoveRight className="w-3 h-3" />
            </Button>
          </div>
          
          {/* Green Lock Icon */}
          <div className="relative w-28 h-28 flex items-center justify-center">
            <div className="absolute inset-0 bg-[#62D116]/20 rounded-full blur-2xl animate-pulse"></div>
            <div className="relative text-7xl drop-shadow-sm transform -rotate-12">
              <span className="bg-[#62D116] text-white p-4 rounded-3xl shadow-xl flex items-center justify-center w-24 h-24">
                🔒
              </span>
            </div>
          </div>

          <div className="flex gap-4 flex-col items-center">
            <h1 className="text-5xl md:text-7xl max-w-4xl tracking-tight text-center font-black text-[#2D2D2D] leading-[1.1]">
              <span className="text-[#2D2D2D]">Private chats, minus the anxiety. This is </span>
              <span className="relative flex w-full justify-center overflow-hidden text-center md:pb-4 md:pt-1 h-[1.2em]">
                &nbsp;
                {titles.map((title, index) => (
                  <motion.span
                    key={index}
                    className="absolute font-black text-[#62D116]"
                    initial={{ opacity: 0, y: "-100" }}
                    transition={{ type: "spring", stiffness: 50 }}
                    animate={
                      titleNumber === index
                        ? {
                            y: 0,
                            opacity: 1,
                          }
                        : {
                            y: titleNumber > index ? -150 : 150,
                            opacity: 0,
                          }
                    }
                  >
                    {title}
                  </motion.span>
                ))}
              </span>
            </h1>

            <p className="text-lg md:text-xl leading-relaxed tracking-tight text-[#757575] max-w-2xl text-center font-medium mt-4">
              No accounts, no history, and no trackers. Just simple, friendly 
              conversations that disappear when you're done.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row gap-4 mt-6">
            <Link href="/verify">
              <Button size="lg" className="gap-4 w-full sm:w-auto text-lg shadow-xl shadow-green-500/20 active:scale-95 transition-all">
                Start Chatting <MoveRight className="w-5 h-5" />
              </Button>
            </Link>
            <Link href="#how-it-works">
               <Button size="lg" variant="secondary" className="gap-4 w-full sm:w-auto text-lg hover:bg-gray-50 active:scale-95 transition-all text-gray-600">
                How it works
              </Button>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

export { AnimatedHero };
