"use client";

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useUser } from '@/context/UserContext';
import Camera from '@/components/Camera';

export default function VerifyPage() {
  const [isVerifying, setIsVerifying] = useState(false);
  const router = useRouter();
  const { setUserInfo, deviceId } = useUser();

  const handleCapture = async (blob: Blob) => {
    setIsVerifying(true);
  };

  const completeVerification = (detectedGender: 'M' | 'F', verificationToken: string) => {
    setUserInfo({
      genderVerified: true,
      gender: detectedGender,
      verificationToken
    });
    setIsVerifying(false);
    router.push('/profile');
  };

  return (
    <div className="min-h-screen bg-white relative overflow-hidden flex flex-col items-center pt-24 pb-12">
      <div className="w-full max-w-xl px-6 relative z-10">
        <div className="text-center mb-12 space-y-4">
          <Link href="/" className="inline-flex items-center gap-2 mb-8 group">
             <div className="w-8 h-8 bg-gray-100 rounded-lg flex items-center justify-center group-hover:bg-green-50 transition-colors">
              <span className="text-sm">↩️</span>
            </div>
            <span className="text-xs font-bold text-gray-400 uppercase tracking-widest group-hover:text-primary transition-colors">Back to Home</span>
          </Link>
          
          <h2 className="text-4xl md:text-5xl font-black text-main tracking-tight">
            Smile for the Camera!
          </h2>
          
          <div className="inline-flex flex-wrap justify-center items-center gap-3 px-6 py-3 bg-green-50 rounded-full border border-green-100">
            <span className="flex items-center gap-2 text-[10px] font-bold text-green-600 uppercase tracking-widest">
              <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"/>
              Verifying Gender AI
            </span>
            <span className="text-green-200 text-xs">•</span>
            <span className="text-[10px] font-bold text-green-600 uppercase tracking-widest">Live Capture Only</span>
            <span className="text-green-200 text-xs">•</span>
            <span className="text-[10px] font-bold text-green-600 uppercase tracking-widest">Image Auto Deleted</span>
          </div>
        </div>

        <div className="relative">
           {/* Decorative elements behind camera */}
           <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-[120%] bg-green-500/5 rounded-full blur-3xl -z-10" />
           
           <Camera onCapture={handleCapture} isVerifying={isVerifying} completeVerification={completeVerification} deviceId={deviceId} />
        </div>

        <p className="mt-12 text-center text-xs font-medium text-gray-400 max-w-sm mx-auto leading-relaxed">
          Your privacy is our priority. No images are stored. Only the result is used to ensure safety.
        </p>
      </div>
    </div>
  );
}
