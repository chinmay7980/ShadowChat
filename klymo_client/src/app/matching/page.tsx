"use client";

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useUser } from '@/context/UserContext';
import { io, Socket } from 'socket.io-client';
import SubHeader from '@/components/SubHeader';
import { SOCKET_URL } from '@/lib/config';

let socket: Socket;

export default function MatchingPage() {
  const router = useRouter();
  const { nickname, gender, matchPreference, deviceId, bio, genderVerified, verificationToken } = useUser();
  const [status, setStatus] = useState('Searching...');
  const [errorStatus, setErrorStatus] = useState<string | null>(null);

  useEffect(() => {
    setStatus('Initializing...');
    socket = io(SOCKET_URL, {
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 500,
      reconnectionDelayMax: 3000,
      timeout: 15000,
      transports: ['websocket', 'polling']
    });

    socket.on('connect', () => {
      setStatus('Searching...');
      setErrorStatus(null);
      if (!genderVerified || !gender || !verificationToken) {
        setErrorStatus('Verification required. Please verify before matching.');
        socket.disconnect();
        return;
      }
      socket.emit('join_queue', {
        nickname,
        gender,
        matchPreference,
        deviceId,
        bio,
        genderVerified,
        verificationToken
      });
    });

    socket.on('connect_error', (err) => {
      console.error('Connection Error:', err);
      setErrorStatus('Shield Offline: Could not connect to the matching mainframe.');
    });

    socket.on('match_found', (data) => {
      setStatus('Match Found!');
      sessionStorage.setItem('current_room', data.roomId);
      sessionStorage.setItem('partner_info', JSON.stringify(data.partner));
      
      setTimeout(() => {
        router.push('/chat');
      }, 1500);
    });

    socket.on('error', ({ message }) => {
      setErrorStatus(message);
    });

    return () => {
      if (socket) socket.disconnect();
    };
  }, [nickname, gender, matchPreference, deviceId, bio, genderVerified, verificationToken, router]);

  return (
    <div className="min-h-screen bg-white font-sans text-main">
      <SubHeader />
      
      <div className="max-w-md mx-auto px-6 pb-20 text-center flex flex-col items-center">
        
        <div className="mb-16 space-y-2">
           <h1 className="text-4xl font-black tracking-tight text-main">Finding your match...</h1>
           <p className="text-[10px] text-gray-400 font-bold uppercase tracking-[0.2em]">Step 03: Matchmaking Engine</p>
        </div>

        {/* Pulse Animation Circle */}
        <div className="relative mb-20">
           {/* Ripple Effect */}
           <div className="absolute inset-0 bg-green-500/10 rounded-full animate-ping [animation-duration:3s]" />
           <div className="absolute inset-4 bg-green-500/20 rounded-full animate-ping [animation-duration:3s] [animation-delay:0.5s]" />
           
           {/* Center Circle */}
           <div className="relative w-64 h-64 bg-gradient-to-br from-gray-50 to-white rounded-full border border-gray-100 shadow-[0_20px_50px_-12px_rgba(98,209,22,0.2)] flex flex-col items-center justify-center z-10">
              <div className="text-5xl mb-4 text-primary animate-bounce-slow">
                 {errorStatus ? '⚠️' : status === 'Match Found!' ? '🎉' : '🔍'}
              </div>
              <div className={`text-xs font-black uppercase tracking-widest ${errorStatus ? 'text-red-500' : 'text-primary'}`}>
                {errorStatus || status}
              </div>
           </div>
        </div>

        {errorStatus && (
          <div className="mb-12 animate-in fade-in slide-in-from-top-4 duration-500">
            <div className="max-w-xs mx-auto p-4 bg-red-50 border border-red-100 rounded-2xl mb-6">
              <p className="text-[10px] font-bold text-red-500 uppercase tracking-widest leading-relaxed">
                {errorStatus}
              </p>
            </div>
            <button 
              onClick={() => window.location.reload()}
              className="px-8 py-3 bg-red-500 text-white rounded-full font-black text-[10px] uppercase tracking-widest hover:bg-red-600 transition-all shadow-lg shadow-red-500/20"
            >
              Force Recalibrate
            </button>
          </div>
        )}

        <div className="space-y-8 w-full max-w-sm">
           <p className="text-xs text-gray-400 font-medium max-w-xs mx-auto leading-relaxed">
            Scanning for a friendly human who matches your preferences...
           </p>

           <div className="flex justify-center gap-3">
             {['Search', 'Identify', 'Connect'].map((step, i) => {
               const isActive = (status === 'Searching...' && i === 0) || (status === 'Match Found!' && i === 1);
               return (
                <div key={i} className={`px-6 py-2.5 rounded-full text-[10px] font-black uppercase tracking-widest transition-all ${
                  isActive
                  ? 'bg-primary text-white shadow-lg shadow-green-500/30'
                  : 'bg-gray-100 text-gray-400'
                }`}>
                  {step}
                </div>
               );
             })}
           </div>
        </div>

      </div>
    </div>
  );
}
