"use client";

import React, { useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { io } from 'socket.io-client';
import { useUser } from '@/context/UserContext';
import { SOCKET_URL } from '@/lib/config';

import SubHeader from '@/components/SubHeader';

function EndPageContent() {
  const router = useRouter();
  const { deviceId } = useUser();
  const searchParams = useSearchParams();
  const isReport = searchParams.get('report') === 'true';
  const [blockUser, setBlockUser] = useState(false);

  const handleBlockToggle = () => {
    const newState = !blockUser;
    setBlockUser(newState);
    
    if (newState && deviceId) {
      const targetDeviceId = sessionStorage.getItem('report_target');
      if (targetDeviceId && targetDeviceId !== deviceId) {
        const socket = io(SOCKET_URL, {
          reconnection: true,
          reconnectionAttempts: 5,
          timeout: 10000,
          transports: ['websocket', 'polling']
        });
        socket.on('connect', () => {
          socket.emit('block_user', { 
            myDeviceId: deviceId, 
            targetDeviceId: targetDeviceId 
          });
          setTimeout(() => socket.disconnect(), 1000);
        });
      }
    }
  };

  return (
    <div className="min-h-screen bg-white font-sans text-main">
      <SubHeader />
      
      <div className="max-w-md mx-auto px-6 pb-20 text-center">
        <div className="bg-white p-10 rounded-[2.5rem] border border-gray-200 shadow-xl shadow-gray-100 relative overflow-hidden">
          
          <div className="w-24 h-24 bg-gray-50 border border-gray-100 rounded-full flex items-center justify-center mx-auto mb-8 group">
             <div className={`w-16 h-16 rounded-full flex items-center justify-center shadow-lg transition-all ${isReport ? 'bg-red-500 shadow-red-500/30' : 'bg-primary shadow-green-500/30'}`}>
                {isReport ? (
                  <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                ) : (
                  <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                  </svg>
                )}
             </div>
          </div>

          <div className="mb-10">
            <h2 className="text-3xl font-black tracking-tighter mb-2 uppercase text-main">
              {isReport ? 'Protocol Noted' : 'Session Closed'}
            </h2>
            <p className="text-[10px] text-gray-400 font-bold uppercase tracking-[0.2em] px-4 leading-relaxed">
              {isReport 
                ? 'Your report has been logged. We prioritize community safety above all.'
                : 'All ephemeral data associated with this session has been destroyed.'}
            </p>
          </div>

          <div className="space-y-4 mb-10">
            <button 
              onClick={handleBlockToggle}
              className={`w-full py-5 rounded-2xl font-black text-[10px] uppercase tracking-[0.2em] transition-all border flex items-center justify-center gap-3 active:scale-[0.98] ${
                blockUser 
                  ? 'bg-red-500 border-red-400 text-white shadow-lg shadow-red-500/20' 
                  : 'bg-gray-50 border-gray-100 text-gray-400 hover:bg-gray-100 hover:text-gray-600'
              }`}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
              {blockUser ? 'Channel Blocked' : 'Block User Permanently'}
            </button>
          </div>

          <div className="space-y-4">
            <button 
              onClick={() => router.push('/matching')}
              className="w-full py-5 bg-primary text-white rounded-2xl font-black text-xs uppercase tracking-[0.2em] transition-all hover:bg-primary-hover shadow-xl shadow-green-500/20 active:scale-[0.98]"
            >
              Find New Match
            </button>
            <button 
              onClick={() => router.push('/')}
              className="w-full py-5 bg-white border border-gray-200 text-gray-400 rounded-2xl font-black text-[10px] uppercase tracking-[0.2em] transition-all hover:bg-gray-50 hover:text-gray-600 active:scale-[0.98]"
            >
              Return to Core
            </button>
          </div>
        </div>

        <p className="mt-12 text-[10px] text-gray-400 font-bold uppercase tracking-widest max-w-xs mx-auto leading-relaxed">
          Zero logs kept. No tracking traces left. This session is now a ghost of the past.
        </p>
      </div>
    </div>
  );
}

export default function EndClient() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-white font-sans text-main flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
      </div>
    }>
      <EndPageContent />
    </Suspense>
  );
}

