"use client";

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useUser } from '@/context/UserContext';
import { DeviceIdentity } from '@/lib/device';
import { Filter } from 'bad-words';
import SubHeader from '@/components/SubHeader';

const profanityFilter = new Filter();

export default function ProfilePage() {
  const router = useRouter();
  const { nickname, bio, matchPreference, setUserInfo, gender } = useUser();
  const [localNickname, setLocalNickname] = useState(nickname);
  const [localBio, setLocalBio] = useState(bio);
  const [localPreference, setLocalPreference] = useState(matchPreference);
  const [error, setError] = useState('');
  const [matchesLeft, setMatchesLeft] = useState<number | null>(null);

  useEffect(() => {
    const count = DeviceIdentity.getMatchCount();
    setMatchesLeft(100 - count);
  }, []);

  const handleStartMatching = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const cleanNickname = localNickname.trim();
    const cleanBio = localBio.trim();

    if (cleanNickname.length < 3) {
      setError('Nickname must be at least 3 characters.');
      return;
    }

    if (cleanBio.length < 10) {
      setError('Bio must be at least 10 characters.');
      return;
    }

    if (profanityFilter.isProfane(cleanNickname) || profanityFilter.isProfane(cleanBio)) {
      setError('Please avoid using profanity in your profile.');
      return;
    }

    const emojiMatch = cleanBio.match(/[\uD800-\uDBFF][\uDC00-\uDFFF]|\u261D|\u263A|\u2639|\u2665|\u2708|\u2709|\u270C|\u270D|[\u2702-\u27B0]/g);
    if (emojiMatch && emojiMatch.length > 5) {
      setError('Maximum 5 emojis allowed in bio.');
      return;
    }

    if (DeviceIdentity.isLimitReached()) {
      setError('Daily match limit reached. Please come back tomorrow.');
      return;
    }

    setUserInfo({
      nickname: localNickname,
      bio: localBio,
      matchPreference: localPreference
    });

    router.push('/matching');
  };

  return (
    <div className="min-h-screen bg-white font-sans text-main">
      <SubHeader />
      
      <div className="max-w-xl mx-auto px-6 pb-20">
        
        {/* Progress Bar */}
        <div className="flex justify-center mb-12">
           <div className="w-64 h-2 bg-gray-100 rounded-full overflow-hidden">
             <div className="w-2/3 h-full bg-primary rounded-full" />
           </div>
        </div>

        <div className="text-center mb-10">
          <h1 className="text-3xl md:text-4xl font-black tracking-tight text-main mb-2">Tell us a bit about you</h1>
          <p className="text-[10px] text-gray-400 font-bold uppercase tracking-[0.2em]">Step 02: Your Identity</p>
        </div>

        <div className="bg-white border border-gray-200 shadow-xl shadow-gray-100/50 p-8 rounded-[2rem]">
          
          <form onSubmit={handleStartMatching} className="space-y-8">
            {/* Nickname & Gender Status Row */}
            <div className="flex flex-col md:flex-row gap-6">
                <div className="flex-1 space-y-2">
                    <div className="flex justify-between">
                        <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest ml-1">Nickname</label>
                    </div>
                    <div className="relative">
                        <span className="absolute left-4 top-1/2 -translate-y-1/2 text-xs font-bold text-gray-300">face</span>
                        <input 
                            type="text"
                            value={localNickname}
                            onChange={(e) => setLocalNickname(e.target.value)}
                            placeholder="Swift Panda"
                            required
                            className="w-full bg-gray-50 border border-gray-100 rounded-2xl pl-14 pr-16 py-4 focus:outline-none focus:border-primary/50 focus:ring-2 focus:ring-primary/10 transition-all text-sm font-bold text-main placeholder:text-gray-300"
                        />
                        <button type="button" className="absolute right-4 top-1/2 -translate-y-1/2 text-[10px] font-bold text-blue-400 uppercase hover:text-blue-500">
                            refresh
                        </button>
                    </div>
                </div>

                <div className="space-y-2 min-w-[140px]">
                    <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest ml-1 text-right block">AI Status</label>
                    <div className={`h-[54px] flex items-center justify-center rounded-2xl text-[10px] font-black uppercase tracking-wider px-4 border ${gender ? 'bg-green-50 text-green-600 border-green-100' : 'bg-gray-50 text-gray-400 border-gray-100'}`}>
                        {gender ? (
                            <>
                              <span className="w-1.5 h-1.5 rounded-full bg-green-500 mr-2 animate-pulse"></span>
                               Verified {gender === 'M' ? 'Male' : 'Female'}
                            </>
                        ) : 'Not Verified'}
                    </div>
                </div>
            </div>

            {/* Bio */}
            <div className="space-y-2">
              <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest ml-1">Short Bio</label>
              <textarea 
                value={localBio}
                onChange={(e) => setLocalBio(e.target.value)}
                placeholder="Tell your future match something friendly..."
                required
                maxLength={140}
                className="w-full bg-gray-50 border border-gray-100 rounded-2xl px-5 py-4 focus:outline-none focus:border-primary/50 focus:ring-2 focus:ring-primary/10 transition-all h-32 resize-none text-sm font-medium leading-relaxed text-main placeholder:text-gray-300"
              />
            </div>

            {/* Looking For */}
            <div className="space-y-4">
              <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest ml-1">I want to talk to</label>
              <div className="flex gap-3">
                {['Male', 'Female', 'Any'].map((pref) => {
                  const val = pref === 'Any' ? 'Any' : pref[0];
                  const isActive = localPreference === val;
                  return (
                  <label key={pref} className="flex-1 cursor-pointer group">
                    <input 
                      type="radio" 
                      name="preference" 
                      value={val} 
                      checked={isActive}
                      onChange={() => setLocalPreference(val as 'M' | 'F' | 'Any')}
                      className="hidden"
                    />
                    <div className={`flex flex-col items-center justify-center py-4 rounded-2xl border transition-all duration-200 ${
                      isActive
                      ? 'bg-green-50 border-primary shadow-[0_0_0_1px_rgba(98,209,22,1)]' 
                      : 'bg-white border-gray-100 hover:border-gray-200 hover:bg-gray-50'
                    }`}>
                      <span className={`text-[10px] font-bold uppercase ${isActive ? 'text-green-600' : 'text-gray-400'}`}>
                        {pref === 'Any' ? 'group' : pref.toLowerCase()}
                      </span>
                      <span className={`text-xs font-black uppercase mt-1 ${isActive ? 'text-green-700' : 'text-gray-600'}`}>
                        {pref}
                      </span>
                    </div>
                  </label>
                  );
                })}
              </div>
            </div>

            {error && (
              <div className="bg-red-50 border border-red-100 text-red-500 p-4 rounded-2xl text-xs font-bold text-center">
                {error}
              </div>
            )}

            <button 
              type="submit"
              className="w-full py-5 bg-primary text-white rounded-2xl font-black text-xs uppercase tracking-[0.2em] transition-all hover:bg-primary-hover shadow-xl shadow-green-500/20 active:scale-[0.98] mt-4"
            >
              Start Matching
            </button>
          </form>
        </div>

        <footer className="mt-12 text-center">
            {matchesLeft !== null && (
              <div className="inline-flex items-center gap-2 px-4 py-2 bg-gray-50 rounded-full border border-gray-100">
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
                <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">
                   Available Sessions: <span className="text-gray-600">{matchesLeft} remaining</span>
                </p>
              </div>
            )}
        </footer>
      </div>
    </div>
  );
}
