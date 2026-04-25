"use client";

import React, { createContext, useContext, useEffect, useState } from 'react';
import { getDeviceFingerprint, DeviceIdentity } from '@/lib/device';

interface UserContextType {
  deviceId: string | null;
  genderVerified: boolean;
  gender: 'M' | 'F' | null;
  verificationToken: string | null;
  nickname: string;
  bio: string;
  matchPreference: 'M' | 'F' | 'Any';
  setUserInfo: (info: Partial<UserContextType>) => void;
  isLoading: boolean;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

export function UserProvider({ children }: { children: React.ReactNode }) {
  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [genderVerified, setGenderVerified] = useState(false);
  const [gender, setGender] = useState<'M' | 'F' | null>(null);
  const [verificationToken, setVerificationToken] = useState<string | null>(null);
  const [nickname, setNickname] = useState('');
  const [bio, setBio] = useState('');
  const [matchPreference, setMatchPreference] = useState<'M' | 'F' | 'Any'>('Any');
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const initDevice = async () => {
      if (typeof window !== 'undefined') {
        const stored = localStorage.getItem('anon_chat_verification');
        if (stored) {
          try {
            const parsed = JSON.parse(stored);
            if (parsed.gender && parsed.verified) {
              setGender(parsed.gender);
              setGenderVerified(true);
              setVerificationToken(parsed.token || null);
            }
          } catch (err) {
            localStorage.removeItem('anon_chat_verification');
          }
        }
      }
      let id = DeviceIdentity.getStoredId();
      if (!id) {
        id = await getDeviceFingerprint();
        DeviceIdentity.setStoredId(id);
      }
      setDeviceId(id);
      setIsLoading(false);
    };
    initDevice();
  }, []);

  const setUserInfo = (info: Partial<UserContextType>) => {
    if (info.genderVerified !== undefined) setGenderVerified(info.genderVerified);
    if (info.gender !== undefined) setGender(info.gender);
    if (info.verificationToken !== undefined) setVerificationToken(info.verificationToken);
    if (info.nickname !== undefined) setNickname(info.nickname);
    if (info.bio !== undefined) setBio(info.bio);
    if (info.matchPreference !== undefined) setMatchPreference(info.matchPreference);

    if (typeof window !== 'undefined' && (info.genderVerified !== undefined || info.gender !== undefined || info.verificationToken !== undefined)) {
      const verified = info.genderVerified ?? genderVerified;
      const storedGender = info.gender ?? gender;
      const token = info.verificationToken ?? verificationToken;
      if (verified && storedGender) {
        localStorage.setItem('anon_chat_verification', JSON.stringify({
          verified: true,
          gender: storedGender,
          token: token || null,
          updatedAt: Date.now()
        }));
      } else {
        localStorage.removeItem('anon_chat_verification');
      }
    }
  };

  return (
    <UserContext.Provider value={{ 
      deviceId, 
      genderVerified, 
      gender, 
      verificationToken,
      nickname, 
      bio, 
      matchPreference,
      setUserInfo,
      isLoading
    }}>
      {children}
    </UserContext.Provider>
  );
}

export const useUser = () => {
  const context = useContext(UserContext);
  if (context === undefined) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};
