"use client";

import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useUser } from '@/context/UserContext';
import { io, Socket } from 'socket.io-client';
import { DeviceIdentity } from '@/lib/device';
import SubHeader from '@/components/SubHeader';
import { SOCKET_URL } from '@/lib/config';

interface Message {
  senderId: string;
  text?: string;
  image?: string;
  timestamp: number;
}

export default function ChatPage() {
  const router = useRouter();
  const { deviceId } = useUser();
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [partner, setPartner] = useState<any>(null);
  const [roomId, setRoomId] = useState<string | null>(null);
  const [isPartnerTyping, setIsPartnerTyping] = useState(false);
  const [ownId, setOwnId] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const messageListRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleEndSession = useCallback(() => {
    if (socketRef.current && roomId) {
      socketRef.current.emit('leave_chat', roomId);
    }
    sessionStorage.removeItem('current_room');
    sessionStorage.removeItem('partner_info');
    sessionStorage.removeItem('report_target'); 
    
    DeviceIdentity.incrementMatchCount();
    router.push('/end');
  }, [roomId, router]);

  useEffect(() => {
    const storedRoom = sessionStorage.getItem('current_room');
    const storedPartner = sessionStorage.getItem('partner_info');

    if (!storedRoom || !storedPartner) {
      router.push('/profile');
      return;
    }

    setRoomId(storedRoom);
    setPartner(JSON.parse(storedPartner));

    const socket = io(SOCKET_URL, {
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 500,
      reconnectionDelayMax: 3000,
      timeout: 15000,
      transports: ['websocket', 'polling']
    });
    socketRef.current = socket;

    socket.on('connect', () => {
      setOwnId(socket.id || null);
      socket.emit('join_room', storedRoom);
    });

    socket.on('receive_message', (msg: Message) => {
      setMessages(prev => [...prev, msg]);
    });

    socket.on('partner_typing', ({ isTyping }) => {
      setIsPartnerTyping(isTyping);
    });

    socket.on('partner_left', () => {
      handleEndSession();
    });

    socket.on('error', ({ message }) => {
      alert(message);
    });

    return () => {
      if (socketRef.current) socketRef.current.disconnect();
    };
  }, [handleEndSession, router]);

  useEffect(() => {
    const handlePageExit = () => {
      if (socketRef.current && roomId) {
        socketRef.current.emit('leave_chat', roomId);
        socketRef.current.disconnect();
      }
    };
    window.addEventListener('beforeunload', handlePageExit);
    window.addEventListener('pagehide', handlePageExit);
    return () => {
      window.removeEventListener('beforeunload', handlePageExit);
      window.removeEventListener('pagehide', handlePageExit);
    };
  }, [roomId]);

  useEffect(() => {
    if (!messageListRef.current) return;
    const el = messageListRef.current;
    requestAnimationFrame(() => {
      el.scrollTop = el.scrollHeight;
    });
  }, [messages.length]);

  const scrollToBottom = useCallback(() => {
    if (!messageListRef.current) return;
    const el = messageListRef.current;
    el.scrollTop = el.scrollHeight;
  }, []);

  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || !roomId || !socketRef.current) return;

    const newMessage: Message = {
      senderId: ownId || 'me',
      text: inputText,
      timestamp: Date.now()
    };

    socketRef.current.emit('send_message', { roomId, message: inputText });
    setMessages(prev => [...prev, newMessage]);
    setInputText('');
    socketRef.current.emit('typing', { roomId, isTyping: false });
  };

  const handleTyping = (e: React.ChangeEvent<HTMLInputElement>) => {
    setInputText(e.target.value);
    if (roomId && socketRef.current) {
      socketRef.current.emit('typing', { roomId, isTyping: e.target.value.length > 0 });
    }
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !roomId || !socketRef.current) return;

    if (file.size > 1024 * 1024) { // 1MB limit
      alert("Image file is too large (max 1MB)");
      return;
    }

    const reader = new FileReader();
    reader.onloadend = () => {
      const base64 = reader.result as string;
      const newMessage: Message = {
        senderId: ownId || 'me',
        image: base64,
        timestamp: Date.now()
      };
      
      socketRef.current?.emit('send_image', { roomId, image: base64 });
      setMessages(prev => [...prev, newMessage]);
    };
    reader.readAsDataURL(file);
    
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="h-screen overflow-hidden bg-white font-sans text-main flex flex-col">
      <SubHeader />
      
      <div className="flex-1 max-w-4xl w-full mx-auto px-6 pb-6 flex flex-col min-h-0">
        <div className="bg-white rounded-[2rem] border border-gray-200 flex-1 flex flex-col overflow-hidden mb-6 shadow-xl shadow-gray-100">
          
          {/* Chat Header */}
          <div className="px-8 py-6 border-b border-gray-100 bg-gray-50/50 flex justify-between items-center backdrop-blur-sm">
            <div className="flex items-center gap-4">
              <div className="relative">
                <div className="w-12 h-12 bg-primary rounded-2xl flex items-center justify-center text-xl font-black text-white shadow-lg shadow-green-500/20">
                  {partner?.nickname?.charAt(0).toUpperCase() || '?'}
                </div>
                <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-green-500 border-4 border-white rounded-full" />
              </div>
              <div>
                <h3 className="font-black text-lg tracking-tight text-main">@{partner?.nickname || 'Anonymous'}</h3>
                <div className="h-4 flex items-center">
                  {isPartnerTyping ? (
                    <div className="flex gap-1 items-center">
                      <span className="w-1 h-1 bg-primary rounded-full animate-bounce"></span>
                      <span className="w-1 h-1 bg-primary rounded-full animate-bounce [animation-delay:0.2s]"></span>
                      <span className="w-1 h-1 bg-primary rounded-full animate-bounce [animation-delay:0.4s]"></span>
                    </div>
                  ) : (
                    <span className="text-[10px] text-gray-400 font-black uppercase tracking-widest">Active Session</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Messages Area */}
          <div ref={messageListRef} className="flex-1 overflow-y-auto p-8 space-y-6 custom-scrollbar scroll-smooth bg-white">
            {messages.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center opacity-30 pointer-events-none select-none">
                 <div className="text-6xl mb-4 grayscale opacity-20">💬</div>
                 <p className="text-[10px] font-black uppercase tracking-[0.3em] text-gray-400">Start the conversation</p>
              </div>
            )}
            {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.senderId === ownId ? 'justify-end' : 'justify-start'} animate-in fade-in slide-in-from-bottom-2 duration-300`}>
                <div className={`max-w-[80%] rounded-[1.5rem] shadow-sm overflow-hidden ${
                  msg.senderId === ownId 
                  ? 'bg-primary text-white rounded-tr-none shadow-green-500/20' 
                  : 'bg-gray-100 text-gray-800 rounded-tl-none border border-gray-200'
                }`}>
                  {msg.image ? (
                    <div className="p-2">
                      <img src={msg.image} alt="Shared" onLoad={scrollToBottom} className="rounded-xl w-full h-auto max-h-64 object-cover" />
                    </div>
                  ) : (
                    <div className="px-6 py-4">
                      <p className="text-sm leading-relaxed font-bold">{msg.text}</p>
                    </div>
                  )}
                  <p className={`text-[8px] px-6 pb-2 font-black uppercase tracking-tighter ${msg.senderId === ownId ? 'text-white/70 text-right' : 'text-gray-400'}`}>
                    {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </p>
                </div>
              </div>
            ))}
            <div ref={scrollRef} />
          </div>

          {/* Input Area */}
          <div className="p-6 bg-white border-t border-gray-100">
            <form onSubmit={handleSendMessage} className="space-y-4">
              <div className="relative group">
                <input 
                  type="text"
                  value={inputText}
                  onChange={handleTyping}
                  placeholder="Type a secure message..."
                  className="w-full bg-gray-50 border border-gray-200 rounded-2xl px-6 py-4 pr-32 focus:outline-none focus:border-primary/50 focus:ring-2 focus:ring-primary/10 transition-all text-sm font-bold text-main placeholder:text-gray-400"
                />
                
                {/* Image Upload Button */}
                <input 
                  type="file" 
                  ref={fileInputRef} 
                  onChange={handleImageUpload} 
                  accept="image/*" 
                  className="hidden" 
                />
                <button 
                  type="button" 
                  onClick={() => fileInputRef.current?.click()}
                  className="absolute right-16 top-2 bottom-2 px-3 text-gray-400 hover:text-primary transition-all active:scale-95 flex items-center justify-center border-r border-gray-200 mr-2"
                >
                  <svg viewBox="0 0 24 24" className="w-5 h-5 fill-current">
                    <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14zm-5-7l-3 3.72L9 13l-3 4h12l-4-5z" />
                  </svg>
                </button>

                {/* Send Button */}
                <button type="submit" className="absolute right-2 top-2 bottom-2 px-4 bg-primary rounded-xl hover:bg-primary-hover transition-all active:scale-95 flex items-center justify-center shadow-md shadow-green-500/20">
                  <svg viewBox="0 0 24 24" className="w-5 h-5 fill-white">
                    <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
                  </svg>
                </button>
              </div>
              
              <div className="flex gap-3 h-12">
                <button 
                  type="button" 
                  onClick={() => {
                    if (socketRef.current && partner) {
                      socketRef.current.emit('report_user', { 
                        reporterDeviceId: deviceId, 
                        targetDeviceId: partner.deviceId, 
                        reason: 'User reported via chat button' 
                      });
                    }
                    sessionStorage.setItem('report_target', partner?.deviceId || '');
                    router.push('/end?report=true');
                  }}
                  className="flex-1 rounded-2xl border border-red-100 bg-red-50 text-red-500 text-[10px] font-black uppercase tracking-widest hover:bg-red-500 hover:text-white transition-all active:scale-95"
                >
                  Report
                </button>
                <button 
                  type="button"
                  onClick={handleEndSession}
                  className="flex-1 rounded-2xl border border-gray-200 bg-white text-gray-500 text-[10px] font-black uppercase tracking-widest hover:bg-gray-50 hover:text-gray-700 transition-all active:scale-95"
                >
                  Leave
                </button>
                <button 
                  type="button" 
                  onClick={handleEndSession}
                  className="flex-[2] rounded-2xl bg-primary text-white text-[10px] font-black uppercase tracking-widest hover:bg-primary-hover transition-all shadow-lg shadow-green-500/20 active:scale-95"
                >
                  Next Match
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
