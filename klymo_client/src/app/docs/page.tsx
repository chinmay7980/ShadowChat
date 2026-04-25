"use client";

import React from 'react';
import SubHeader from '@/components/SubHeader';

export default function DocsPage() {
  return (
    <div className="min-h-screen bg-white font-sans text-main">
      <SubHeader />

      <div className="max-w-4xl mx-auto px-6 pb-20">
        <div className="mb-10">
          <h1 className="text-4xl md:text-5xl font-black tracking-tight text-main mb-3">Documentation</h1>
          <p className="text-sm text-gray-500 font-medium">
            Product overview, privacy guarantees, and system flow for ShadowChat.
          </p>
        </div>

        <section className="space-y-4 mb-12">
          <h2 className="text-2xl font-black tracking-tight text-main">Core Features</h2>
          <ul className="list-disc pl-6 text-sm text-gray-600 space-y-2">
            <li>Anonymous onboarding with no email or phone required.</li>
            <li>Device fingerprinting for daily limits and abuse prevention.</li>
            <li>AI gender verification from live camera capture only.</li>
            <li>Realtime 1-to-1 chat using WebSockets.</li>
            <li>Ephemeral sessions with reporting and blocking tools.</li>
          </ul>
        </section>

        <section className="space-y-4 mb-12">
          <h2 className="text-2xl font-black tracking-tight text-main">Key Flows</h2>
          <div className="text-sm text-gray-600 space-y-3">
            <p>
              <span className="font-bold text-gray-800">Verification:</span> A user opens the
              verification screen and captures a live selfie. The image is sent to the backend,
              forwarded to the verification service, classified, and immediately discarded. Only
              the gender result and a short‑lived verification token are returned.
            </p>
            <p>
              <span className="font-bold text-gray-800">Matching:</span> Verified users join the
              matchmaking queue. The server reads the Redis queue, finds a compatible partner, and
              emits a shared room to both users. Messages are then exchanged through Socket.IO in
              that room.
            </p>
            <p>
              <span className="font-bold text-gray-800">Ephemeral chat:</span> Messages live only in
              the browser state. Leaving the session clears the local state and room membership.
            </p>
          </div>
        </section>

        <section className="space-y-4 mb-12">
          <h2 className="text-2xl font-black tracking-tight text-main">Delete‑After‑Verify</h2>
          <div className="text-sm text-gray-600 space-y-3">
            <p>
              Verification images are processed in memory only. The backend does not write them to
              disk, and the verification service discards the bytes immediately after classification.
              Only the resulting gender label and a signed verification token are retained.
            </p>
          </div>
        </section>

        <section className="space-y-4 mb-12">
          <h2 className="text-2xl font-black tracking-tight text-main">Device ID</h2>
          <div className="text-sm text-gray-600 space-y-3">
            <p>
              A deterministic device fingerprint is generated in the browser and stored locally.
              It is used to enforce daily limits, prevent abuse, and associate verification tokens
              without collecting any personal identifiers.
            </p>
          </div>
        </section>

        <section className="space-y-4">
          <h2 className="text-2xl font-black tracking-tight text-main">Architecture Diagram</h2>
          <p className="text-sm text-gray-600">
            Queue and Socket flow between the browser, backend, and Redis.
          </p>
          <div className="border border-gray-200 rounded-2xl p-6 bg-gray-50">
            <div className="flex flex-col gap-4 text-xs text-gray-700 font-semibold">
              <div className="flex items-center gap-3">
                <div className="px-3 py-2 rounded-lg bg-white border border-gray-200 shadow-sm">Client (Next.js)</div>
                <span className="text-gray-400">Socket.IO: join_queue</span>
                <span className="text-gray-400">→</span>
                <div className="px-3 py-2 rounded-lg bg-white border border-gray-200 shadow-sm">Backend (Node.js)</div>
                <span className="text-gray-400">LPUSH / LRANGE</span>
                <span className="text-gray-400">→</span>
                <div className="px-3 py-2 rounded-lg bg-white border border-gray-200 shadow-sm">Redis Queue</div>
              </div>
              <div className="flex items-center gap-3">
                <div className="px-3 py-2 rounded-lg bg-white border border-gray-200 shadow-sm">Backend (Node.js)</div>
                <span className="text-gray-400">Match Found</span>
                <span className="text-gray-400">→</span>
                <div className="px-3 py-2 rounded-lg bg-white border border-gray-200 shadow-sm">Client (Next.js)</div>
              </div>
              <div className="flex items-center gap-3">
                <div className="px-3 py-2 rounded-lg bg-white border border-gray-200 shadow-sm">Client</div>
                <span className="text-gray-400">Socket.IO: join_room / send_message</span>
                <span className="text-gray-400">→</span>
                <div className="px-3 py-2 rounded-lg bg-white border border-gray-200 shadow-sm">Backend</div>
                <span className="text-gray-400">Socket.IO: receive_message</span>
                <span className="text-gray-400">→</span>
                <div className="px-3 py-2 rounded-lg bg-white border border-gray-200 shadow-sm">Client</div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
