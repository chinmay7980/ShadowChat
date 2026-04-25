"use client";

import React, { useRef, useState, useCallback, useEffect } from 'react';
import { API_BASE_URL } from '@/lib/config';

interface CameraProps {
  onCapture: (blob: Blob) => void;
  isVerifying: boolean;
  completeVerification: (gender: 'M' | 'F', token: string) => void;
  deviceId: string | null;
}

export default function Camera({ onCapture, completeVerification, deviceId }: Omit<CameraProps, 'isVerifying'>) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cameraStarted, setCameraStarted] = useState(false);
  const [showScanning, setShowScanning] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    verified: boolean;
    gender?: 'M' | 'F';
    error?: string;
  } | null>(null);

  const startCamera = useCallback(async () => {
    try {
      const mediaStream = await navigator.mediaDevices.getUserMedia({ 
        video: { facingMode: 'user', width: 640, height: 640 } 
      });
      setStream(mediaStream);
      if (videoRef.current) {
        videoRef.current.srcObject = mediaStream;
      }
      setCameraStarted(true);
      setError(null);
    } catch (err) {
      setError("Camera access denied. Please enable camera permissions.");
      console.error(err);
    }
  }, []);

  useEffect(() => {
    // Don't auto-start camera, let user click "Start Camera" button
    return () => {
      stream?.getTracks().forEach(track => track.stop());
    };
  }, [stream]);

  const captureFrame = async () => {
    if (videoRef.current && canvasRef.current) {
      const context = canvasRef.current.getContext('2d');
      if (context) {
        setShowScanning(true);
        setVerificationResult(null);
        
        canvasRef.current.width = videoRef.current.videoWidth;
        canvasRef.current.height = videoRef.current.videoHeight;
        context.drawImage(videoRef.current, 0, 0);
        
        const base64Image = canvasRef.current.toDataURL('image/jpeg', 0.95);
        onCapture(new Blob()); // Keep the original prop call for flow

        try {
          if (!deviceId) {
            setShowScanning(false);
            setVerificationResult({
              verified: false,
              error: "Device ID not ready. Please refresh and try again."
            });
            return;
          }
          const response = await fetch(`${API_BASE_URL}/api/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ image: base64Image, deviceId })
          });
          
          const data = await response.json();
          setShowScanning(false);
          
          if (data.verified) {
            if (!data.verificationToken) {
              setVerificationResult({
                verified: false,
                error: "Verification token missing. Please retry."
              });
              return;
            }
            setVerificationResult({
              verified: true,
              gender: data.gender
            });
            completeVerification(data.gender, data.verificationToken);
          } else {
            setVerificationResult({
              verified: false,
              error: data.error || "Verification failed"
            });
          }
        } catch (err) {
          setShowScanning(false);
          setVerificationResult({
            verified: false,
            error: "Network error. Ensure server is running."
          });
          console.error(err);
        }
      }
    }
  };

  return (
    <div className="secure-verify-container">
      {/* SecureVerify Header */}
      <header className="verify-header">
        <div className="verify-logo">
          <div className="logo-mark">S</div>
          <h1>ShadowChat</h1>
        </div>
        {cameraStarted && (
          <div className="status-badge">
            <span className="status-dot"></span>
            Camera Ready
          </div>
        )}
      </header>

      {/* Main Verification Card */}
      <div className="verification-card">
        <div className="camera-container">
          {!cameraStarted && !error && (
            <div className="placeholder-message">
              <p>Click &quot;Start Camera&quot; to begin</p>
            </div>
          )}
          
          {error && (
            <div className="error-message">
              <p>{error}</p>
            </div>
          )}

          <video 
            ref={videoRef} 
            autoPlay 
            playsInline 
            muted
            className={`camera-feed ${cameraStarted ? 'active' : ''}`}
          />
          <canvas ref={canvasRef} className="hidden" />
          
          {/* Scanning Overlay with Corner Brackets */}
          <div className={`scan-overlay ${showScanning ? 'active' : ''}`}>
            <div className="scan-line"></div>
            <div className="corner topleft"></div>
            <div className="corner topright"></div>
            <div className="corner bottomleft"></div>
            <div className="corner bottomright"></div>
          </div>
        </div>

        {/* Control Buttons */}
        <div className="controls">
          <button 
            onClick={startCamera}
            className="btn primary-btn"
            disabled={cameraStarted}
          >
            {cameraStarted ? 'Camera Active' : 'Start Camera'}
          </button>
          <button 
            onClick={captureFrame}
            className="btn action-btn"
            disabled={!cameraStarted || showScanning}
          >
            Verify Identity
          </button>
        </div>

        {/* Result Area */}
        {(showScanning || verificationResult) && (
          <div className="result-container">
            {showScanning && (
              <div className="loader">
                <div className="spinner"></div>
                <p>Analyzing...</p>
              </div>
            )}
            
            {verificationResult && !showScanning && (
              <div className="result-content">
                <div className="result-icon">
                  {verificationResult.verified 
                    ? (verificationResult.gender === 'M' ? '👨' : '👩')
                    : '⚠️'
                  }
                </div>
                <h2 className={verificationResult.verified ? 'result-success' : 'result-error'}>
                  {verificationResult.verified ? 'Verified Response' : 'Verification Failed'}
                </h2>
                <p>
                  {verificationResult.verified 
                    ? `Gender classified as: ${verificationResult.gender === 'M' ? 'Male' : 'Female'}`
                    : verificationResult.error
                  }
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Privacy Note */}
      <div className="privacy-note">
        <h3>
          <span className="lock-emoji">🛡️</span>
          Privacy Guarantee
        </h3>
        <p>Images are processed in-memory and deleted immediately. No data is stored or logged.</p>
      </div>

      <style jsx>{`
        .secure-verify-container {
          width: 100%;
          max-width: 480px;
          margin: 0 auto;
          padding: 1.5rem;
        }

        .verify-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 2rem;
        }

        .verify-logo {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .logo-mark {
          width: 32px;
          height: 32px;
          background: #62D116;
          color: #ffffff;
          border-radius: 0.5rem;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 800;
          box-shadow: 0 6px 16px rgba(98, 209, 22, 0.2);
        }

        .verify-logo h1 {
          font-size: 1.25rem;
          font-weight: 800;
          letter-spacing: -0.03em;
          text-transform: uppercase;
          color: #2D2D2D;
        }

        .status-badge {
          background-color: rgba(98, 209, 22, 0.1);
          color: #62D116;
          padding: 0.25rem 0.75rem;
          border-radius: 9999px;
          font-size: 0.75rem;
          font-weight: 700;
          display: flex;
          align-items: center;
          gap: 0.375rem;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }

        .status-dot {
          width: 6px;
          height: 6px;
          background-color: currentColor;
          border-radius: 50%;
          display: inline-block;
        }

        .verification-card {
          background-color: #ffffff;
          border-radius: 2rem;
          padding: 1.5rem;
          box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.05);
          border: 1px solid #e5e7eb;
        }

        .camera-container {
          width: 100%;
          aspect-ratio: 1/1;
          background-color: #f8fafc;
          border-radius: 1.5rem;
          overflow: hidden;
          position: relative;
          margin-bottom: 2rem;
          border: 1px solid #e2e8f0;
          box-shadow: inset 0 2px 10px rgba(0,0,0,0.05);
        }

        .camera-feed {
          width: 100%;
          height: 100%;
          object-fit: cover;
          display: none;
        }

        .camera-feed.active {
          display: block;
        }

        .placeholder-message,
        .error-message {
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          display: flex;
          justify-content: center;
          align-items: center;
          background-color: #f8fafc;
          color: #94a3b8;
          z-index: 10;
          text-align: center;
          padding: 2rem;
          font-weight: 500;
        }

        .error-message {
          color: #ef4444;
          background-color: #fef2f2;
        }

        .scan-overlay {
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          pointer-events: none;
          z-index: 5;
          display: none;
        }

        .scan-overlay.active {
          display: block;
        }

        .scan-line {
          position: absolute;
          width: 100%;
          height: 2px;
          background: linear-gradient(90deg, transparent, #62D116, transparent);
          top: 0;
          animation: scan 2s linear infinite;
          box-shadow: 0 0 15px #62D116;
        }

        @keyframes scan {
          0% { top: 0%; opacity: 0; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { top: 100%; opacity: 0; }
        }

        .corner {
          position: absolute;
          width: 30px;
          height: 30px;
          border-color: rgba(255, 255, 255, 0.8);
          border-style: solid;
          border-width: 0;
          filter: drop-shadow(0 0 2px rgba(0,0,0,0.3));
        }

        .topleft { top: 20px; left: 20px; border-top-width: 4px; border-left-width: 4px; border-radius: 8px 0 0 0; }
        .topright { top: 20px; right: 20px; border-top-width: 4px; border-right-width: 4px; border-radius: 0 8px 0 0; }
        .bottomleft { bottom: 20px; left: 20px; border-bottom-width: 4px; border-left-width: 4px; border-radius: 0 0 0 8px; }
        .bottomright { bottom: 20px; right: 20px; border-bottom-width: 4px; border-right-width: 4px; border-radius: 0 0 8px 0; }

        .controls {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1rem;
          margin-bottom: 0.5rem;
        }

        .btn {
          padding: 1rem;
          border-radius: 9999px;
          font-family: inherit;
          font-weight: 800;
          font-size: 0.75rem;
          cursor: pointer;
          transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
          border: none;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }

        .primary-btn {
          background-color: #f1f5f9;
          color: #64748b;
        }

        .primary-btn:hover:not(:disabled) {
          background-color: #e2e8f0;
          color: #475569;
        }

        .primary-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .action-btn {
          background-color: #62D116;
          color: white;
          box-shadow: 0 10px 20px -5px rgba(98, 209, 22, 0.3);
        }

        .action-btn:hover:not(:disabled) {
          background-color: #52b112;
          transform: translateY(-1px);
          box-shadow: 0 15px 25px -5px rgba(98, 209, 22, 0.4);
        }

        .action-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
          box-shadow: none;
          transform: none;
        }

        .result-container {
          min-height: 100px;
          display: flex;
          justify-content: center;
          align-items: center;
          text-align: center;
          border-top: 1px solid #f1f5f9;
          padding-top: 1.5rem;
          margin-top: 1.5rem;
        }

        .loader {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 1rem;
          color: #64748b;
        }

        .spinner {
          width: 32px;
          height: 32px;
          border: 3px solid #e2e8f0;
          border-radius: 50%;
          border-top-color: #62D116;
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }

        .result-content {
          animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }

        .result-icon {
          font-size: 3rem;
          margin-bottom: 0.5rem;
        }

        .result-content h2 {
          font-size: 1.25rem;
          font-weight: 800;
          margin-bottom: 0.25rem;
          letter-spacing: -0.025em;
        }

        .result-success { color: #62D116; }
        .result-error { color: #ef4444; }

        .privacy-note {
          background-color: #eff6ff;
          border: 1px solid #dbeafe;
          border-radius: 1rem;
          padding: 1.25rem;
          margin-top: 2rem;
          text-align: center;
        }

        .privacy-note h3 {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          font-size: 0.875rem;
          font-weight: 700;
          color: #3b82f6;
          margin-bottom: 0.5rem;
        }

        .privacy-note p {
          font-size: 0.75rem;
          color: #64748b;
          line-height: 1.5;
          max-width: 300px;
          margin: 0 auto;
        }

        .hidden {
          display: none;
        }
      `}</style>
    </div>
  );
}
