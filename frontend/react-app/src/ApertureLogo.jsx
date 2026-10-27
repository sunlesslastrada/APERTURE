import React, { useState } from "react";

export function ApertureLogo({ className = "w-9 h-9" }) {
  const [imgError, setImgError] = useState(false);

  return (
    <div
      className={`relative flex items-center justify-center shrink-0 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/10 border border-cyan-500/30 p-1 shadow-[0_0_15px_rgba(6,182,212,0.25)] overflow-hidden ${className}`}
    >
      {!imgError ? (
        <img
          src="/aperture-shield.png"
          alt="APERTURE"
          className="w-full h-full object-contain rounded-lg drop-shadow-[0_0_8px_rgba(6,182,212,0.4)]"
          onError={() => setImgError(true)}
        />
      ) : (
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="text-cyan-400 w-full h-full p-0.5"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
          <circle cx="12" cy="11" r="3" className="stroke-cyan-300 fill-cyan-950/50" />
          <path d="m10 8.5 4 5" />
          <path d="m14 8.5-4 5" />
        </svg>
      )}
    </div>
  );
}

export default ApertureLogo;
