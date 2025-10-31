// =============================================
// File: src/components/FullscreenViewer.jsx
// Fullscreen viewer for snapped media (image/video),
// auto-dismiss for view-once messages.
// =============================================

import React, { useEffect, useRef } from "react";

/**
 * Props
 * - open: boolean
 * - message: { id, type:"image"|"video", url, ephemeral?:{mode:"once"|"keep"}, filter?:{id,label} }
 * - onClose: () => void
 * - onViewed?: (id) => void // call when user has viewed (for once)
 */
export function FullscreenViewer({ open, message, onClose, onViewed }) {
  const timerRef = useRef(null);
  const vidRef = useRef(null);

  useEffect(() => {
    if (!open) return;

    if (message?.ephemeral?.mode === "once") {
      if (message.type === "video") {
        const v = vidRef.current;
        if (v) {
          const onEnd = () => { onViewed?.(message.id); onClose?.(); };
          v.addEventListener("ended", onEnd);
          return () => v.removeEventListener("ended", onEnd);
        }
      } else {
        timerRef.current = setTimeout(() => {
          onViewed?.(message.id);
          onClose?.();
        }, 4000);
        return () => clearTimeout(timerRef.current);
      }
    }
  }, [open, message, onClose, onViewed]);

  if (!open || !message) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/95" onClick={onClose}>
      <div className="absolute inset-0 grid place-items-center" onClick={(e)=>e.stopPropagation()}>
        {message.type === "image" ? (
          <img src={message.url} alt="" className="max-w-[95vw] max-h-[85vh] object-contain" />
        ) : message.type === "video" ? (
          <video ref={vidRef} src={message.url} className="max-w-[95vw] max-h-[85vh]" autoPlay controls />
        ) : (
          <div className="text-white/80">Unsupported message</div>
        )}
      </div>

      <div className="absolute top-0 left-0 right-0 h-14 px-3 flex items-center justify-between text-white/90">
        <div className="text-sm">{message.filter?.label || ""}</div>
        <button
          className="px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 border border-white/20"
          onClick={onClose}
        >✕</button>
      </div>
    </div>
  );
}
