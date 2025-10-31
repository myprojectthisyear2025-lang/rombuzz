import React, { useEffect, useMemo, useRef, useState } from "react";

/**
 * SnapCameraSheet — RomBuzz
 *
 * ▶ FREE, no SDK:
 * - Live photo/video capture using getUserMedia
 * - Real‑time filters with HTMLCanvas 2D `ctx.filter` + overlays (vignette, grain)
 * - Filter strip with Instagram/Snap‑style presets + intensity slider
 * - Records FILTERED video by drawing <video> → <canvas> and MediaRecorder on canvas.captureStream()
 * - Uploads to Cloudinary unsigned preset (same as your current flow)
 * - Optional "View once" flag passed back to parent via onSend
 *
 * Props:
 *   open: boolean
 *   onClose(): void
 *   onSend(payload: { type: "image"|"video", url: string, ephemeral, filter: {key, intensity, vignette, grain} }): Promise
 *   cloudName: string (Cloudinary)
 *   uploadPreset: string (Cloudinary unsigned preset)
 *   defaultViewOnce?: boolean
 */

const PRESETS = [
  {
    key: "original",
    name: "Original",
    css: (t=1) => `none`,
  },
  {
    key: "clarendon",
    name: "Clarendon",
    css: (t=1) => `brightness(${1+0.05*t}) contrast(${1+0.25*t}) saturate(${1+0.35*t})`,
  },
  {
    key: "gingham",
    name: "Gingham",
    css: (t=1) => `sepia(${0.3*t}) brightness(${1+0.05*t})`,
  },
  {
    key: "juno",
    name: "Juno",
    css: (t=1) => `saturate(${1+0.4*t}) contrast(${1+0.15*t})`,
  },
  {
    key: "lark",
    name: "Lark",
    css: (t=1) => `brightness(${1+0.08*t}) saturate(${1-0.2*t})`,
  },
  {
    key: "lofi",
    name: "Lo‑Fi",
    css: (t=1) => `contrast(${1+0.35*t}) saturate(${1+0.25*t})`,
  },
  {
    key: "ludwig",
    name: "Ludwig",
    css: (t=1) => `brightness(${1+0.06*t}) contrast(${1+0.2*t})`,
  },
  {
    key: "aden",
    name: "Aden",
    css: (t=1) => `hue-rotate(${10*t}deg) saturate(${1-0.15*t}) brightness(${1+0.05*t})`,
  },
  {
    key: "valencia",
    name: "Valencia",
    css: (t=1) => `sepia(${0.15*t}) contrast(${1+0.1*t}) brightness(${1+0.05*t})`,
  },
  {
    key: "noir",
    name: "Noir",
    css: (t=1) => `grayscale(${1*t}) contrast(${1+0.2*t})`,
  },
  {
    key: "vivid",
    name: "Vivid",
    css: (t=1) => `saturate(${1+0.6*t}) contrast(${1+0.25*t})`,
  },
  {
    key: "matte",
    name: "Matte",
    css: (t=1) => `contrast(${1-0.2*t}) brightness(${1+0.1*t})`,
  },
  {
    key: "warm",
    name: "Warm",
    css: (t=1) => `sepia(${0.12*t}) saturate(${1+0.15*t})`,
  },
  {
    key: "cool",
    name: "Cool",
    css: (t=1) => `hue-rotate(${-10*t}deg) saturate(${1+0.05*t})`,
  },
  {
    key: "cinema",
    name: "Cinema",
    css: (t=1) => `brightness(${1-0.05*t}) contrast(${1+0.3*t}) saturate(${1-0.05*t})`,
  },
];

export default function SnapCameraSheet({ open, onClose, onSend, cloudName, uploadPreset, defaultViewOnce = true }) {
  const [mode, setMode] = useState("photo"); // photo | video
  const [viewOnce, setViewOnce] = useState(!!defaultViewOnce);
  const [activeKey, setActiveKey] = useState("clarendon");
  const [intensity, setIntensity] = useState(0.75); // 0..1
  const [vignette, setVignette] = useState(0.35);   // 0..1
  const [grain, setGrain] = useState(0.15);         // 0..1
  const [recording, setRecording] = useState(false);

  const videoRef = useRef(null);       // live camera
  const streamRef = useRef(null);      // getUserMedia stream
  const canvasRef = useRef(null);      // processing canvas (filtered)
  const thumbRef = useRef(null);       // temp canvas for preview thumbs
  const recRef = useRef(null);         // MediaRecorder
  const chunksRef = useRef([]);

  const preset = useMemo(() => PRESETS.find(p => p.key === activeKey) || PRESETS[0], [activeKey]);
  const cssFilter = useMemo(() => preset.css(intensity), [preset, intensity]);

  useEffect(() => {
    if (!open) return;
    startCamera();
    return () => stopCamera();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, mode]);

  // Draw loop → copy <video> to <canvas> with filters + overlays
  useEffect(() => {
    let id;
    const draw = () => {
      const v = videoRef.current;
      const c = canvasRef.current;
      if (!v || !c) { id = requestAnimationFrame(draw); return; }
      const cw = c.width = v.videoWidth || 720;
      const ch = c.height = v.videoHeight || 1280;
      const ctx = c.getContext("2d");
      if (!ctx) { id = requestAnimationFrame(draw); return; }

      // core filter
      ctx.filter = cssFilter; // HTMLCanvas 2D filter pipeline
      ctx.drawImage(v, 0, 0, cw, ch);
      ctx.filter = "none";

      // vignette overlay
      if (vignette > 0) {
        const g = ctx.createRadialGradient(cw/2, ch/2, Math.min(cw,ch)*(0.35+0.2*(1-vignette)), cw/2, ch/2, Math.max(cw,ch)*0.7);
        g.addColorStop(0, "rgba(0,0,0,0)");
        g.addColorStop(1, `rgba(0,0,0,${0.55*vignette})`);
        ctx.fillStyle = g;
        ctx.fillRect(0,0,cw,ch);
      }

      // film grain overlay
      if (grain > 0) {
        const n = 1200; // noise samples per frame
        ctx.globalAlpha = 0.08 * grain;
        for (let i=0;i<n;i++) {
          const x = Math.random()*cw;
          const y = Math.random()*ch;
          const s = 1 + Math.random()*2;
          const val = 220 + Math.floor(Math.random()*35);
          ctx.fillStyle = `rgb(${val},${val},${val})`;
          ctx.fillRect(x,y,s,s);
        }
        ctx.globalAlpha = 1;
      }

      id = requestAnimationFrame(draw);
    };
    id = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(id);
  }, [cssFilter, vignette, grain]);

  const startCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" }, audio: mode === "video" });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play().catch(()=>{});
      }
    } catch (e) {
      console.error("camera open failed", e);
      alert("Could not open camera. Check permissions.");
      onClose?.();
    }
  };

  const stopCamera = () => {
    try { recRef.current && recRef.current.state !== "inactive" && recRef.current.stop(); } catch {}
    try { streamRef.current?.getTracks()?.forEach(t => t.stop()); } catch {}
    streamRef.current = null; recRef.current = null; chunksRef.current = [];
  };

  const takePhotoBlob = async () => {
    const c = canvasRef.current; if (!c) return null;
    return new Promise((res) => c.toBlob(res, "image/jpeg", 0.92));
  };

  const startRecording = async () => {
    if (recording) return;
    const c = canvasRef.current; if (!c) return;
    const fps = 30;
    const stream = c.captureStream(fps);
    // If source had mic, mix its audio
    const mic = streamRef.current?.getAudioTracks?.()?.[0];
    if (mic) {
      const ms = new MediaStream([mic]);
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const dest = ctx.createMediaStreamDestination();
      const src = ctx.createMediaStreamSource(ms);
      src.connect(dest);
      // merge: add track into canvas stream
      dest.stream.getAudioTracks().forEach(t => stream.addTrack(t));
    }
    chunksRef.current = [];
    const rec = new MediaRecorder(stream, { mimeType: "video/webm;codecs=vp9" });
    recRef.current = rec;
    rec.ondataavailable = (e) => { if (e.data?.size) chunksRef.current.push(e.data); };
    rec.onstop = () => {};
    rec.start();
    setRecording(true);
  };

  const stopRecordingBlob = async () => {
    if (!recRef.current) return null;
    return new Promise((resolve) => {
      recRef.current.onstop = () => {
        const blob = new Blob(chunksRef.current, { type: "video/webm" });
        setRecording(false);
        resolve(blob);
      };
      try { recRef.current.stop(); } catch { resolve(null); }
    });
  };

  const uploadToCloudinary = async (fileOrBlob) => {
    const form = new FormData();
    form.append("file", fileOrBlob);
    form.append("upload_preset", uploadPreset);
    const r = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/auto/upload`, { method: "POST", body: form });
    const j = await r.json();
    if (!j.secure_url) throw new Error("Cloudinary upload failed");
    return j.secure_url;
  };

  const makeThumb = () => {
    const v = videoRef.current; const c = thumbRef.current;
    if (!v || !c) return;
    const w = c.width = 120; const h = c.height = 160;
    const ctx = c.getContext("2d");
    ctx.filter = cssFilter;
    ctx.drawImage(v, 0, 0, w, h);
  };

  return !open ? null : (
    <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4" onClick={onClose}>
      <div className="relative bg-white rounded-2xl w-full max-w-md overflow-hidden" onClick={(e)=>e.stopPropagation()}>
        {/* header */}
        <div className="flex items-center justify-between px-3 py-2 border-b">
          <div className="flex items-center gap-2">
            <button
              className={`px-3 py-1 rounded-lg border ${mode === "photo" ? "bg-rose-500 text-white border-rose-500" : "hover:bg-gray-100"}`}
              onClick={() => setMode("photo")}
            >Photo</button>
            <button
              className={`px-3 py-1 rounded-lg border ${mode === "video" ? "bg-rose-500 text-white border-rose-500" : "hover:bg-gray-100"}`}
              onClick={() => setMode("video")}
            >Video</button>
          </div>
          <button className="p-2 hover:bg-gray-100 rounded-full" onClick={onClose} title="Close">✕</button>
        </div>

        {/* preview: live video (for face framing) + hidden canvas on top drives output */}
        <div className="relative bg-black aspect-[9/16]">
          <video ref={videoRef} autoPlay playsInline muted className="absolute inset-0 w-full h-full object-cover" style={{ filter: cssFilter }} />
          <canvas ref={canvasRef} className="absolute inset-0 w-full h-full pointer-events-none opacity-0" />
        </div>

        {/* controls */}
        <div className="p-3 border-t space-y-3">
          {/* view once + intensities */}
          <div className="grid grid-cols-2 gap-3">
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={viewOnce} onChange={(e)=>setViewOnce(e.target.checked)} />
              Send as “View once”
            </label>
            <div className="text-right text-xs text-gray-500">{preset.name} • {Math.round(intensity*100)}%</div>
          </div>

          {/* sliders */}
          <div className="space-y-2">
            <div>
              <div className="text-xs text-gray-600 mb-1">Filter intensity</div>
              <input type="range" min={0} max={1} step={0.01} value={intensity} onChange={(e)=>setIntensity(parseFloat(e.target.value))} className="w-full" />
            </div>
            <div>
              <div className="text-xs text-gray-600 mb-1">Vignette</div>
              <input type="range" min={0} max={1} step={0.01} value={vignette} onChange={(e)=>setVignette(parseFloat(e.target.value))} className="w-full" />
            </div>
            <div>
              <div className="text-xs text-gray-600 mb-1">Grain</div>
              <input type="range" min={0} max={1} step={0.01} value={grain} onChange={(e)=>setGrain(parseFloat(e.target.value))} className="w-full" />
            </div>
          </div>

          {/* filter strip */}
          <div className="flex gap-2 overflow-x-auto py-1 -mx-1 px-1">
            {PRESETS.map((p) => (
              <button
                key={p.key}
                onClick={() => setActiveKey(p.key)}
                onMouseEnter={makeThumb}
                className={`shrink-0 w-[88px] rounded-xl border overflow-hidden text-center text-[10px] ${activeKey===p.key?"border-rose-500 ring-2 ring-rose-200":"border-gray-200"}`}
                title={p.name}
              >
                <div className="h-[110px] bg-gray-200 grid place-items-center">
                  <canvas ref={thumbRef} width={88} height={110} style={{ filter: p.css(intensity), width: "100%", height: "100%" }} />
                </div>
                <div className="p-1 truncate">{p.name}</div>
              </button>
            ))}
          </div>

          {/* capture controls */}
          {mode === "photo" ? (
            <div className="flex items-center justify-between">
              <button className="px-4 py-2 rounded-lg border hover:bg-gray-50" onClick={onClose}>Cancel</button>
              <button
                className="px-4 py-2 rounded-lg bg-rose-500 text-white hover:bg-rose-600"
                onClick={async () => {
                  const blob = await takePhotoBlob();
                  if (!blob) return;
                  const url = await uploadToCloudinary(blob);
                  await onSend({
                    type: "image",
                    url,
                    ephemeral: viewOnce ? { mode: "once" } : { mode: "keep" },
                    filter: { key: activeKey, intensity, vignette, grain }
                  });
                  onClose?.();
                }}
              >Take & Send</button>
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <button className="px-4 py-2 rounded-lg border hover:bg-gray-50" onClick={onClose}>Cancel</button>
              {!recording ? (
                <button className="px-4 py-2 rounded-lg bg-rose-500 text-white hover:bg-rose-600" onClick={startRecording}>● Record</button>
              ) : (
                <button
                  className="px-4 py-2 rounded-lg bg-red-600 text-white hover:bg-red-700"
                  onClick={async () => {
                    const blob = await stopRecordingBlob();
                    if (!blob) return;
                    const url = await uploadToCloudinary(blob);
                    await onSend({
                      type: "video",
                      url,
                      ephemeral: viewOnce ? { mode: "once" } : { mode: "keep" },
                      filter: { key: activeKey, intensity, vignette, grain }
                    });
                    onClose?.();
                  }}
                >■ Stop & Send</button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
