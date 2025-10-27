// src/components/AiWingmanPanel.jsx
import React, { useState } from "react";

export default function AiWingmanPanel({
  open,
  onClose,
  token,
  apiBase = "http://localhost:4000",
  roomId,
  myId,
  peerId,
  messages = [],
  onUseTip = () => {},
}) {
  const [busy, setBusy] = useState(false);
  const [tips, setTips] = useState([]);
  const [tone, setTone] = useState("friendly");
  const [rewriteSrc, setRewriteSrc] = useState("");
  const [rewriteOut, setRewriteOut] = useState("");

  if (!open) return null;

  const suggest = async () => {
    try {
      setBusy(true);
      setTips([]);
      const last20 = messages.slice(-20).map((m) => {
        const mine = (m.from || m.fromId) === myId;
        const text = m.text?.startsWith("::RBZ::") ? (m.textFallback || "") : (m.text || "");
        return `${mine ? "Me" : "Them"}: ${text || m.url || ""}`;
      }).join("\n");
      const r = await fetch(`${apiBase}/api/ai/wingman/suggest`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          myProfileSummary: "",
          theirProfileSummary: "",
          style: tone,
          context: last20, // backend ignores unknown fields; ok for future
        }),
      });
      const j = await r.json();
      const arr = j?.suggestions || [];
      setTips(arr);
    } catch {
      setTips(["Try asking about something in their photos.", "Share a quick fun fact about yourself.", "Suggest a light plan: coffee this weekend?"]);
    } finally {
      setBusy(false);
    }
  };

  const doRewrite = async () => {
    if (!rewriteSrc.trim()) return;
    try {
      setBusy(true);
      setRewriteOut("");
      const r = await fetch(`${apiBase}/api/ai/wingman/rewrite`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ text: rewriteSrc, tone }),
      });
      const j = await r.json();
      setRewriteOut(j?.rewrite || "");
    } catch {
      setRewriteOut(`(${tone}) ${rewriteSrc}`);
    } finally {
      setBusy(false);
    }
  };

  return (
<div className="fixed top-16 left-0 right-0 bottom-0 z-50 flex h-[calc(100vh-64px)]">
      {/* click-away */}
      <div className="flex-1 bg-black/50" onClick={onClose} />

      <div className="w-full max-w-md bg-white h-full shadow-2xl overflow-y-auto">
        <div className="p-3 border-b flex items-center justify-between sticky top-0 bg-white">
          <div className="font-semibold">AI Wingman</div>
          <button className="text-sm underline" onClick={onClose}>Close</button>
        </div>

        <div className="p-3 space-y-6">
          <section>
            <div className="text-sm text-gray-600 mb-2">Tone</div>
            <select
              className="border rounded px-2 py-1"
              value={tone}
              onChange={(e) => setTone(e.target.value)}
            >
              <option value="friendly">Friendly</option>
              <option value="funny">Funny</option>
              <option value="flirty">Flirty</option>
              <option value="polite">Polite</option>
              <option value="casual">Casual</option>
              <option value="confident">Confident</option>
            </select>
          </section>

          <section>
            <div className="flex items-center justify-between">
              <div className="font-medium">Suggest next lines</div>
              <button
                className="px-3 py-1 rounded bg-rose-500 text-white hover:bg-rose-600 disabled:opacity-60"
                disabled={busy}
                onClick={suggest}
              >
                {busy ? "Thinking…" : "Suggest"}
              </button>
            </div>
            <div className="mt-2 space-y-2">
              {tips.map((t, i) => (
                <div key={i} className="text-sm bg-rose-50 border rounded-lg p-2 flex items-start gap-2">
                  <span>💡</span>
                  <div className="flex-1">{t}</div>
                  <button className="text-xs underline" onClick={() => onUseTip(t)}>Use</button>
                </div>
              ))}
              {!tips.length && <div className="text-xs text-gray-500">No tips yet — click Suggest.</div>}
            </div>
          </section>

          <section>
            <div className="font-medium mb-1">Rewrite my draft</div>
            <textarea
              className="w-full border rounded p-2 text-sm"
              rows={3}
              placeholder="Paste your draft message…"
              value={rewriteSrc}
              onChange={(e) => setRewriteSrc(e.target.value)}
            />
            <div className="mt-2 flex gap-2">
              <button
                className="px-3 py-1 rounded bg-gray-900 text-white hover:bg-black disabled:opacity-60"
                disabled={busy || !rewriteSrc.trim()}
                onClick={doRewrite}
              >
                {busy ? "Working…" : "Rewrite"}
              </button>
              {!!rewriteOut && (
                <button
                  className="px-3 py-1 rounded bg-rose-500 text-white hover:bg-rose-600"
                  onClick={() => onUseTip(rewriteOut)}
                >
                  Use
                </button>
              )}
            </div>
            {!!rewriteOut && (
              <div className="mt-2 p-2 border rounded text-sm bg-gray-50">{rewriteOut}</div>
            )}
          </section>

          <section className="text-xs text-gray-500">
            Tips are generated from recent chat context; never share personal data you’re not comfortable with. 💛
          </section>
        </div>
      </div>
    </div>
  );
}
