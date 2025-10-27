import React, { useMemo } from "react";

/**
 * AiWingmanPanel
 * - self-contained, no API yet
 * - exposes 2 small utilities we’ll later replace with real AI
 * - compatibility% from mutual interests overlap
 */
export default function AiWingmanPanel({ me, them }) {
  const mutual = useMemo(() => {
    const a = new Set(me?.interests || []);
    return (them?.interests || []).filter((x) => a.has(x));
  }, [me, them]);

  const compatibility = useMemo(() => {
    const total = new Set([...(me?.interests || []), ...(them?.interests || [])]).size || 1;
    const score = Math.round((mutual.length / total) * 100);
    return Math.max(8, Math.min(96, score + (them?.hobbies?.length ? 4 : 0)));
  }, [me, them, mutual.length]);

  const opener = useMemo(() => {
    if (!mutual.length) return `I noticed we both like exploring new things. What’s your current obsession?`;
    const top = mutual.slice(0, 2).join(" & ");
    return `You both vibe on ${top}. Try: “Quick pick: ${top} night in or day out?”`;
  }, [mutual]);

  return (
    <div className="rounded-2xl p-4 bg-gradient-to-br from-rose-50 to-pink-50 border border-rose-100">
      <div className="flex items-center justify-between">
        <div className="text-sm text-gray-700">
          <div className="font-semibold text-gray-800">AI Wingman</div>
          <div className="mt-1">Compatibility: <span className="font-bold text-rose-600">{compatibility}%</span></div>
        </div>
      </div>

      <div className="mt-3">
        <div className="text-xs font-medium text-gray-600 mb-1">Suggested opener</div>
        <div className="text-sm text-gray-800 italic">{opener}</div>
      </div>

      {!!mutual.length && (
        <div className="mt-3">
          <div className="text-xs font-medium text-gray-600 mb-1">Shared vibes</div>
          <div className="flex flex-wrap gap-2">
            {mutual.map((m) => (
              <span key={m} className="px-2 py-1 rounded-full bg-white border text-rose-600 text-xs">
                #{m}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
