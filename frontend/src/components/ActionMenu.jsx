// src/components/ActionMenu.jsx
import React, { useEffect, useRef, useState } from "react";

export default function ActionMenu({
  buttonClassName = "",
  menuClassName = "",
  align = "right", // "left" | "right"
  items = [], // [{ label, icon, onClick, danger }]
  onOpen,
  onClose,
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function onDoc(e) {
      if (!ref.current) return;
      if (!ref.current.contains(e.target)) {
        setOpen(false);
        onClose?.();
      }
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("touchstart", onDoc);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("touchstart", onDoc);
    };
  }, [onClose]);

  const pos =
    align === "left"
      ? "left-0 origin-top-left"
      : "right-0 origin-top-right";

  return (
    <div className="relative inline-block text-left" ref={ref}>
      <button
        type="button"
        className={
          buttonClassName ||
          "p-2 rounded-full hover:bg-gray-100 transition focus:outline-none"
        }
        onClick={() => {
          const next = !open;
          setOpen(next);
          if (next) onOpen?.();
          else onClose?.();
        }}
        aria-haspopup="menu"
        aria-expanded={open ? "true" : "false"}
      >
        {/* 3 dots */}
        <svg
          xmlns="http://www.w3.org/2000/svg"
          className="h-5 w-5 text-gray-600"
          viewBox="0 0 20 20"
          fill="currentColor"
        >
          <path d="M6 10a2 2 0 11-4 0 2 2 0 014 0zm6 0a2 2 0 11-4 0 2 2 0 014 0zm6 0a2 2 0 11-4 0 2 2 0 014 0z" />
        </svg>
      </button>

      {/* Menu */}
      {open && (
        <div
          className={
            menuClassName ||
            `absolute z-20 mt-2 min-w-[180px] ${pos} rounded-xl border border-gray-100 bg-white shadow-xl ring-1 ring-black/5 animate-[fadeIn_.12s_ease-in-out]`
          }
          role="menu"
        >
          <ul className="py-1">
            {items.map((it, i) => (
              <li key={i}>
                <button
                  type="button"
                  className={`w-full flex items-center gap-2 px-4 py-2 text-sm hover:bg-gray-50 ${
                    it.danger ? "text-red-600" : "text-gray-700"
                  }`}
                  onClick={() => {
                    setOpen(false);
                    it.onClick?.();
                    onClose?.();
                  }}
                >
                  <span className="inline-flex w-4 h-4 items-center justify-center">
                    {it.icon || null}
                  </span>
                  <span>{it.label}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* tiny keyframes */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: scale(0.98); }
          to { opacity: 1; transform: scale(1); }
        }
      `}</style>
    </div>
  );
}
