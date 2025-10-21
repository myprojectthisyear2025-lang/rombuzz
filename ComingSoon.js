// frontend/src/pages/ComingSoon.jsx
import React from "react";

export default function ComingSoon() {
  const img = "/src/assets/heartrombuzz"; // update if your path differs

  return (
    <div className="min-h-screen grid place-items-center bg-gradient-to-br from-pink-600 via-rose-500 to-amber-400">
      <div className="w-[92vw] max-w-4xl bg-white rounded-3xl shadow-2xl overflow-hidden">
        <div
          className="h-[42vh] sm:h-[50vh] bg-center bg-cover relative"
          style={{ backgroundImage: `url(${img})` }}
          aria-label="RomBuzz hero"
        >
          <div className="absolute inset-0 bg-black/40" />
          <div className="absolute top-4 left-4">
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-white border border-white/40 bg-white/10 backdrop-blur">
              <span className="w-3.5 h-3.5 inline-block bg-white rounded-full" />
              RomBuzz
            </span>
          </div>
        </div>

        <div className="p-6 sm:p-8">
          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight">
            Coming Soon
          </h1>
          <p className="mt-3 text-gray-600">
            We’re polishing the last details of RomBuzz — a fresh way to meet in the middle and plan better dates.
          </p>

          <a
            href="mailto:hello@rombuzz.com?subject=Keep%20me%20posted"
            className="mt-6 inline-flex items-center gap-2 px-5 py-3 rounded-xl font-semibold text-white bg-gradient-to-r from-rose-500 to-amber-400 hover:opacity-95 transition"
          >
            Get launch updates →
          </a>

          <p className="mt-4 text-sm text-gray-500">
            © {new Date().getFullYear()} RomBuzz. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
}
