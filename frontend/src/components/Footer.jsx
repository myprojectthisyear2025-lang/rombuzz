// src/components/Footer.jsx
import React from "react";

export default function Footer() {
  return (
    <footer className="bg-gray-800 text-white text-center py-4 px-6 mt-auto relative z-40">
      <p className="text-sm">
        © {new Date().getFullYear()} <span className="font-semibold">Rombuzz</span>. All rights reserved.
      </p>

      <div className="flex justify-center gap-6 mt-2 text-sm">
        <a href="#" className="hover:text-rose-300 transition-colors">
          Privacy
        </a>
        <a href="#" className="hover:text-rose-300 transition-colors">
          Terms
        </a>
        <a href="#" className="hover:text-rose-300 transition-colors">
          Contact
        </a>
      </div>
    </footer>
  );
}
