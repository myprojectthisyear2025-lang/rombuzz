import React, { useState } from "react";
export default function Notifications() {
  const [email, setEmail] = useState(true);
  const [push, setPush] = useState(true);
  return (
    <div>
      <h3 className="text-lg font-semibold">Notifications</h3>
      <div className="mt-4 grid gap-3 max-w-lg">
        <label className="flex items-center gap-2"><input type="checkbox" checked={email} onChange={e=>setEmail(e.target.checked)} /> Email notifications</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={push} onChange={e=>setPush(e.target.checked)} /> Push notifications</label>
        <p className="text-xs text-gray-500">Wire these toggles to your notifications API.</p>
      </div>
    </div>
  );
}
