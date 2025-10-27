import React, { useEffect, useState } from "react";
const API_BASE = "http://localhost:4000/api";
const token = () => localStorage.getItem("token") || sessionStorage.getItem("token") || "";

export default function Blocking() {
  const [list, setList] = useState([]);

  const load = async () => {
    const r = await fetch(`${API_BASE}/blocks`, { headers: { Authorization: `Bearer ${token()}` }});
    const j = await r.json();
    setList(j.blocks || []);
  };
  const unblock = async (userId) => {
    await fetch(`${API_BASE}/blocks/${userId}`, { method: "DELETE", headers: { Authorization: `Bearer ${token()}` }});
    load();
  };
  useEffect(()=>{ load(); }, []);

  return (
    <div>
      <h3 className="text-lg font-semibold">Blocking</h3>
      <ul className="mt-4 space-y-2">
        {list.map(b => (
          <li key={b.id} className="border rounded px-3 py-2 flex items-center justify-between">
            <div className="text-sm">{b.firstName} {b.lastName}</div>
            <button onClick={()=>unblock(b.id)} className="text-rose-600 text-sm">Unblock</button>
          </li>
        ))}
        {!list.length && <div className="text-sm text-gray-500">No one blocked.</div>}
      </ul>
    </div>
  );
}
