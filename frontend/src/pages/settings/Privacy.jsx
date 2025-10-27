import React, { useEffect, useState } from "react";
const API_BASE = "http://localhost:4000/api";
const token = () => localStorage.getItem("token") || sessionStorage.getItem("token") || "";

const FIELDS = [
  ["age","Age"],["height","Height"],["city","City"],["orientation","Orientation"],
  ["interests","Interests"],["hobbies","Hobbies"],["likes","Likes"],["dislikes","Dislikes"],
  ["lookingFor","Looking for"],["voiceIntro","Voice intro"],["photos","Photos"],
];

const Opt = ({label,value,onChange}) => (
  <label className="inline-flex items-center gap-2 text-sm">
    <input type="radio" checked={value===label.toLowerCase()} onChange={() => onChange(label.toLowerCase())}/>
    {label}
  </label>
);

export default function Privacy() {
  const [form, setForm] = useState({ visibilityMode: "auto", fieldVisibility: {} });

  useEffect(() => {
    (async () => {
      const r = await fetch(`${API_BASE}/auth/me`, { headers: { Authorization: `Bearer ${token()}` }});
      const j = await r.json();
      const u = j.user || {};
      setForm({
        visibilityMode: u.visibilityMode || "auto",
        fieldVisibility: { ...FIELDS.reduce((a,[k]) => (a[k]="public",a), {}), ...(u.fieldVisibility||{}) }
      });
    })();
  }, []);

  const setField = (k,val) =>
    setForm(p => ({...p, fieldVisibility: {...p.fieldVisibility, [k]: val}}));

  const save = async () => {
    await fetch(`${API_BASE}/users/me`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token()}` },
      body: JSON.stringify(form),
    });
    alert("Privacy saved ✔");
  };

  return (
    <div>
      <h3 className="text-lg font-semibold">Privacy</h3>
      <p className="text-sm text-gray-600 mb-4">Who can see your info</p>

      <div className="mb-6 p-4 rounded-xl border bg-gray-50">
        <div className="font-medium mb-2">Profile visibility</div>
        <div className="grid gap-3">
          {[
            ["auto","Auto (blur until match)","Photos appear blurred in Discover until you both like each other."],
            ["limited","Limited preview","Show a limited preview (up to 3 photos + a few facts)."],
            ["full","Full (except Matches-only)","Show full profile (except items set to “Matches only”)."],
            ["hidden","Hidden (not in Discover)","Not discoverable. Existing matches can still chat."]
          ].map(([key,label,desc]) => (
            <label key={key} className="flex items-start gap-3">
              <input type="radio" name="vis" checked={form.visibilityMode===key} onChange={()=>setForm(p=>({...p,visibilityMode:key}))}/>
              <div>
                <div className="font-medium">{label}</div>
                <div className="text-xs text-gray-600">{desc}</div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div className="grid gap-4">
        {FIELDS.map(([k, label]) => {
          const v = form.fieldVisibility[k] || "public";
          return (
            <div key={k} className="p-3 border rounded-xl">
              <div className="text-sm font-medium mb-2">{label}</div>
              <div className="flex gap-6">
                <Opt label="Public" value={v} onChange={(val)=>setField(k,val)} />
                <Opt label="Matches" value={v} onChange={(val)=>setField(k,val)} />
                <Opt label="Hidden" value={v} onChange={(val)=>setField(k,val)} />
              </div>
            </div>
          );
        })}
      </div>

      <button onClick={save} className="mt-5 px-4 py-2 rounded bg-rose-500 text-white">Save</button>
    </div>
  );
}
