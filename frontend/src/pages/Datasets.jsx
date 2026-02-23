import React, { useEffect, useState } from "react";
import { api } from "../api";

export default function Datasets(){
  const [items,setItems] = useState([]);
  const [kind,setKind] = useState("nvd_cpe_cve");
  const [name,setName] = useState("nvd-sample");
  const [file,setFile] = useState(null);
  const [msg,setMsg] = useState("");
  const [err,setErr] = useState("");

  async function load(){ setItems(await api("/datasets")); }
  useEffect(()=>{ load(); }, []);

  async function upload(){
    setMsg(""); setErr("");
    if (!file) return setErr("Pick file first");
    const form = new FormData();
    form.append("file", file);
    try{
      const r = await api(`/datasets/upload?kind=${encodeURIComponent(kind)}&name=${encodeURIComponent(name)}`, {
        method:"POST",
        body: form,
        headers: {} // do not force JSON content-type
      });
      setMsg(`Uploaded dataset_id=${r.dataset_id}`);
      await load();
    }catch(e){ setErr(e.message||String(e)); }
  }

  return (
    <div>
      <h2>Datasets</h2>
      <div style={{ border:"1px solid #ddd", padding:12, borderRadius:12, maxWidth:900 }}>
        <h3>Upload (admin only)</h3>
        <select value={kind} onChange={e=>setKind(e.target.value)} style={{ width:"100%", marginBottom:8 }}>
          <option value="osv">osv</option>
          <option value="nvd_cpe_cve">nvd_cpe_cve</option>
          <option value="cisa_kev">cisa_kev</option>
          <option value="favicon_hash_map">favicon_hash_map</option>
          <option value="cms_cve_map">cms_cve_map</option>
          <option value="compliance_map">compliance_map</option>
        </select>
        <input value={name} onChange={e=>setName(e.target.value)} style={{ width:"100%", marginBottom:8 }}/>
        <input type="file" onChange={e=>setFile(e.target.files?.[0] || null)} style={{ width:"100%", marginBottom:8 }}/>
        <button onClick={upload}>Upload</button>
        {msg && <div>{msg}</div>}
        {err && <div style={{ color:"crimson" }}>{err}</div>}
      </div>

      <h3 style={{ marginTop:16 }}>Existing</h3>
      <table border="1" cellPadding="6">
        <thead><tr><th>ID</th><th>Name</th><th>Kind</th><th>Enabled</th></tr></thead>
        <tbody>
          {items.map(d=>(
            <tr key={d.id}><td>{d.id}</td><td>{d.name}</td><td>{d.kind}</td><td>{String(d.enabled)}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
