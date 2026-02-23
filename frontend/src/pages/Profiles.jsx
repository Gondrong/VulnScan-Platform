import React, { useEffect, useState } from "react";
import { api } from "../api";

export default function Profiles(){
  const [items,setItems] = useState([]);
  const [name,setName] = useState("default");
  const [plugins,setPlugins] = useState(`{
  "net.port.discovery.v2": true,
  "fingerprint.http": true,
  "fingerprint.banner.multi": true,
  "fingerprint.web.tech": true,
  "fingerprint.favicon.hash": true,
  "cpe.builder": true,
  "cve.match.nvd_cpe": true,
  "cve.match.cms": true,
  "priority.cisa_kev": true,
  "tls.basic.version": true,
  "auth.ssh.inventory": false,
  "cve.match.packages": false
}`);
  const [options,setOptions] = useState(`{
  "auth": { "ssh_credential_id": 1, "ssh_port": 22 },
  "cve": { "dataset_kinds": ["osv","nvd_cpe_cve","cisa_kev","cms_cve_map","favicon_hash_map","compliance_map"] },
  "asset": { "criticality": 2 }
}`);
  const [msg,setMsg] = useState("");
  const [err,setErr] = useState("");

  async function load(){ setItems(await api("/scan/profiles")); }
  useEffect(()=>{ load(); }, []);

  async function create(){
    setMsg(""); setErr("");
    try{
      await api("/scan/profiles", { method:"POST", body:{
        name,
        plugin_selection_json: plugins,
        options_json: options
      }});
      setMsg("Profile created");
      await load();
    }catch(e){ setErr(e.message||String(e)); }
  }

  return (
    <div>
      <h2>Profiles</h2>
      <div style={{ border:"1px solid #ddd", padding:12, borderRadius:12, maxWidth:900 }}>
        <h3>Create</h3>
        <input value={name} onChange={e=>setName(e.target.value)} style={{ width:"100%", marginBottom:8 }}/>
        <label>plugin_selection_json</label>
        <textarea rows={10} value={plugins} onChange={e=>setPlugins(e.target.value)} style={{ width:"100%", marginBottom:8 }}/>
        <label>options_json</label>
        <textarea rows={8} value={options} onChange={e=>setOptions(e.target.value)} style={{ width:"100%", marginBottom:8 }}/>
        <button onClick={create}>Create</button>
        {msg && <div>{msg}</div>}
        {err && <div style={{ color:"crimson" }}>{err}</div>}
      </div>

      <h3 style={{ marginTop:16 }}>Existing</h3>
      <table border="1" cellPadding="6">
        <thead><tr><th>ID</th><th>Name</th></tr></thead>
        <tbody>
          {items.map(p=>(
            <tr key={p.id}><td>{p.id}</td><td>{p.name}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
