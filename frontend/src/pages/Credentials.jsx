import React, { useEffect, useState } from "react";
import { api } from "../api";

export default function Credentials(){
  const [items,setItems] = useState([]);
  const [name,setName] = useState("prod-ssh");
  const [username,setUsername] = useState("ubuntu");
  const [secretType,setSecretType] = useState("ssh_key");
  const [secret,setSecret] = useState("-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----");
  const [passphrase,setPassphrase] = useState("");
  const [msg,setMsg] = useState("");
  const [err,setErr] = useState("");

  async function load(){ setItems(await api("/credentials")); }
  useEffect(()=>{ load(); }, []);

  async function create(){
    setMsg(""); setErr("");
    try{
      await api("/credentials", { method:"POST", body:{
        name, kind:"ssh", username,
        secret_type: secretType,
        secret,
        passphrase: passphrase || null
      }});
      setMsg("Credential created");
      await load();
    }catch(e){ setErr(e.message||String(e)); }
  }

  return (
    <div>
      <h2>Credentials</h2>
      <div style={{ border:"1px solid #ddd", padding:12, borderRadius:12, maxWidth:900 }}>
        <h3>Create SSH Credential (admin only)</h3>
        <input value={name} onChange={e=>setName(e.target.value)} style={{ width:"100%", marginBottom:8 }}/>
        <input value={username} onChange={e=>setUsername(e.target.value)} style={{ width:"100%", marginBottom:8 }}/>
        <select value={secretType} onChange={e=>setSecretType(e.target.value)} style={{ width:"100%", marginBottom:8 }}>
          <option value="password">password</option>
          <option value="ssh_key">ssh_key</option>
        </select>
        <textarea rows={8} value={secret} onChange={e=>setSecret(e.target.value)} style={{ width:"100%", marginBottom:8 }}/>
        <input value={passphrase} onChange={e=>setPassphrase(e.target.value)} placeholder="passphrase optional" style={{ width:"100%", marginBottom:8 }}/>
        <button onClick={create}>Create</button>
        {msg && <div>{msg}</div>}
        {err && <div style={{ color:"crimson" }}>{err}</div>}
      </div>

      <h3 style={{ marginTop:16 }}>Existing</h3>
      <table border="1" cellPadding="6">
        <thead><tr><th>ID</th><th>Name</th><th>Username</th><th>Secret Type</th></tr></thead>
        <tbody>
          {items.map(i=>(
            <tr key={i.id}><td>{i.id}</td><td>{i.name}</td><td>{i.username}</td><td>{i.secret_type}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
