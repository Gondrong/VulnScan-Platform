import React, { useState } from "react";
import { api, setToken } from "../api";

export default function Login(){
  const [email,setEmail] = useState("admin@local");
  const [password,setPassword] = useState("admin123");
  const [err,setErr] = useState("");

  async function submit(){
    setErr("");
    try{
      const r = await api("/auth/login", { method:"POST", body:{ email, password } });
      setToken(r.token);
      location.href="/";
    }catch(e){
      setErr(e.message||String(e));
    }
  }

  return (
    <div style={{ maxWidth:420 }}>
      <h2>Login</h2>
      <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="email" style={{ width:"100%", marginBottom:8 }}/>
      <input value={password} onChange={e=>setPassword(e.target.value)} placeholder="password" type="password" style={{ width:"100%", marginBottom:8 }}/>
      <button onClick={submit}>Login</button>
      {err && <div style={{ color:"crimson", marginTop:8 }}>{err}</div>}
    </div>
  );
}
