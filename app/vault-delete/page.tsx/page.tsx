"use client";

import { useState } from "react";

export default function VaultDeleteHelper() {
  const [adminPass, setAdminPass] = useState("");
  const [id, setId] = useState("vlt_1b9860786999");
  const [result, setResult] = useState("");

  async function run() {
    setResult("sending...");
    try {
      const res = await fetch("/api/vault/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, adminPass }),
      });
      const text = await res.text();
      setResult(`HTTP ${res.status} ${text}`);
    } catch (err) {
      setResult(`error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return (
    <main style={{ padding: 24, fontFamily: "sans-serif" }}>
      <h1>Temporary vault-delete helper</h1>
      <p>
        <label>
          Entry id{" "}
          <input value={id} onChange={(e) => setId(e.target.value)} />
        </label>
      </p>
      <p>
        <label>
          Admin passphrase{" "}
          <input
            type="password"
            value={adminPass}
            onChange={(e) => setAdminPass(e.target.value)}
          />
        </label>
      </p>
      <button onClick={run}>Delete entry</button>
      <pre>{result}</pre>
    </main>
  );

}
