import { useState, useEffect } from "react";

const API = "http://localhost:8000";
const SEV_COLORS = { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#2563eb", info: "#6b7280" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const STATUS_LABELS = { new: "New", investigating: "Investigating", mitigated: "Mitigated", resolved: "Resolved" };

function useIncidents(filters) {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    setLoading(true);
    const params = new URLSearchParams();
    if (filters.severity?.length) params.set("severity", filters.severity.join(","));
    if (filters.status?.length) params.set("status", filters.status.join(","));
    fetch(`${API}/incidents?${params}`)
      .then((r) => r.json())
      .then((data) => { setIncidents(data.incidents || data || []); setLoading(false); })
      .catch(() => { setIncidents(mockData()); setLoading(false); });
  }, [filters.severity, filters.status]);
  return { incidents, loading };
}

function mockData() {
  const sevs = ["critical","high","medium","low","info"];
  const sts = ["new","investigating","mitigated","resolved"];
  return Array.from({ length: 20 }, (_, i) => ({
    id: `INC-${String(i + 1).padStart(4, "0")}`,
    title: [`API latency spike`, `Pod crash loop`, `Disk usage >90%`, `SSL cert expiring`, `Rate limit breached`][i % 5],
    severity: sevs[i % 5],
    status: sts[i % 4],
    service: [`payment-svc`, `auth-svc`, `gateway`, `worker`, `cache`][i % 5],
    created_at: new Date(Date.now() - i * 3600000).toISOString(),
    description: "Automated alert correlated into incident by rules engine.",
    notifications: Math.floor(Math.random() * 3),
  }));
}

export default function App() {
  const [sevFilter, setSevFilter] = useState([]);
  const [statusFilter, setStatusFilter] = useState([]);
  const [selected, setSelected] = useState(null);
  const { incidents, loading } = useIncidents({ severity: sevFilter, status: statusFilter });

  const toggle = (arr, setArr, val) => setArr((a) => a.includes(val) ? a.filter((x) => x !== val) : [...a, val]);

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 1200, margin: "0 auto", padding: 20 }}>
      <h1 style={{ margin: "0 0 16px" }}>🚨 Incident Triage Dashboard</h1>
      <div style={{ display: "flex", gap: 24, marginBottom: 16, flexWrap: "wrap" }}>
        <div><strong>Severity:</strong>{" "}{SEV_ORDER.map((s) => (
          <button key={s} onClick={() => toggle(sevFilter, setSevFilter, s)}
            style={{ margin: 2, padding: "4px 10px", borderRadius: 4, border: "1px solid",
              background: sevFilter.includes(s) ? SEV_COLORS[s] : "#fff",
              color: sevFilter.includes(s) ? "#fff" : SEV_COLORS[s],
              borderColor: SEV_COLORS[s], cursor: "pointer", fontSize: 12 }}>{s}</button>
        ))}</div>
        <div><strong>Status:</strong>{" "}{Object.keys(STATUS_LABELS).map((s) => (
          <button key={s} onClick={() => toggle(statusFilter, setStatusFilter, s)}
            style={{ margin: 2, padding: "4px 10px", borderRadius: 4, border: "1px solid #999",
              background: statusFilter.includes(s) ? "#333" : "#fff",
              color: statusFilter.includes(s) ? "#fff" : "#333", cursor: "pointer", fontSize: 12 }}>
            {STATUS_LABELS[s]}</button>
        ))}</div>
      </div>
      <div style={{ display: "flex", gap: 16 }}>
        <table style={{ flex: 1, borderCollapse: "collapse", fontSize: 14, minWidth: 0 }}>
          <thead><tr style={{ background: "#f3f4f6", textAlign: "left" }}>
            {["ID","Severity","Status","Title","Service","Time"].map((h) => (
              <th key={h} style={{ padding: "8px 10px", borderBottom: "2px solid #d1d5db" }}>{h}</th>
            ))}
          </tr></thead>
          <tbody>
            {loading && <tr><td colSpan={6} style={{ padding: 20, textAlign: "center" }}>Loading…</td></tr>}
            {incidents.map((inc) => (
              <tr key={inc.id} onClick={() => setSelected(inc)}
                style={{ cursor: "pointer", background: selected?.id === inc.id ? "#e0e7ff" : "#fff" }}>
                <td style={{ padding: "6px 10px", borderBottom: "1px solid #e5e7eb" }}>{inc.id}</td>
                <td style={{ padding: "6px 10px", borderBottom: "1px solid #e5e7eb" }}>
                  <span style={{ background: SEV_COLORS[inc.severity], color: "#fff", padding: "2px 8px",
                    borderRadius: 10, fontSize: 11, fontWeight: 600 }}>{inc.severity}</span></td>
                <td style={{ padding: "6px 10px", borderBottom: "1px solid #e5e7eb" }}>{STATUS_LABELS[inc.status] || inc.status}</td>
                <td style={{ padding: "6px 10px", borderBottom: "1px solid #e5e7eb" }}>{inc.title}</td>
                <td style={{ padding: "6px 10px", borderBottom: "1px solid #e5e7eb" }}>{inc.service}</td>
                <td style={{ padding: "6px 10px", borderBottom: "1px solid #e5e7eb", whiteSpace: "nowrap" }}>
                  {new Date(inc.created_at).toLocaleString()}</td>
              </tr>
            ))}
            {!loading && incidents.length === 0 && <tr><td colSpan={6} style={{ padding: 20, textAlign: "center", color: "#999" }}>No incidents match filters</td></tr>}
          </tbody>
        </table>
        {selected && (
          <div style={{ width: 320, minWidth: 320, background: "#f9fafb", borderRadius: 8, padding: 16, border: "1px solid #e5e7eb", alignSelf: "flex-start" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <h3 style={{ margin: 0 }}>{selected.id}</h3>
              <button onClick={() => setSelected(null)} style={{ border: "none", background: "none", cursor: "pointer", fontSize: 18 }}>✕</button>
            </div>
            <p style={{ margin: "0 0 8px", fontWeight: 600 }}>{selected.title}</p>
            <div style={{ marginBottom: 6 }}><span style={{ background: SEV_COLORS[selected.severity], color: "#fff",
              padding: "2px 8px", borderRadius: 10, fontSize: 11, fontWeight: 600 }}>{selected.severity}</span>{" "}
              <span style={{ fontSize: 13, color: "#555" }}>{STATUS_LABELS[selected.status]}</span></div>
            <div style={{ fontSize: 13, color: "#555", lineHeight: 1.6 }}>
              <div><strong>Service:</strong> {selected.service}</div>
              <div><strong>Created:</strong> {new Date(selected.created_at).toLocaleString()}</div>
              <div><strong>Notifications sent:</strong> {selected.notifications}</div>
              <p style={{ margin: "8px 0 0" }}>{selected.description}</p>
            </div>
            <div style={{ marginTop: 16, display: "flex", gap: 6, flexWrap: "wrap" }}>
              {Object.keys(STATUS_LABELS).filter((s) => s !== selected.status).map((s) => (
                <button key={s} onClick={() => { selected.status = s; setSelected({ ...selected }); }}
                  style={{ padding: "4px 12px", fontSize: 12, borderRadius: 4, border: "1px solid #999",
                    background: "#fff", cursor: "pointer" }}>→ {STATUS_LABELS[s]}</button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}