import React, { useContext, useState, useEffect } from "react";
import Sidebar from "../Sidebar/Sidebar";
import { SystemContext } from "../../context/SystemContext";
import "./Dashboard.css";

export default function Dashboard() {
  const { hosts: contextHosts, events: contextEvents, toastMessage, scanNetwork } = useContext(SystemContext);

  // =============================== Static Initial Data ===============================
  const initialHosts = [
    { name: "Host-1", status: "Online" },
    { name: "Host-2", status: "Online" },
    { name: "Host-3", status: "Offline" }
  ];

  const initialEvents = [
    { date: "2026-03-01", type: "DDoS", host: "Host-1", severity: "High" },
    { date: "2026-03-02", type: "Malware", host: "Host-2", severity: "Critical" },
    { date: "2026-03-03", type: "Phishing", host: "Host-3", severity: "Medium" },
    { date: "2026-03-04", type: "Spam", host: "Host-1", severity: "Low" }
  ];

  // =============================== Local State ===============================
  const [hosts, setHosts] = useState(initialHosts);
  const [events, setEvents] = useState(initialEvents);

  // =============================== IPS Decision Engine ===============================
  const generateAction = (severity) => {
    switch (severity) {
      case "Critical": return "Host Isolated";
      case "High": return "IP Blacklisted";
      case "Medium": return "Traffic Dropped";
      case "Low": return "Firewall Rule Added";
      default: return "Connection Reset";
    }
  };

  // =============================== Add New Events after Scan ===============================
  useEffect(() => {
    if (!scanNetwork) return;

    const newEvents = contextEvents
      .filter(e => !events.find(ev => ev.date === e.date && ev.host === e.host && ev.type === e.type))
      .map(e => ({
        ...e,
        date: new Date().toISOString().split("T")[0]
      }));

    if (newEvents.length > 0) setEvents(prev => [...prev, ...newEvents]);

    const newHosts = contextHosts.filter(h => !hosts.find(existing => existing.name === h.name));
    if (newHosts.length > 0) setHosts(prev => [...prev, ...newHosts]);

  }, [scanNetwork, contextEvents, contextHosts, hosts, events]);

  // =============================== Stats ===============================
  const allEvents = events; // كل الأحداث الحالية بعد الدمج
  const totalThreats = allEvents.length;
  const criticalThreats = allEvents.filter(e => e.severity === "Critical").length;
  const highThreats = allEvents.filter(e => e.severity === "High").length;
  const mediumThreats = allEvents.filter(e => e.severity === "Medium").length;
  const lowThreats = allEvents.filter(e => e.severity === "Low").length;

  const activeHosts = hosts.filter(h => h.status === "Online").length;
  const isolatedHosts = allEvents.filter(e => e.severity === "Critical" || e.severity === "High").length;

  // =============================== Render ===============================
  return (
    <div className="dashboard-container">
      <Sidebar />

      {toastMessage && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "100%",
          padding: "15px 0",
          textAlign: "center",
          backgroundColor: "#ef4444",
          color: "#fff",
          fontWeight: "bold",
          zIndex: 9999,
          boxShadow: "0px 2px 10px rgba(0,0,0,0.3)"
        }}>
          {toastMessage}
        </div>
      )}

      <div className="dashboard-content">
        {/* Header */}
        <div className="icondesign">
          <div className="icons">
            <svg xmlns="http://www.w3.org/2000/svg" width="50" height="50" fill="currentColor" viewBox="0 0 16 16">
              <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.73 10.73 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.55.55 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.856C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/>
              <path d="M8 5.993c1.664 0 3.007 1.343 3.007 3.007S9.664 12.007 8 12.007 4.993 10.664 4.993 9 6.336 5.993 8 5.993z"/>
            </svg>
          </div>
          <h1>Dashboard</h1>
        </div>

        {/* Stats */}
        <div className="stats-grid">
          <div className="stat-card">
            <h4>Total Attacks</h4>
            <p>{totalThreats}</p>
          </div>

          <div className="stat-card">
            <h4>Critical Attacks</h4>
            <p className="severity-critical">{criticalThreats}</p>
          </div>

          <div className="stat-card">
            <h4>High Attacks</h4>
            <p className="severity-high">{highThreats}</p>
          </div>

          <div className="stat-card">
            <h4>Medium Attacks</h4>
            <p className="severity-medium">{mediumThreats}</p>
          </div>

          <div className="stat-card">
            <h4>Low Attacks</h4>
            <p className="severity-low">{lowThreats}</p>
          </div>

          <div className="stat-card">
            <h4>Active Hosts</h4>
            <p className="host-online">{activeHosts}</p>
          </div>

          <div className="stat-card">
            <h4>Isolated Hosts</h4>
            <p className="host-offline">{isolatedHosts}</p>
          </div>
        </div>

        {/* Events Table */}
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>Date</th>
                <th>Attack Type</th>
                <th>Host</th>
                <th>Severity</th>
                <th>Action Applied</th>
                <th>Connection</th>
              </tr>
            </thead>
            <tbody>
              {allEvents.map((event, idx) => (
                <tr key={idx}>
                  <td>{event.date}</td>
                  <td>{event.type}</td>
                  <td>{event.host}</td>
                  <td className={`severity-${event.severity.toLowerCase()}`}>{event.severity}</td>
                  <td>{generateAction(event.severity)}</td>
                  <td className={`host-${event.severity === "Critical" || event.severity === "High" ? "offline" : "online"}`}>
                    {event.severity === "Critical" || event.severity === "High" ? "Offline" : "Online"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}