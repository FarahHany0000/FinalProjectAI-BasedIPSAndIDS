import React, { useState } from "react";
import Sidebar from "../Sidebar/Sidebar";

export default function Dashboard() {

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

  const [hosts] = useState(initialHosts);
  const [events] = useState(initialEvents);

  const allEvents = events;

  const generateAction = (severity) => {
    switch (severity) {
      case "Critical": return "Host Isolated";
      case "High": return "IP Blacklisted";
      case "Medium": return "Traffic Dropped";
      case "Low": return "Firewall Rule Added";
      default: return "No Action";
    }
  };

  /* ================= Host Status Logic ================= */

  const hostsWithStatus = hosts.map(host => {

    const hostEvents = allEvents.filter(e => e.host === host.name);
    const lastEvent = hostEvents[hostEvents.length - 1];

    const status =
      lastEvent && (lastEvent.severity === "Critical" || lastEvent.severity === "High")
        ? "Offline"
        : "Online";

    return { ...host, status };

  });

  /* ================= Statistics ================= */

  const totalThreats = allEvents.length;

  const criticalThreats = allEvents.filter(e => e.severity === "Critical").length;
  const highThreats = allEvents.filter(e => e.severity === "High").length;
  const mediumThreats = allEvents.filter(e => e.severity === "Medium").length;
  const lowThreats = allEvents.filter(e => e.severity === "Low").length;

  const activeHosts = hostsWithStatus.filter(h => h.status === "Online").length;
  const isolatedHosts = hostsWithStatus.filter(h => h.status === "Offline").length;

  return (

    <div className="dashboard-container">

      <Sidebar />

      <div className="dashboard-content">

        {/* ================= Header ================= */}

        <div className="icondesign">
          <div className="icons">
            <svg xmlns="http://www.w3.org/2000/svg" width="50" height="50" fill="currentColor" viewBox="0 0 16 16">
              <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856..." />
            </svg>
          </div>
          <h1>Dashboard</h1>
        </div>

        {/* ================= Statistics ================= */}

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

        {/* ================= Hosts Table ================= */}

        <div className="panel">

          <h3>Network Hosts Overview</h3>

          <table>

            <thead>
              <tr>
                <th>Host Name</th>
                <th>connection</th>
                <th>Total Attacks</th>
                <th>Last Severity</th>
                <th>Last Attack Time</th>
              </tr>
            </thead>

            <tbody>

              {hostsWithStatus.map((host, idx) => {

                const hostEvents = allEvents.filter(e => e.host === host.name);
                const totalAttacks = hostEvents.length;

                const lastEvent = hostEvents[hostEvents.length - 1] || {};

                const lastSeverity = lastEvent.severity || "-";
                const lastTime = lastEvent.date || "-";

                return (

                  <tr key={idx}>

                    <td>{host.name}</td>

                    <td className={host.status === "Online" ? "host-online" : "host-offline"}>
                      {host.status}
                    </td>

                    <td>{totalAttacks}</td>

                    <td className={`severity-${lastSeverity.toLowerCase()}`}>
                      {lastSeverity}
                    </td>

                    <td>{lastTime}</td>

                  </tr>

                );

              })}

            </tbody>

          </table>

        </div>

        {/* ================= Events Table ================= */}

        <div className="panel">

          <h3>Host Attack Events</h3>

          <table>

            <thead>
              <tr>
                <th>Host Name</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Action Taken</th>
              
              </tr>
            </thead>

            <tbody>

              {allEvents.map((event, idx) => {

                const hostLastEvent = allEvents
                  .filter(e => e.host === event.host)
                  .slice(-1)[0];

                const hostStatus =
                  hostLastEvent &&
                  (hostLastEvent.severity === "Critical" || hostLastEvent.severity === "High")
                    ? "Offline"
                    : "Online";

                return (

                  <tr key={idx}>

                    <td>{event.host}</td>

                    <td>{event.type}</td>

                    <td className={`severity-${event.severity.toLowerCase()}`}>
                      {event.severity}
                    </td>

                    <td>{generateAction(event.severity)}</td>

                    

                  </tr>

                );

              })}

            </tbody>

          </table>

        </div>

      </div>

    </div>

  );
}
