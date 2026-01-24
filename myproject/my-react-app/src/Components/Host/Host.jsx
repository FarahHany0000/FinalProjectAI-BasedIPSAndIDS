import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Host.css";
import Sidebar from "../Sidebar/Sidebar";

export default function Host() {
  const navigate = useNavigate();

  const [hosts, setHosts] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    online: 0,
    warnings: 0,
    threats: 0,
  });

  useEffect(() => {
    const token = localStorage.getItem("token");

    // ✅ لو مفيش توكن يرجع للّوجين
    if (!token) {
      navigate("/host");
      return;
    }

    fetchHosts();
  }, [navigate]);

  const fetchHosts = () => {
    // ===== Fake Backend Data =====
    const fakeHosts = [
      {
        name: "PC-01",
        ip: "192.168.1.2",
        os: "Windows 10",
        status: "Online",
        cpu: 22,
        memory: 20,
        disk: 12,
        network: 0,
        threats: 0,
      },
      {
        name: "PC-03",
        ip: "192.168.1.4",
        os: "Windows 7",
        status: "Warning",
        cpu: 94,
        memory: 98,
        disk: 94,
        network: 50,
        threats: 2,
      },
      {
        name: "PC-02",
        ip: "192.168.1.3",
        os: "Windows 10",
        status: "Offline",
        cpu: 0,
        memory: 0,
        disk: 0,
        network: 0,
        threats: 0,
      },
    ];

    setHosts(fakeHosts);

    setStats({
      total: fakeHosts.length,
      online: fakeHosts.filter(h => h.status === "Online").length,
      warnings: fakeHosts.filter(h => h.status === "Warning").length,
      threats: fakeHosts.reduce((sum, h) => sum + h.threats, 0),
    });
  };

  return (
    <div className="dashboard">
      <Sidebar />

      <div className="host-content">

        {/* ===== HEADER ===== */}
        <div className="icondesign">
          <div className="icons">
               <svg
          xmlns="http://www.w3.org/2000/svg"
          width="50"
          height="50"
          fill="currentColor"
          viewBox="0 0 16 16"
        >
          <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.73 10.73 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.55.55 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.856C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/>
          <path d="M8 5.993c1.664 0 3.007 1.343 3.007 3.007S9.664 12.007 8 12.007 4.993 10.664 4.993 9 6.336 5.993 8 5.993z"/>
        </svg>
          </div>
          <h1>Host Monitoring</h1>
        </div>

        <p className="subtitle">
          Real-time intrusion detection and prevention overview
        </p>

        {/* ===== TOP STATS ===== */}
        <div className="host-stats">
          <div className="stat-card">Total Agents <span>{stats.total}</span></div>
          <div className="stat-card success">Online <span>{stats.online}</span></div>
          <div className="stat-card warning">Warnings <span>{stats.warnings}</span></div>
          <div className="stat-card danger">Total Threats <span>{stats.threats}</span></div>
        </div>

        {/* ===== HOST CARDS ===== */}
        <div className="host-grid">
          {hosts.map((host, index) => (
            <div key={index} className="host-card">

              <div className="host-header">
                <div className="host-title">
                  <span className={`status-icon ${host.status.toLowerCase()}`} />
                  <h3>{host.name}</h3>
                </div>

                <span className={`badge ${host.status.toLowerCase()}`}>
                  {host.status}
                </span>
              </div>

              <p className="host-sub">
                {host.ip} • {host.os}
              </p>

              {/* METRICS */}
              {["cpu", "memory", "disk", "network"].map((item) => (
                <div key={item}>
                  <div className="metric">
                    <span>{item.toUpperCase()}</span>
                    <span>{host[item]}%</span>
                  </div>
                  <div className="progress">
                    <div style={{ width: `${host[item]}%` }} />
                  </div>
                </div>
              ))}

              <div className="host-footer">
                <span>
                  Threats:{" "}
                  <b className={host.threats > 0 ? "danger-text" : ""}>
                    {host.threats}
                  </b>
                </span>
                <button className="refresh">⟳</button>
              </div>

            </div>
          ))}
        </div>

      </div>
    </div>
  );
}
