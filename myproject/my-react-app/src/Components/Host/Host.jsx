import React, { useContext, useEffect, useState } from "react";
import "./Host.css";
import Sidebar from "../Sidebar/Sidebar";
import { SystemContext } from "../../context/SystemContext";

export default function Host() {

  const { hosts } = useContext(SystemContext);

  const [stats, setStats] = useState({
    total: 0,
    online: 0,
    warning: 0,
    threats: 0,
  });

  useEffect(() => {

    setStats({
      total: hosts.length,
      online: hosts.filter((h) => h.status === "Online").length,
      warning: hosts.filter((h) => h.status === "Warning").length,
      threats: hosts.reduce((sum, h) => sum + h.threats, 0),
    });

  }, [hosts]);

  return (
    <div className="dashboard">
      <Sidebar />

      <div className="host-content">

        <div className="icondesign">
          <div className="icons">
            <svg xmlns="http://www.w3.org/2000/svg" width="50" height="50" fill="currentColor" viewBox="0 0 16 16">
              <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.73 10.73 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.55.55 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.856C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/>
              <path d="M8 5.993c1.664 0 3.007 1.343 3.007 3.007S9.664 12.007 8 12.007 4.993 10.664 4.993 9 6.336 5.993 8 5.993z"/>
            </svg>
          </div>

          <h1>Host Monitoring</h1>
        </div>

        <p className="subtitle">
          Real-time intrusion detection and prevention overview
        </p>

        {/* Stats */}
        <div className="host-stats">
          <div className="stat-card">
            Total Agents
            <span>{stats.total}</span>
          </div>

          <div className="stat-card success">
            Online
            <span>{stats.online}</span>
          </div>

          <div className="stat-card warning">
            Warning
            <span>{stats.warning}</span>
          </div>

          <div className="stat-card danger">
            Total Threats
            <span>{stats.threats}</span>
          </div>
        </div>

        {/* Hosts */}
        <div className="host-grid">

          {hosts.map((host, index) => (

            <div
              key={index}
              className={`host-card
                ${host.threats > 0
                  ? "danger-bg"
                  : host.status === "Offline"
                  ? "offline-bg"
                  : host.status === "Warning"
                  ? "warning-bg"
                  : ""}
              `}
            >

              <div className="host-header">

                <div className="host-title">
                  <span
                    className={`status-icon
                      ${host.threats > 0
                        ? "danger"
                        : host.status.toLowerCase()}
                    `}
                  />

                  <h3>{host.name}</h3>
                </div>

                <span
                  className={`badge
                    ${host.threats > 0
                      ? "danger"
                      : host.status.toLowerCase()}
                  `}
                >
                  {host.status}
                </span>

              </div>

              <p className="host-sub">
                {host.ip} • {host.os}
              </p>

              {["cpu", "memory", "disk", "network"].map((item) => (

                <div key={item}>

                  <div className="metric">
                    <span>{item.toUpperCase()}</span>

                    <span>
                      {host.status === "Offline"
                        ? "Offline"
                        : `${host[item]}%`}
                    </span>

                  </div>

                  <div className="progress">

                    <div
                      style={{
                        width: host.status === "Offline"
                          ? "100%"
                          : `${host[item]}%`,

                        backgroundColor:
                          host.threats > 0
                            ? "#ef4444"
                            : host.status === "Warning"
                            ? "#facc15"
                            : host.status === "Offline"
                            ? "#6b7280"
                            : "#2563eb",

                        opacity: host.status === "Offline" ? 0.6 : 1,

                        display: "flex",
                        alignItems: "center",
                        justifyContent: host.status === "Offline"
                          ? "center"
                          : "flex-end",

                        color: host.status === "Offline"
                          ? "white"
                          : "transparent",

                        fontWeight: host.status === "Offline"
                          ? "600"
                          : "normal",

                        fontSize: "12px"
                      }}
                    >
                      {host.status === "Offline" ? "Offline" : ""}
                    </div>

                  </div>

                </div>

              ))}

              <div className="host-footer">

                <span>
                  Threats:
                  <b className={host.threats > 0 ? "danger-text" : ""}>
                    {host.threats}
                  </b>
                </span>

              </div>

            </div>

          ))}

        </div>

      </div>
    </div>
  );
}