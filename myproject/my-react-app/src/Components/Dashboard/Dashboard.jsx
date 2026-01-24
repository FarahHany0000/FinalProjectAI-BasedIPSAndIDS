import React, { useEffect, useState } from "react";
import StatesCard from "../StatesCard/StatesCard";
import Sidebar from "../Sidebar/Sidebar";
import AttackDistribution from '../AttackDistribution/AttackDistribution';
import AttackTrends from '../AttackTrends/AttackTrends';
import RecentAlert from '../RecentAlert/RecentAlert';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [trends, setTrends] = useState([]);
  const [distribution, setDistribution] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState(null);

  const token = localStorage.getItem("token") || "mysecrettoken";

  useEffect(() => {
    if (!token) return;

    const fetchData = async () => {
      try {
        const urls = [
          { key: "stats", url: "http://127.0.0.1:5000/api/dashboard/stats" },
          { key: "trends", url: "http://127.0.0.1:5000/api/dashboard/trends" },
          { key: "distribution", url: "http://127.0.0.1:5000/api/dashboard/distribution" },
          { key: "alerts", url: "http://127.0.0.1:5000/api/dashboard/recent-alerts" }
        ];

        for (let u of urls) {
          const res = await fetch(u.url, { headers: { Authorization: `Bearer ${token}` } });
          if (!res.ok) throw new Error(`Failed to fetch ${u.key}`);
          const data = await res.json();
          if (u.key === "stats") setStats(data);
          if (u.key === "trends") setTrends(data);
          if (u.key === "distribution") setDistribution(data);
          if (u.key === "alerts") setAlerts(data);
        }

      } catch (err) {
        setError(err.message);
      }
    };

    fetchData();
  }, [token]);

  if (!token) return <p>Please login to see the dashboard</p>;
  if (error) return <p>Error: {error}</p>;
  if (!stats) return <p>Loading dashboard...</p>;

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="host-content">
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
          <h1>Dashboard</h1>
        </div>

        <p className="subtitle">
          Real-time intrusion detection and prevention overview
        </p>
       <div className="main-content">
        <div className="stats-grid">
          <StatesCard title="Total Threats Detected" value={stats.total_threats} color="green" />
          <StatesCard title="Blocked Attacks" value={stats.blocked_attacks} color="red" />
          <StatesCard title="Active Hosts" value={stats.active_hosts} color="blue" />
          <StatesCard title="AI Confidence" value={stats.ai_confidence + "%"} color="purple" />
        </div>
        <div className="charts">
          <AttackTrends data={trends} />
          <AttackDistribution data={distribution} />
        </div>
        <RecentAlert data={alerts} />
      </div>
      </div>
      
      
     
    </div>
  );
}
