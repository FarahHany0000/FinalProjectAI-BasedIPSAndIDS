// Scanner.js
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Sidebar from '../Sidebar/Sidebar';
import './scanner.css';
import StatCard from '../StatCard/StatCard';
import '../UpdatePage/update.css';
import ResultRow from '../ResultRow/ResultRow';

export default function Scanner() {
  const navigate = useNavigate();

  // Example stats state
  const [stats, setStats] = useState({
    total: 3,
    online: 1,
    warnings: 1,
    threats: 1
  });

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    if (!token) {
      navigate('/scanner'); 
    }
  }, [navigate]);

  
  const handleFiles = (e) => {
    const files = e.target.files;
    console.log("Selected files:", files);
    
  };

  return (
    <div className="dashboard">
      <Sidebar />

      <div className="scanner-content">
        {/* Header with icon */}
        <div className="scanner-header">
          <div className="icon-container">
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
          <h1>Scanner</h1>
        </div>

        <p className="scanner-description">
          Real-time intrusion detection and prevention overview
        </p>

        <main>
          {/* Stats Cards */}
          <div className="host-stats">
            <div className="stat-card">Total Scanned <span>{stats.total}</span></div>
            <div className="stat-card success">Clean Files <span>{stats.online}</span></div>
            <div className="stat-card warning">Threats Detected <span>{stats.warnings}</span></div>
            <div className="stat-card danger"> Suspicious <span>{stats.threats}</span></div>
          </div>

          {/* File Upload Box */}
          <div className="upload-box">
            <p>Drag and drop files here, or click to browse</p>
            <label className="custom-file-btn">
              Select Files
              <input 
                type="file" 
                multiple 
                onChange={handleFiles} 
                style={{ display: 'none' }} 
              />
            </label>
          </div>

          {/* Scan Results */}
          <h2>Scan Results</h2>
          <div className="results-list">
            <ResultRow name="financial_report.pdf" status="CLEAN" confidence="99.2%" color="green" />
            <ResultRow name="installer.exe" status="THREAT" confidence="97.8%" color="red" />
            <ResultRow name="document.pdf" status="SUSPICIOUS" confidence="85.3%" color="yellow" />
          </div>
        </main>
      </div>
    </div>
  );
}
