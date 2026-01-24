// Update.js
import React, { useState } from 'react';
import Sidebar from '../Sidebar/Sidebar';
import "../Host/host.css";
import './update.css'; 

export default function Update() {
  // Example stats (replace with your data source)
  const [stats, setStats] = useState({
    total: 10,
    online: 7,
    warnings: 2,
    threats: 1,
  });

  const handleFiles = (e) => {
    const files = e.target.files;
    console.log("Selected files:", files);
    // Here you can send files to your backend or process them
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
          <h1>Update Model</h1>
        </div>

        <p className="subtitle">
          Real-time intrusion detection and prevention overview
        </p>

        {/* ===== TOP STATS ===== */}
    
        <div className="upload-box">
          <p>Drag and drop files here, or click to browse</p>
          {/* File input styled like button */}
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
      </div>
    </div>
  );
}
