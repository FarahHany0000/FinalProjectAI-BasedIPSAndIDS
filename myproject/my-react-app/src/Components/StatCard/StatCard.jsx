import React from 'react';
import '../Scanner/scanner.css'; 

export default function StatesCard({ label, count, color }) {
  return (
    <div className={`stat-card ${color}`}>
      <h3>{count}</h3>
      <p>{label}</p>
    </div>
  );
}