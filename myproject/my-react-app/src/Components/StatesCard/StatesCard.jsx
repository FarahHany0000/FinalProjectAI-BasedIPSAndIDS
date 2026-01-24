import React from 'react';

export default function StatesCard({ title, value, color }) {
  return (
    <div className={`stats-card ${color}`}>
      <p>{title}</p>
      <h2>{value !== undefined && value !== null ? value : "Loading..."}</h2>
    </div>
  );
}
