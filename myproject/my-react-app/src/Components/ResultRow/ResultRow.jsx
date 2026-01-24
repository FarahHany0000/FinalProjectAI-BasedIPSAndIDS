// ResultRow.js
import React from 'react';
import './result.css';

export default function ResultRow({ name, status, confidence, color }) {
  return (
    <div className={`result-row result-${color}`}>
      <span className="file-name">{name}</span>
      <span className="file-status">{status}</span>
      <span className="file-confidence">{confidence}</span>
    </div>
  );
}
