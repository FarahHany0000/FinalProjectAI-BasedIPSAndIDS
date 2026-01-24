import React from 'react';
// import "./RecentAlert.css";

export default function RecentAlert({ data }) {
  if (!data || data.length === 0) return <p>Loading alerts...</p>;

  return (
    <div className="recent-alerts">
      <h3>Recent Alerts</h3>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Time</th>
            <th>Type</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Port</th>
            <th>Status</th>
            <th>Confidence</th>
            <th>Protocol</th>
          </tr>
        </thead>
        <tbody>
          {data.map(alert => (
            <tr key={alert.id}>
              <td>{alert.id || "N/A"}</td>
              <td>{alert.timestamp || "N/A"}</td>
              <td>{alert.attack_type || "N/A"}</td>
              <td>{alert.source_ip || "N/A"}</td>
              <td>{alert.destination_ip || "N/A"}</td>
              <td>{alert.port ?? "N/A"}</td>
              <td>{alert.status || "N/A"}</td>
              <td>{alert.confidence ?? "0"}%</td>
              <td>{alert.protocol || "N/A"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
