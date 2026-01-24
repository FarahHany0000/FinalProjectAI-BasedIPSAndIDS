import React from 'react';
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

export default function AttackTrends({ data }) {
  if (!data || data.length === 0) return <p>Loading chart...</p>;

  const chartData = {
    labels: data.map(d => d.time || "N/A"),
    datasets: [
      {
        label: "Attacks Detected",
        data: data.map(d => d.detected ?? 0),
        borderColor: "red",
        backgroundColor: "rgba(255,0,0,0.2)",
        fill: false,
        tension: 0.2,
      },
      {
        label: "Attacks Blocked",
        data: data.map(d => d.blocked ?? 0),
        borderColor: "green",
        backgroundColor: "rgba(0,255,0,0.2)",
        fill: false,
        tension: 0.2,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: { position: "top", labels: { font: { size: 12 } } },
      tooltip: { mode: "index", intersect: false },
    },
    scales: {
      x: { title: { display: true, text: "Time (24h)" }, ticks: { font: { size: 11 } } },
      y: { title: { display: true, text: "Number of Attacks" }, beginAtZero: true, ticks: { font: { size: 11 } } },
    },
  };

  return (
    <div className="chart attack-trends">
      <h3>Attack Trends (24h)</h3>
      <Line data={chartData} options={options} />
    </div>
  );
}
