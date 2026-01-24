import React from 'react';
import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";

ChartJS.register(ArcElement, Tooltip, Legend);

export default function AttackDistribution({ data }) {
  if (!data || data.length === 0) return <p>Loading chart...</p>;

  const chartData = {
    labels: data.map(d => d.attack_type || "Unknown"),
    datasets: [
      {
        label: "Threats",
        data: data.map(d => d.count ?? 0),
        backgroundColor: ["#ff4d4f", "#7f5af0", "#ff7a45", "#ffa940", "#40a9ff"],
        hoverOffset: 10,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: { position: "right", labels: { font: { size: 12 } } },
      tooltip: { enabled: true },
    },
  };

  return (
    <div className="chart attack-distribution">
      <h3>Attack Type Distribution</h3>
      <Pie data={chartData} options={options} />
    </div>
  );
}
