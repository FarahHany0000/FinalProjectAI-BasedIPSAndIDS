import React, { createContext, useState, useEffect } from "react";

export const SystemContext = createContext();

export const SystemProvider = ({ children }) => {
  const [hosts, setHosts] = useState([
    { name: "PC-01", ip: "192.168.1.2", os: "Windows 10 Pro", status: "Online", cpu: 28, memory: 45, disk: 60, network: 10, threats: 0 },
    { name: "PC-02", ip: "192.168.1.3", os: "Windows 11", status: "Online", cpu: 85, memory: 90, disk: 70, network: 80, threats: 3 },
    { name: "PC-03", ip: "192.168.1.4", os: "Ubuntu 22.04", status: "Warning", cpu: 95, memory: 80, disk: 50, network: 40, threats: 1 },
    { name: "PC-04", ip: "192.168.1.5", os: "Windows 7", status: "Offline", cpu: 0, memory: 0, disk: 0, network: 0, threats: 2 },
  ]);

  const [events, setEvents] = useState([]);
  const [toastMessage, setToastMessage] = useState("");

  const generateAction = (severity) => {
    switch (severity) {
      case "Critical": return "Host Isolated";
      case "High": return "IP Blacklisted";
      case "Medium": return "Traffic Dropped";
      case "Low": return "Firewall Rule Added";
      default: return "Connection Reset";
    }
  };

  const scanNetwork = () => {
    const updatedHosts = hosts.map(h => ({
      ...h,
      status: Math.random() > 0.25 ? "Online" : "Offline",
      cpu: Math.floor(Math.random() * 100),
      memory: Math.floor(Math.random() * 100),
      disk: Math.floor(Math.random() * 100),
      network: Math.floor(Math.random() * 100),
      threats: Math.random() > 0.7 ? Math.floor(Math.random() * 5) : 0
    }));
    setHosts(updatedHosts);

    const attackTypes = ["Malware Communication", "DDoS Traffic Detected", "Phishing Domain Access", "Brute Force Login Attempt", "SQL Injection Attempt", "Botnet Command Activity", "Port Scanning Activity"];
    const severities = ["Low", "Medium", "High", "Critical"];
    const randomHost = updatedHosts[Math.floor(Math.random() * updatedHosts.length)];

    const newEvent = {
      id: `ALT-${Math.floor(Math.random() * 1000)}`,
      date: new Date().toLocaleString(),
      type: attackTypes[Math.floor(Math.random() * attackTypes.length)],
      host: randomHost.ip,
      severity: severities[Math.floor(Math.random() * severities.length)],
      action: generateAction(severities[Math.floor(Math.random() * severities.length)]),
    };

    setEvents(prev => [newEvent, ...prev]);

    
    setToastMessage("Network Scan Completed Successfully!");
    setTimeout(() => setToastMessage(""),1000000);
  };

  useEffect(() => {
    const interval = setInterval(scanNetwork, 10000000);
    return () => clearInterval(interval);
  }, [hosts]);

  return (
    <SystemContext.Provider value={{ hosts, setHosts, events, setEvents, scanNetwork, toastMessage }}>
      {children}

   
      {toastMessage && (
        <div style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "100%",
          padding: "15px 0",
          textAlign: "center",
          backgroundColor: "#ef4444", 
          color: "#fff",
          fontWeight: "bold",
          zIndex: 9999,
          boxShadow: "0px 2px 10px rgba(0,0,0,0.3)"
        }}>
          {toastMessage}
        </div>
      )}
    </SystemContext.Provider>
  );
};