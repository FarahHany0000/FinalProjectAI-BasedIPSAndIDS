import React, { createContext, useState } from "react";

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

  return (
    <SystemContext.Provider value={{ hosts, setHosts, events, setEvents, toastMessage, setToastMessage }}>
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