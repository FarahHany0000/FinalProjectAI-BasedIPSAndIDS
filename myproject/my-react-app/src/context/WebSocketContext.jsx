// src/context/WebSocketContext.jsx
import { createContext, useContext, useEffect, useRef, useState } from "react";
import { io } from "socket.io-client";

const WebSocketContext = createContext(null);

export const WebSocketProvider = ({ children }) => {
  const socketRef = useRef(null);
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (!token) return;

    socketRef.current = io("http://localhost:5000", {
      transports: ["websocket"],
      auth: { token }
    });

    socketRef.current.on("connect", () => console.log(" Socket connected"));
    socketRef.current.on("new_threat", (alert) => setAlerts(prev => [alert, ...prev]));

    return () => socketRef.current.disconnect();
  }, []);

  return (
    <WebSocketContext.Provider value={{ alerts }}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => useContext(WebSocketContext);
