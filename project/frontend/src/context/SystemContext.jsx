import React, { createContext, useState } from "react";

export const SystemContext = createContext();

export const SystemProvider = ({ children }) => {
  const [toastMessage, setToastMessage] = useState("");

  return (
    <SystemContext.Provider value={{ toastMessage, setToastMessage }}>
      {children}
      {toastMessage && (
        <div style={{
          position: "fixed", top: 0, left: 0, width: "100%",
          padding: "12px 0", textAlign: "center",
          backgroundColor: "#ef4444", color: "#fff",
          fontWeight: "bold", zIndex: 9999,
          boxShadow: "0px 2px 10px rgba(0,0,0,0.3)",
          animation: "fadeIn 0.5s ease forwards"
        }}>
          {toastMessage}
        </div>
      )}
    </SystemContext.Provider>
  );
};
