// import { useState, useEffect } from "react";
// import { useNavigate } from "react-router-dom";
// import "./Login.css";

// import React from 'react'

// export default function Login_page() {
//   const navigate = useNavigate();
//   const [username, setUsername] = useState("");
//   const [password, setPassword] = useState("");
//   const [error, setError] = useState("");
//   const [loading, setLoading] = useState(false);

//   useEffect(() => {
//     const storedUser = localStorage.getItem("username");
//     if (storedUser) navigate("/dashpage");
//   }, [navigate]);

//   const handleSubmit = async (e) => {

//   e.preventDefault()

//   const res = await fetch("http://localhost:5000/api/auth/login",{

//     method:"POST",

//     headers:{
//       "Content-Type":"application/json"
//     },

//     body: JSON.stringify({

//       username,
//       password

//     })

//   })

//   const data = await res.json()

//   if(res.ok){

//     localStorage.setItem("access_token",data.access_token)

//     navigate("/dashboardpage")

//   }

// }

//   return (
//     <div className="login-container">
//       <div className="login-card">
//         <h2>AI-IDS/IPS System</h2>
//         <form onSubmit={handleSubmit}>
//           <input
//             placeholder="Username"
//             value={username}
//             onChange={(e) => setUsername(e.target.value)}
//           />
//           <input
//             type="password"
//             placeholder="Password"
//             value={password}
//             onChange={(e) => setPassword(e.target.value)}
//           />
//           {error && <p className="error">{error}</p>}
//           <button type="submit" disabled={loading}>
//             {loading ? "Signing in..." : "Sign In"}
//           </button>
//         </form>
//       </div>
//     </div>
//   );

// }
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import "./Login.css";

export default function Login_page() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (token) navigate("/dashboardpage");
  }, [navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    const res = await fetch("http://localhost:5000/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (res.ok) {
      localStorage.setItem("access_token", data.access_token);
      navigate("/dashboardpage");
    } else {
      setError(data.msg || "Login failed");
    }
    setLoading(false);
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>AI-IDS/IPS System</h2>
        <form onSubmit={handleSubmit}>
          <input placeholder="Username" value={username} onChange={(e)=>setUsername(e.target.value)}/>
          <input type="password" placeholder="Password" value={password} onChange={(e)=>setPassword(e.target.value)}/>
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
