import { io } from "socket.io-client";

const socket = io("http://127.0.0.1:5000", {
  transports: ["websocket", "polling"],
  reconnection: true,
  reconnectionDelay: 2000,
});

export default socket;
