import { Routes, Route, Navigate } from 'react-router-dom';
import Login_page from './Components/Login/Login_page';
import Dashboard from './Components/Dashboard/Dashboard';
import NotFound from './Components/NotFound/NotFound';
import ProtectedRoute from './Components/ProtectedRoute';
import Devices from './Components/Devices/Devices';
import DeviceDetail from './Components/DeviceDetail/DeviceDetail';
import Network from './Components/Network/Network';
import Controls from './Components/Controls/Controls';
import { SystemProvider } from './context/SystemContext';

function App() {
  return (
    <SystemProvider>
      <Routes>
        <Route path='/' element={<Login_page />} />

        {/* Protected routes */}
        <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/devices" element={<ProtectedRoute><Devices /></ProtectedRoute>} />
        <Route path="/device/:host_name" element={<ProtectedRoute><DeviceDetail /></ProtectedRoute>} />
        <Route path="/network" element={<ProtectedRoute><Network /></ProtectedRoute>} />
        <Route path="/controls" element={<ProtectedRoute><Controls /></ProtectedRoute>} />

        {/* Backward compatibility redirects */}
        <Route path="/dashboardpage" element={<Navigate to="/dashboard" replace />} />
        <Route path="/host" element={<Navigate to="/devices" replace />} />
        <Route path="/host/:host_name" element={<Navigate to="/devices" replace />} />
        <Route path="/alert" element={<Navigate to="/dashboard" replace />} />
        <Route path="/agents" element={<Navigate to="/devices" replace />} />

        <Route path='*' element={<NotFound />} />
      </Routes>
    </SystemProvider>
  );
}

export default App;
