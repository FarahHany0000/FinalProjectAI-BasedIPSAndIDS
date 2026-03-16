import { Routes, Route } from 'react-router-dom';
import Login_page from './Components/Login/Login_page';
import Dashboard from './Components/Dashboard/Dashboard';
import NotFound from './Components/NotFound/NotFound';
import ProtectedRoute from './Components/ProtectedRoute';
import Alertpage from './Components/AlertPage/Alertpage';
import Host from './Components/Host/Host';
import HostLogs from './Components/HostLogs/HostLogs';
import Agents from './Components/Agents/Agents';
import Network from './Components/Network/Network';
import { SystemProvider } from './context/SystemContext';

function App() {
  return (
    <SystemProvider>
      <Routes>
        <Route path='/' element={<Login_page />} />

        {/* Protected routes */}
        <Route path="/dashboardpage" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/host" element={<ProtectedRoute><Host /></ProtectedRoute>} />
        <Route path="/host/:host_name" element={<ProtectedRoute><HostLogs /></ProtectedRoute>} />
        <Route path="/alert" element={<ProtectedRoute><Alertpage /></ProtectedRoute>} />
        <Route path="/agents" element={<ProtectedRoute><Agents /></ProtectedRoute>} />
        <Route path="/network" element={<ProtectedRoute><Network /></ProtectedRoute>} />

        <Route path='*' element={<NotFound />} />
      </Routes>
    </SystemProvider>
  );
}

export default App;
