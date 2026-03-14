import { Routes, Route } from 'react-router-dom';
import Login_page from './Components/Login/Login_page';
import Dashboard from './Components/Dashboard/Dashboard';
import NotFound from './Components/NotFound/NotFound';
import ProtectedRoute from './Components/ProtectedRoute';
import Alertpage from './Components/AlertPage/Alertpage';
import Host from './Components/Host/Host';
import Scanner from './Components/Scanner/Scanner';
import Update from './Components/UpdatePage/Update';
import LogsAttack from './Components/LogsAttack/logsattack';
import Attackdetail from './Components/Attackdetail/attackdetail';
import { SystemProvider } from './context/SystemContext';
import HostLogs from './Components/HostLogs';

function App() {
  return (
    <SystemProvider>
      <Routes>
        <Route path='/' element={<Login_page />} />
        
        {/* Protected routes */}
        <Route 
          path="/dashboardpage" 
          element={
            // <ProtectedRoute>
              <Dashboard />
            // </ProtectedRoute>
          } 
        />
        <Route 
          path="/host" 
          element={
            // <ProtectedRoute>
              <Host />
            // </ProtectedRoute>
          } 
        />

        {/* Alerts pages */}
        <Route path='/alert' element={<Alertpage />} />
        <Route path='/alert/logs' element={<LogsAttack />} />
         <Route path="/logs" element={<HostLogs />} />
        <Route path='/alert/attackdetail' element={<Attackdetail />} />
        <Route path="/host/:host_name" element={<HostLogs />} />

        {/* Uncomment when ready */}
        {/* <Route path='/scanner' element={<Scanner />} />
        <Route path='/updatepage' element={<Update />} /> */}

        <Route path='*' element={<NotFound />} />
      </Routes>
    </SystemProvider>
  )
}

export default App;
