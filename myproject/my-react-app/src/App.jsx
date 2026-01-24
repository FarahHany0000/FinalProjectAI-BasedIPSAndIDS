import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import Login_page from './Components/Login/Login_page'
import { Route, Routes } from 'react-router-dom'
import Dashboard from './Components/Dashboard/Dashboard'
import NotFound from './Components/NotFound/NotFound'
import ProtectedRoute from './Components/ProtectedRoute'
import Alertpage from './Components/AlertPage/Alertpage'
import Host from './Components/Host/Host'
import Scanner from './Components/Scanner/Scanner'
import Update from './Components/UpdatePage/Update'

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
    <Routes>
      <Route path='/' element={<Login_page/>}></Route>
       <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Dashboard />
         </ProtectedRoute>
        }
      />
      <Route path='*' element={<NotFound/>}></Route>
      <Route path='/alert' element={<Alertpage/>}></Route>
      <Route path='/scanner' element={<Scanner/>}></Route>
      <Route path='/updatepage' element={<Update/>}></Route>
      <Route path='/host' element={<Host/>}></Route>
    

    
    </Routes>
    
    </>
  )
}

export default App
