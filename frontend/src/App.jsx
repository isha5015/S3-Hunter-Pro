import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import PayloadManager from './pages/PayloadManager';
import BucketExplorer from './pages/BucketExplorer';
import SessionHistory from './pages/SessionHistory';
import Reports from './pages/Reports';
import AiAssistant from './pages/AiAssistant';

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-cyber-bg">
        <Navbar />
        <main className="flex-1 ml-64 p-6 overflow-auto">
          <Routes>
            <Route path="/"               element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard"      element={<Dashboard />} />
            <Route path="/payloads"       element={<PayloadManager />} />
            <Route path="/explorer"       element={<BucketExplorer />} />
            <Route path="/history"        element={<SessionHistory />} />
            <Route path="/reports"        element={<Reports />} />
            <Route path="/ai"             element={<AiAssistant />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
