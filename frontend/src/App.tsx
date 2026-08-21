import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AppLayout from './layouts/AppLayout';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import LiveScan from './pages/LiveScan';
import Findings from './pages/Findings';
import Reports from './pages/Reports';
import PayloadLibrary from './pages/PayloadLibrary';
import DatasetTools from './pages/DatasetTools';

export default function App() {
  return (
    <BrowserRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan/new" element={<NewScan />} />
          <Route path="/scan/live" element={<LiveScan />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/payloads" element={<PayloadLibrary />} />
          <Route path="/datasets" element={<DatasetTools />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </BrowserRouter>
  );
}
