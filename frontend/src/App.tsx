
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import DashboardLayout from './layouts/DashboardLayout';
import Overview from './pages/Overview';
import IncidentList from './pages/IncidentList';
import IncidentDetail from './pages/IncidentDetail';
import Alerts from './pages/Alerts';
import Endpoints from './pages/Endpoints';
import AttackStories from './pages/AttackStories';
import MitreAttack from './pages/MitreAttack';
import Settings from './pages/Settings';
import AIAnalyst from './pages/AIAnalyst';



function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<DashboardLayout />}>
          <Route index element={<Overview />} />
          <Route path="incidents" element={<IncidentList />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="stories" element={<AttackStories />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="endpoints" element={<Endpoints />} />
          <Route path="mitre" element={<MitreAttack />} />
          <Route path="ai-analyst" element={<AIAnalyst />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
