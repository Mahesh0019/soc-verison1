import { Route, Routes } from "react-router-dom";

import { Layout } from "./components/Layout";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AdminPage } from "./pages/AdminPage";
import { AlertsPage } from "./pages/AlertsPage";
import { DetectionLabPage } from "./pages/DetectionLabPage";
import { EventsPage } from "./pages/EventsPage";
import { LoginPage } from "./pages/LoginPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ResearchBenchmarkPage } from "./pages/ResearchBenchmarkPage";
import { RulesPage } from "./pages/RulesPage";
import { ThreatHuntingPage } from "./pages/ThreatHuntingPage";
import { ThreatIntelPage } from "./pages/ThreatIntelPage";
import { UploadLogsPage } from "./pages/UploadLogsPage";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route index element={<OverviewPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="threat-hunting" element={<ThreatHuntingPage />} />
          <Route path="research" element={<ResearchBenchmarkPage />} />
          <Route path="detection-lab" element={<DetectionLabPage />} />
          <Route path="rules" element={<RulesPage />} />
          <Route path="upload" element={<UploadLogsPage />} />
          <Route path="threat-intel" element={<ThreatIntelPage />} />
          <Route element={<ProtectedRoute roles={["admin"]} />}>
            <Route path="admin" element={<AdminPage />} />
          </Route>
        </Route>
      </Route>
    </Routes>
  );
}

