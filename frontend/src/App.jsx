import { NavLink, Route, Routes, Navigate } from "react-router-dom";
import Incidents from "./pages/Incidents.jsx";
import IncidentDetail from "./pages/IncidentDetail.jsx";
import LiveLogs from "./pages/LiveLogs.jsx";
import Services from "./pages/Services.jsx";
import Rules from "./pages/Rules.jsx";

const links = [
  ["/incidents", "Incidents"],
  ["/logs", "Live logs"],
  ["/services", "Services"],
  ["/rules", "Rules"],
];

export default function App() {
  return (
    <div className="shell">
      <nav className="side">
        <div className="brand">Incident Copilot</div>
        {links.map(([to, label]) => (
          <NavLink key={to} to={to} className={({ isActive }) => "navlink" + (isActive ? " active" : "")}>
            {label}
          </NavLink>
        ))}
      </nav>
      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/incidents" replace />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/logs" element={<LiveLogs />} />
          <Route path="/services" element={<Services />} />
          <Route path="/rules" element={<Rules />} />
        </Routes>
      </main>
    </div>
  );
}
