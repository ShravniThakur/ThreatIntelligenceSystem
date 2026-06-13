import { Routes, Route, useLocation } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import AppShell from "./components/layout/AppShell.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Analyze from "./pages/Analyze.jsx";
import Result from "./pages/Result.jsx";
import ResultSection from "./pages/ResultSection.jsx";
import History from "./pages/History.jsx";

export default function App() {
  const location = useLocation();
  return (
    <AppShell>
      <AnimatePresence mode="wait">
        <Routes location={location} key={location.pathname}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analyze" element={<Analyze />} />
          <Route path="/result/:hash" element={<Result />} />
          <Route path="/result/:hash/section/:key" element={<ResultSection />} />
          <Route path="/history" element={<History />} />
          <Route path="*" element={<Dashboard />} />
        </Routes>
      </AnimatePresence>
    </AppShell>
  );
}
