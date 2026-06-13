import Sidebar from "./Sidebar.jsx";
import Topbar from "./Topbar.jsx";

/** Fixed sidebar + sticky topbar + scrolling content region. */
export default function AppShell({ children }) {
  return (
    <div className="min-h-full">
      <Sidebar />
      <div className="pl-64">
        <Topbar />
        <main className="px-6 py-6 max-w-[1400px] mx-auto">{children}</main>
      </div>
    </div>
  );
}
