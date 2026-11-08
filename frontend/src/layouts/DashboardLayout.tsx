import { Outlet, useLocation } from 'react-router-dom';
import Sidebar, { MobileNav } from '../components/Sidebar';

export default function DashboardLayout() {
  const { pathname } = useLocation();
  // The AI Analyst is a full-height chat surface and manages its own padding/scrolling.
  const fullBleed = pathname.startsWith('/ai-analyst');
  return (
    <div className="flex h-screen overflow-hidden bg-slate-950 font-sans text-slate-300">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <MobileNav />
        <main className={fullBleed ? 'min-h-0 flex-1 overflow-hidden' : 'min-h-0 flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8'}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
