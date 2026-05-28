import { useEffect } from 'react';
import { useDashboardStore } from './stores/dashboardStore';
import { useCapabilitiesStore } from './stores/capabilitiesStore';
import { DashboardView } from './components/dashboard/DashboardView';
import { ScanView } from './components/scan/ScanView';
import { TabNavigation } from './components/dashboard/TabNavigation';
import { SettingsView } from './components/settings/SettingsView';
import { PrivilegeBanner } from './components/common/PrivilegeBanner';

export function App() {
  const activeTab = useDashboardStore((s) => s.activeTab);
  const setActiveTab = useDashboardStore((s) => s.setActiveTab);
  const fetchCapabilities = useCapabilitiesStore((s) => s.fetchCapabilities);

  // Fetch platform capabilities once on app mount
  useEffect(() => {
    fetchCapabilities();
  }, [fetchCapabilities]);

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      <header className="border-b border-gray-800 px-6 py-4">
        <nav className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img
              src="/netSentinel-logo.png"
              alt="NetSentinel logo"
              className="w-10 h-10 rounded-lg"
            />
            <h1 className="text-2xl font-bold text-blue-500">NetSentinel</h1>
          </div>
        </nav>
      </header>
      <PrivilegeBanner />
      <main className="p-6">
        <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />
        {activeTab === 'dashboard' && <DashboardView />}
        {activeTab === 'scan' && <ScanView />}
        {activeTab === 'settings' && <SettingsView />}
      </main>
    </div>
  );
}