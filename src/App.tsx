import { useDashboardStore } from './stores/dashboardStore';
import { DashboardView } from './components/dashboard/DashboardView';
import { ScanView } from './components/scan/ScanView';
import { TabNavigation } from './components/dashboard/TabNavigation';

export function App() {
  const { activeTab, setActiveTab } = useDashboardStore();

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100">
      <header className="border-b border-gray-800 px-6 py-4">
        <nav className="flex items-center justify-between">
          <h1 className="text-2xl font-bold text-blue-500">NetSentinel</h1>
        </nav>
      </header>
      <main className="p-6">
        <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />
        {activeTab === 'dashboard' && <DashboardView />}
        {activeTab === 'scan' && <ScanView />}
        {activeTab === 'settings' && <SettingsView />}
      </main>
    </div>
  );
}

// Placeholder for Settings view
const SettingsView: React.FC = () => (
  <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
    <h2 className="text-xl font-semibold text-gray-200 mb-4">Settings</h2>
    <p className="text-gray-400">Settings panel coming soon...</p>
  </div>
);