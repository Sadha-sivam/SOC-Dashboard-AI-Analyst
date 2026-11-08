import { useCallback, useEffect, useState } from 'react';

type Preferences = {
  analysisWindow: number;
  refreshInterval: number;
  minimumSeverity: number;
  showInfoAlerts: boolean;
};

const defaults: Preferences = {
  analysisWindow: 24,
  refreshInterval: 60,
  minimumSeverity: 7,
  showInfoAlerts: false,
};

const STORAGE_KEY = 'soc-dashboard-settings';

export default function Settings() {
  const [preferences, setPreferences] = useState<Preferences>(defaults);
  const [saved, setSaved] = useState(false);
  const [checking, setChecking] = useState(false);
  const [backendStatus, setBackendStatus] = useState('Not checked');
  const [wazuhStatus, setWazuhStatus] = useState('Not checked');
  const [lastChecked, setLastChecked] = useState('');

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setPreferences({ ...defaults, ...JSON.parse(stored) });
      }
    } catch {
      console.warn('Could not load saved SOC dashboard preferences.');
    }
  }, []);

  const update = <K extends keyof Preferences>(
    key: K,
    value: Preferences[K],
  ) => {
    setPreferences((current) => ({ ...current, [key]: value }));
    setSaved(false);
  };

  const saveSettings = () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
    setSaved(true);
  };

  const resetSettings = () => {
    setPreferences(defaults);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(defaults));
    setSaved(true);
  };

  const checkConnections = useCallback(async () => {
    setChecking(true);
    setBackendStatus('Checking...');
    setWazuhStatus('Checking...');

    const baseUrl = (
      import.meta.env.VITE_BACKEND_URL || 'http://localhost:3000'
    ).replace(/\/$/, '');

    try {
      const response = await fetch(`${baseUrl}/api/agents`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      setBackendStatus('Connected');
      setWazuhStatus('API responded');

      // Verify that the alert endpoint also responds.
      const alertResponse = await fetch(`${baseUrl}/api/alerts`);
      if (!alertResponse.ok) {
        setWazuhStatus('Alert endpoint error');
      } else {
        const data = await alertResponse.json();
        setWazuhStatus(
          data.source === 'Wazuh Indexer'
            ? `Connected — ${data.count ?? 0} alerts returned`
            : 'Endpoint responded — source not confirmed',
        );
      }
    } catch {
      setBackendStatus('Unavailable');
      setWazuhStatus('Could not verify');
    } finally {
      setLastChecked(new Date().toLocaleString());
      setChecking(false);
    }
  }, []);

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="mt-1 text-sm text-gray-500">
          Configure your dashboard preferences and check service connectivity.
        </p>
      </div>

      <section className="rounded-xl border border-gray-200 p-5 dark:border-gray-700">
        <h2 className="text-lg font-semibold">Connection status</h2>
        <p className="mt-1 text-sm text-gray-500">
          Check whether the dashboard can reach its backend and retrieve alerts.
        </p>

        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div className="rounded-lg bg-gray-50 p-4 dark:bg-gray-800">
            <p className="text-sm text-gray-500">Backend API</p>
            <p className="mt-1 font-semibold">{backendStatus}</p>
          </div>
          <div className="rounded-lg bg-gray-50 p-4 dark:bg-gray-800">
            <p className="text-sm text-gray-500">Wazuh alert data</p>
            <p className="mt-1 font-semibold">{wazuhStatus}</p>
          </div>
        </div>

        <button
          type="button"
          onClick={checkConnections}
          disabled={checking}
          className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
        >
          {checking ? 'Checking...' : 'Test connections'}
        </button>

        {lastChecked && (
          <p className="mt-2 text-xs text-gray-500">
            Last checked: {lastChecked}
          </p>
        )}
        <p className="mt-3 text-xs text-gray-500">
          A successful API response confirms reachability, not the health of
          every Wazuh service.
        </p>
      </section>

      <section className="rounded-xl border border-gray-200 p-5 dark:border-gray-700">
        <h2 className="text-lg font-semibold">Analysis preferences</h2>
        <p className="mt-1 text-sm text-gray-500">
          Choose your preferred values for future dashboard integrations.
        </p>

        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <label className="block">
            <span className="text-sm font-medium">Analysis time window</span>
            <select
              value={preferences.analysisWindow}
              onChange={(e) => update('analysisWindow', Number(e.target.value))}
              className="mt-2 w-full rounded-lg border border-gray-300 bg-transparent p-2.5 dark:border-gray-600"
            >
              <option value={1}>Last 1 hour</option>
              <option value={6}>Last 6 hours</option>
              <option value={12}>Last 12 hours</option>
              <option value={24}>Last 24 hours</option>
              <option value={48}>Last 48 hours</option>
              <option value={168}>Last 7 days</option>
            </select>
          </label>

          <label className="block">
            <span className="text-sm font-medium">Preferred refresh interval</span>
            <select
              value={preferences.refreshInterval}
              onChange={(e) => update('refreshInterval', Number(e.target.value))}
              className="mt-2 w-full rounded-lg border border-gray-300 bg-transparent p-2.5 dark:border-gray-600"
            >
              <option value={15}>15 seconds</option>
              <option value={30}>30 seconds</option>
              <option value={60}>1 minute</option>
              <option value={300}>5 minutes</option>
              <option value={0}>Manual refresh</option>
            </select>
          </label>

          <label className="block">
            <span className="text-sm font-medium">Minimum severity to highlight</span>
            <select
              value={preferences.minimumSeverity}
              onChange={(e) => update('minimumSeverity', Number(e.target.value))}
              className="mt-2 w-full rounded-lg border border-gray-300 bg-transparent p-2.5 dark:border-gray-600"
            >
              <option value={4}>Low and above (level 4+)</option>
              <option value={7}>Medium and above (level 7+)</option>
              <option value={10}>High and above (level 10+)</option>
              <option value={12}>Critical only (level 12+)</option>
            </select>
          </label>

          <label className="flex items-center gap-3 rounded-lg border border-gray-200 p-3 dark:border-gray-700">
            <input
              type="checkbox"
              checked={preferences.showInfoAlerts}
              onChange={(e) => update('showInfoAlerts', e.target.checked)}
              className="h-4 w-4"
            />
            <span>
              <span className="block text-sm font-medium">Include informational alerts</span>
              <span className="block text-xs text-gray-500">
                Preference for a future global alert filter
              </span>
            </span>
          </label>
        </div>

        <div className="mt-6 flex flex-wrap gap-3">
          <button
            type="button"
            onClick={saveSettings}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white"
          >
            Save settings
          </button>
          <button
            type="button"
            onClick={resetSettings}
            className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium dark:border-gray-600"
          >
            Reset defaults
          </button>
          {saved && (
            <span className="self-center text-sm text-green-600">
              Preferences saved in this browser.
            </span>
          )}
        </div>
      </section>

      <section className="rounded-xl border border-gray-200 p-5 dark:border-gray-700">
        <h2 className="text-lg font-semibold">Security and privacy</h2>
        <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-gray-500">
          <li>Credentials and API keys are not displayed on this page.</li>
          <li>Preferences are stored in this browser, not in a server database.</li>
          <li>
            Analysis-window, severity, and refresh preferences are not yet
            applied globally to the other dashboard pages.
          </li>
        </ul>
      </section>
    </div>
  );
}
