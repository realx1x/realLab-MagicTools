import { useEffect, useRef, type ComponentType } from 'react';
import { HashRouter, Navigate, NavLink, Route, Routes, useLocation } from 'react-router-dom';
import {
  Activity,
  CircleOff,
  FolderCog,
  History,
  LoaderCircle,
  Play,
  Radio,
  RefreshCw,
  Settings,
  ShieldAlert,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react';

import { Button, Menu, Tooltip } from '@dpm/ui';

import { HistoryPage } from '../features/history/HistoryPage';
import { LaunchProfilesPage } from '../features/launch-profiles/LaunchProfilesPage';
import { ProcessesPage } from '../features/processes/ProcessesPage';
import { ProjectsRulesPage } from '../features/projects-rules/ProjectsRulesPage';
import { SettingsPage } from '../features/settings/SettingsPage';
import { THEME_OPTIONS } from '../features/settings/themeOptions';
import type { SupervisorConnectionState } from '../lib/supervisor';
import { DesktopLifecycleController } from './DesktopLifecycleController';
import { SupervisorProvider, useSupervisorSnapshot } from './SupervisorProvider';
import { ThemeProvider, useTheme } from './ThemeProvider';

interface NavigationItem {
  icon: LucideIcon;
  label: string;
  path: string;
}

interface ConnectionPresentation {
  Icon: ComponentType<{
    'aria-hidden': true;
    className?: string;
    size: number;
    strokeWidth: number;
  }>;
  label: string;
  tone: 'neutral' | 'busy' | 'connected' | 'warning';
}

const navigation: readonly NavigationItem[] = [
  { icon: Activity, label: 'Processes', path: '/processes' },
  { icon: Play, label: 'Launch profiles', path: '/launch-profiles' },
  { icon: FolderCog, label: 'Projects & rules', path: '/projects-rules' },
  { icon: History, label: 'History', path: '/history' },
  { icon: Settings, label: 'Settings', path: '/settings' },
];

export function App() {
  return (
    <ThemeProvider>
      <SupervisorProvider>
        <HashRouter>
          <DesktopLifecycleController>
            <AppShell />
          </DesktopLifecycleController>
        </HashRouter>
      </SupervisorProvider>
    </ThemeProvider>
  );
}

function AppShell() {
  const location = useLocation();
  const snapshot = useSupervisorSnapshot();
  const connection = presentConnection(snapshot.connectionState);
  const activeNavigation = navigation.find((item) => item.path === location.pathname);
  const focusedRoute = useRef<string | null>(null);

  useEffect(() => {
    document.title = activeNavigation
      ? `${activeNavigation.label} | Dev Process Manager`
      : 'Dev Process Manager';
  }, [activeNavigation]);

  useEffect(() => {
    if (!activeNavigation) {
      return;
    }
    if (focusedRoute.current === null) {
      focusedRoute.current = location.pathname;
      return;
    }
    if (focusedRoute.current === location.pathname) {
      return;
    }
    focusedRoute.current = location.pathname;
    const frame = globalThis.requestAnimationFrame(() => {
      document.getElementById('main-content')?.focus({ preventScroll: true });
    });
    return () => globalThis.cancelAnimationFrame(frame);
  }, [activeNavigation, location.pathname]);

  return (
    <div className="app-shell">
      <span aria-atomic="true" aria-live="polite" className="visually-hidden">
        {activeNavigation ? `${activeNavigation.label} page` : ''}
      </span>
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById('main-content')?.focus({ preventScroll: true });
        }}
      >
        Skip to content
      </a>
      <header className="topbar">
        <div className="topbar-identity">
          <strong className="product-name">Dev Process Manager</strong>
          {activeNavigation ? (
            <>
              <span aria-hidden="true" className="topbar-divider" />
              <span className="route-name">{activeNavigation.label}</span>
            </>
          ) : null}
        </div>
        <div className="topbar-actions">
          <span
            aria-atomic="true"
            aria-live="polite"
            className="connection-status"
            data-tone={connection.tone}
            role="status"
          >
            <connection.Icon
              aria-hidden={true}
              className={
                connection.tone === 'busy' ? 'status-icon status-icon--busy' : 'status-icon'
              }
              size={14}
              strokeWidth={1.8}
            />
            <span className="connection-label">{connection.label}</span>
          </span>
          <ThemeMenu />
        </div>
      </header>
      <div className="workspace">
        <nav className="sidebar" aria-label="Primary navigation">
          {navigation.map(({ icon: Icon, label, path }) => (
            <Tooltip content={label} key={path}>
              <NavLink
                className={({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')}
                to={path}
              >
                <Icon aria-hidden="true" size={16} strokeWidth={1.8} />
                <span>{label}</span>
              </NavLink>
            </Tooltip>
          ))}
        </nav>
        <div className="route-frame">
          <Routes>
            <Route element={<Navigate replace to="/processes" />} path="/" />
            <Route element={<ProcessesPage />} path="/processes" />
            <Route element={<LaunchProfilesPage />} path="/launch-profiles" />
            <Route element={<ProjectsRulesPage />} path="/projects-rules" />
            <Route element={<HistoryPage />} path="/history" />
            <Route element={<SettingsPage />} path="/settings" />
            <Route element={<Navigate replace to="/processes" />} path="*" />
          </Routes>
        </div>
      </div>
    </div>
  );
}

function ThemeMenu() {
  const { preference, setPreference } = useTheme();
  const current = THEME_OPTIONS.find((option) => option.value === preference);
  if (!current) {
    throw new Error('Unknown theme preference');
  }
  const CurrentIcon = current.icon;
  return (
    <Menu
      items={THEME_OPTIONS.map(({ icon: Icon, label, value }) => ({
        icon: <Icon aria-hidden="true" size={15} strokeWidth={1.8} />,
        id: value,
        label,
        onSelect: () => setPreference(value),
      }))}
      label="Theme"
      trigger={
        <Button
          className="theme-trigger"
          leadingIcon={<CurrentIcon aria-hidden="true" size={15} strokeWidth={1.8} />}
          size="compact"
          title="Theme"
          variant="ghost"
        >
          <span className="theme-mode-label">{current.label}</span>
        </Button>
      }
    />
  );
}

function presentConnection(state: SupervisorConnectionState): ConnectionPresentation {
  switch (state.kind) {
    case 'connected':
      return { Icon: Radio, label: 'Supervisor connected', tone: 'connected' };
    case 'connecting':
      return { Icon: LoaderCircle, label: 'Connecting to Supervisor', tone: 'busy' };
    case 'authenticating':
      return { Icon: LoaderCircle, label: 'Authenticating', tone: 'busy' };
    case 'backoff':
      return { Icon: RefreshCw, label: 'Reconnecting', tone: 'busy' };
    case 'incompatibleVersion':
      return { Icon: TriangleAlert, label: 'Supervisor update required', tone: 'warning' };
    case 'accessDenied':
      return { Icon: ShieldAlert, label: 'Supervisor access denied', tone: 'warning' };
    case 'shuttingDown':
      return { Icon: CircleOff, label: 'Supervisor shutting down', tone: 'neutral' };
    case 'disconnected':
      return { Icon: CircleOff, label: 'Supervisor offline', tone: 'neutral' };
  }
}
