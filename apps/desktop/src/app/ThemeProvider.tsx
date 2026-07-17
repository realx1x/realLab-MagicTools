import { isTauri } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from 'react';

export type ThemePreference = 'system' | 'light' | 'dark';

interface ThemeContextValue {
  preference: ThemePreference;
  setPreference: (preference: ThemePreference) => void;
}

const THEME_STORAGE_KEY = 'dpm.theme';
const initialPreference = readThemePreference();

applyDocumentTheme(initialPreference);

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreference] = useState<ThemePreference>(initialPreference);

  useEffect(() => {
    applyDocumentTheme(preference);
    persistThemePreference(preference);
    if (isTauri()) {
      void getCurrentWindow()
        .setTheme(preference === 'system' ? null : preference)
        .catch(() => undefined);
    }
  }, [preference]);

  const value = useMemo(() => ({ preference, setPreference }), [preference]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const value = useContext(ThemeContext);
  if (!value) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return value;
}

function readThemePreference(): ThemePreference {
  try {
    const stored = globalThis.localStorage?.getItem(THEME_STORAGE_KEY);
    if (stored === 'system' || stored === 'light' || stored === 'dark') {
      return stored;
    }
  } catch {
    // The system preference remains the fail-closed visual default.
  }
  return 'system';
}

function persistThemePreference(preference: ThemePreference) {
  try {
    globalThis.localStorage?.setItem(THEME_STORAGE_KEY, preference);
  } catch {
    // Theme application does not depend on persistence being available.
  }
}

function applyDocumentTheme(preference: ThemePreference) {
  if (typeof document === 'undefined') {
    return;
  }
  if (preference === 'system') {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = preference;
  }
}
