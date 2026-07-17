import { Monitor, Moon, Sun, type LucideIcon } from 'lucide-react';

import type { ThemePreference } from '../../app/ThemeProvider';

export interface ThemeOption {
  icon: LucideIcon;
  label: string;
  value: ThemePreference;
}

export const THEME_OPTIONS: readonly ThemeOption[] = [
  { icon: Monitor, label: 'System', value: 'system' },
  { icon: Sun, label: 'Light', value: 'light' },
  { icon: Moon, label: 'Dark', value: 'dark' },
];
