import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export type DesktopRoute = 'launch-profiles' | 'settings';
export type ExitRequestSource = 'system' | 'tray';

export interface DesktopNavigationRequest {
  nonce: string;
  route: DesktopRoute;
}

export interface DesktopExitRequest {
  nonce: string;
  source: ExitRequestSource;
}

export interface DesktopLifecycleSnapshot {
  pendingExit: DesktopExitRequest | null;
  pendingNavigation: DesktopNavigationRequest | null;
}

export interface DesktopLifecycleConnection {
  dispose(): void;
  snapshot: DesktopLifecycleSnapshot;
}

interface DesktopLifecycleHandlers {
  onExitRequest(request: DesktopExitRequest): void;
  onNavigationRequest(request: DesktopNavigationRequest): void;
}

const NAVIGATE_EVENT = 'desktop://navigate-requested';
const EXIT_EVENT = 'desktop://exit-requested';
const NONCE = /^[0-9a-f]{64}$/;

export async function connectDesktopLifecycle(
  handlers: DesktopLifecycleHandlers,
): Promise<DesktopLifecycleConnection> {
  const unlistenNavigation = await listen<unknown>(NAVIGATE_EVENT, (event) => {
    if (isDesktopNavigationRequest(event.payload)) {
      handlers.onNavigationRequest(event.payload);
    }
  });
  let unlistenExit: UnlistenFn | null = null;
  try {
    unlistenExit = await listen<unknown>(EXIT_EVENT, (event) => {
      if (isDesktopExitRequest(event.payload)) {
        handlers.onExitRequest(event.payload);
      }
    });
    const value = await invoke<unknown>('desktop_lifecycle_snapshot');
    if (!isDesktopLifecycleSnapshot(value)) {
      throw new TypeError('invalid desktop lifecycle snapshot');
    }
    return {
      dispose() {
        unlistenNavigation();
        unlistenExit?.();
      },
      snapshot: value,
    };
  } catch (error) {
    unlistenNavigation();
    unlistenExit?.();
    throw error;
  }
}

export function acknowledgeDesktopNavigation(nonce: string): Promise<boolean> {
  requireNonce(nonce);
  return invoke<boolean>('desktop_acknowledge_navigation', { request: { nonce } });
}

export function completeDesktopExit(nonce: string): Promise<boolean> {
  requireNonce(nonce);
  return invoke<boolean>('desktop_complete_exit', { request: { nonce } });
}

export function cancelDesktopExit(nonce: string): Promise<boolean> {
  requireNonce(nonce);
  return invoke<boolean>('desktop_cancel_exit', { request: { nonce } });
}

export function isDesktopNavigationRequest(value: unknown): value is DesktopNavigationRequest {
  return (
    hasExactKeys(value, ['nonce', 'route']) &&
    isNonce(value.nonce) &&
    (value.route === 'launch-profiles' || value.route === 'settings')
  );
}

export function isDesktopExitRequest(value: unknown): value is DesktopExitRequest {
  return (
    hasExactKeys(value, ['nonce', 'source']) &&
    isNonce(value.nonce) &&
    (value.source === 'system' || value.source === 'tray')
  );
}

function isDesktopLifecycleSnapshot(value: unknown): value is DesktopLifecycleSnapshot {
  return (
    hasExactKeys(value, ['pendingExit', 'pendingNavigation']) &&
    (value.pendingExit === null || isDesktopExitRequest(value.pendingExit)) &&
    (value.pendingNavigation === null || isDesktopNavigationRequest(value.pendingNavigation))
  );
}

function requireNonce(value: string) {
  if (!isNonce(value)) {
    throw new TypeError('invalid desktop lifecycle nonce');
  }
}

function isNonce(value: unknown): value is string {
  return typeof value === 'string' && NONCE.test(value);
}

function hasExactKeys<Value extends object, Key extends string>(
  value: unknown,
  keys: readonly Key[],
): value is Value & Record<Key, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => actual.includes(key));
}
