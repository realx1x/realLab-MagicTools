import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useState,
  useSyncExternalStore,
} from 'react';

import {
  createSupervisorSnapshotStore,
  type SupervisorSnapshotState,
  type SupervisorSnapshotStore,
} from '../lib/supervisor';

const EMPTY_SNAPSHOT: SupervisorSnapshotState = Object.freeze({
  connectionState: Object.freeze({ kind: 'disconnected', reason: null }),
  generation: null,
  revision: 0,
  synchronized: false,
  processes: Object.freeze([]),
  portBindings: Object.freeze([]),
});

const SupervisorStoreContext = createContext<SupervisorSnapshotStore | null>(null);

let sharedStore: SupervisorSnapshotStore | null = null;
let sharedStorePromise: Promise<SupervisorSnapshotStore> | null = null;
let sharedConsumers = 0;

export function SupervisorProvider({ children }: { children: ReactNode }) {
  const [store, setStore] = useState<SupervisorSnapshotStore | null>(sharedStore);

  useEffect(() => {
    let cancelled = false;
    const pending = acquireSupervisorStore();
    void pending.then(
      (available) => {
        if (!cancelled) {
          setStore(available);
        }
      },
      () => {
        if (!cancelled) {
          setStore(null);
        }
      },
    );
    return () => {
      cancelled = true;
      releaseSupervisorStore();
    };
  }, []);

  return (
    <SupervisorStoreContext.Provider value={store}>{children}</SupervisorStoreContext.Provider>
  );
}

export function useSupervisorSnapshot(): SupervisorSnapshotState {
  const store = useContext(SupervisorStoreContext);
  const subscribe = useCallback(
    (listener: () => void) => (store ? store.subscribe(listener) : () => undefined),
    [store],
  );
  const getSnapshot = useCallback(() => store?.getSnapshot() ?? EMPTY_SNAPSHOT, [store]);
  return useSyncExternalStore(subscribe, getSnapshot, getEmptySnapshot);
}

function getEmptySnapshot() {
  return EMPTY_SNAPSHOT;
}

function acquireSupervisorStore(): Promise<SupervisorSnapshotStore> {
  sharedConsumers += 1;
  if (sharedStorePromise) {
    return sharedStorePromise;
  }

  const pending = createSupervisorSnapshotStore();
  sharedStorePromise = pending;
  void pending.then(
    (store) => {
      if (sharedStorePromise !== pending) {
        store.dispose();
        return;
      }
      sharedStore = store;
      if (sharedConsumers === 0) {
        disposeSharedStore(pending, store);
      }
    },
    () => {
      if (sharedStorePromise === pending) {
        sharedStorePromise = null;
        sharedStore = null;
      }
    },
  );
  return pending;
}

function releaseSupervisorStore() {
  sharedConsumers = Math.max(0, sharedConsumers - 1);
  if (sharedConsumers !== 0 || !sharedStorePromise) {
    return;
  }
  const pending = sharedStorePromise;
  void pending.then(
    (store) => {
      if (sharedConsumers === 0 && sharedStorePromise === pending) {
        disposeSharedStore(pending, store);
      }
    },
    () => undefined,
  );
}

function disposeSharedStore(
  pending: Promise<SupervisorSnapshotStore>,
  store: SupervisorSnapshotStore,
) {
  if (sharedStorePromise !== pending) {
    return;
  }
  store.dispose();
  sharedStore = null;
  sharedStorePromise = null;
}
