---
name: Frontend Standards
description: Comprehensive coding standards, patterns, and best practices for the NetSentinel frontend. This skill defines the non-negotiable rules for TypeScript strictness, Tauri IPC, React performance, accessibility, and Tailwind CSS styling.
version: 1.0.0
project: NetSentinel
context: React 19 + TypeScript + Tailwind CSS + Zustand + Tauri
---

# NetSentinel Frontend Standards

This skill defines the authoritative rules and patterns that every frontend developer, planner, and reviewer must follow when working on the NetSentinel project.

---

## 1. TypeScript Strictness

TypeScript strict mode is non-negotiable for all `.ts` and `.tsx` files.

### 1.1 Forbidden Patterns

| Pattern | Rule | Reason |
|---------|------|--------|
| `any` | **NEVER use** | Breaks type safety entirely. Use `unknown` with type narrowing. |
| `as Type` | **AVOID** | Use only when absolutely safe, with a comment explaining why. |
| `!` (non-null assertion) | **NEVER use** | Use optional chaining (`?.`) or explicit checks instead. |
| `// @ts-ignore` | **NEVER use** | Fix the underlying type error properly. |

### 1.2 Type Definitions

All IPC payloads **MUST** have explicit interfaces:

```typescript
// BAD — generic and unsafe
const result = await invoke('scan_network', { range: range as any });

// GOOD — strict interface
interface ScanRequest {
  cidr: string;
  timeout_ms: number;
}

interface ScanResponse {
  devices: Device[];
  duration_ms: number;
}

const result = await invoke<ScanResponse>('scan_network', {
  cidr: validatedCidr,
  timeout_ms: SCAN_TIMEOUT,
});
```

### 1.3 Generic Constraints

Use generics to maintain type safety across async operations:

```typescript
// GOOD — generic with constraint
async function fetchScanResult<T extends ScanResult>(
  scanId: string
): Promise<T> {
  return invoke<T>('get_scan_result', { scanId });
}
```

---

## 2. Tauri IPC Communication

All communication with the Rust backend happens through Tauri's invoke and event system.

### 2.1 Command Invocation Pattern

```typescript
// Always await with try/catch
async function startScan(cidr: string): Promise<ScanResponse> {
  try {
    return await invoke<ScanResponse>('start_scan', { cidr });
  } catch (error) {
    if (isTauriError(error)) {
      console.error(`Scan failed: ${error.message}`);
      throw new ScanError(error.message, error.code);
    }
    throw error;
  }
}
```

### 2.2 Event Listening with Cleanup

**CRITICAL:** Every `listen()` call MUST be cleaned up in the `useEffect` return function. Failure to do so causes memory leaks in the WebView.

```typescript
useEffect(() => {
  let unlisten: (() => void) | undefined;

  const setupListener = async () => {
    unlisten = await listen<DeviceFoundEvent>('device_found', (event) => {
      setDevices((prev) => [...prev, event.payload]);
    });
  };

  setupListener();

  // Cleanup function — MANDATORY
  return () => {
    if (unlisten) {
      unlisten();
      unlisten = undefined;
    }
  };
}, []);
```

### 2.3 Event Types

All event payloads must have explicit TypeScript interfaces:

```typescript
interface DeviceFoundEvent {
  ip: string;
  mac: string;
  hostname?: string;
  timestamp: number;
}

interface ScanProgressEvent {
  scanned: number;
  total: number;
  currentTarget: string;
}

interface ScanCompleteEvent {
  scanId: string;
  deviceCount: number;
  duration_ms: number;
}
```

### 2.4 Multi-Listener Handling

When a component needs multiple event listeners, track them all for cleanup:

```typescript
useEffect(() => {
  const listeners: (() => void)[] = [];

  const setup = async () => {
    const unlisten1 = await listen<DeviceFoundEvent>('device_found', handler1);
    const unlisten2 = await listen<ScanProgressEvent>('scan_progress', handler2);

    listeners.push(unlisten1, unlisten2);
  };

  setup();

  return () => {
    listeners.forEach((unlisten) => unlisten());
  };
}, []);
```

---

## 3. React Component Patterns

### 3.1 Functional Components Only

Use only functional components with hooks. Class components are not permitted.

```typescript
// CORRECT
export const NetworkGraph: React.FC<NetworkGraphProps> = ({ devices }) => {
  return (/* component */);
}

// INCORRECT — class components not allowed
export class NetworkGraph extends Component { /* ... */ }
```

### 3.2 Component Structure

Each component file should follow this order:

1. Type definitions (interfaces/types)
2. Component function
3. Helper hooks (custom hooks above component if co-located)
4. Export

```typescript
// 1. Type definitions
interface DeviceCardProps {
  device: Device;
  isSelected: boolean;
  onSelect: (id: string) => void;
}

// 2. Custom hooks (if component-specific)
const useDeviceSelection = (deviceId: string) => {
  const selectDevice = useStore((s) => s.selectDevice);
  return { isSelected: useStore((s) => s.selectedIds.includes(deviceId)), selectDevice };
};

// 3. Component
export const DeviceCard: React.FC<DeviceCardProps> = ({ device, isSelected, onSelect }) => {
  return (
    <div className={clsx('card', isSelected && 'card-selected')}>
      {/* JSX */}
    </div>
  );
};
```

### 3.3 Memoization Guidelines

Use `useMemo`, `useCallback`, and `React.memo` strategically:

| Scenario | Technique |
|----------|-----------|
| Expensive calculations (large device lists) | `useMemo` |
| Callbacks passed as props to memoized children | `useCallback` |
| Pure presentational components | `React.memo` |
| Array mapping with stable keys | Always ensure `key` is stable (device MAC preferred over array index) |

```typescript
// Memoize expensive filtered/sorted lists
const sortedDevices = useMemo(() => {
  return [...devices].sort((a, b) => a.ip.localeCompare(b.ip));
}, [devices]);

// Memoize callbacks for child components
const handleDeviceSelect = useCallback((id: string) => {
  onSelect(id);
}, [onSelect]);
```

### 3.4 List Rendering

When rendering large lists (network scans can return 200+ devices), ensure:

```typescript
// Always use stable, unique keys — MAC addresses preferred
{devices.map((device) => (
  <DeviceCard key={device.mac} device={device} />
))}

// For virtualized lists (100+ items), use react-window or similar
```

---

## 4. State Management (Zustand)

### 4.1 Store Structure

Organize Zustand stores by domain feature:

```
src/
  stores/
    scanStore.ts      # Network scanning state
    deviceStore.ts    # Discovered devices
    uiStore.ts        # UI state (modals, sidebar)
```

### 4.2 Store Patterns

```typescript
interface ScanStore {
  // State
  isScanning: boolean;
  scanProgress: number;
  devices: Device[];

  // Actions
  startScan: (cidr: string) => Promise<void>;
  stopScan: () => void;
}

export const useScanStore = create<ScanStore>((set, get) => ({
  // Initial state
  isScanning: false,
  scanProgress: 0,
  devices: [],

  // Actions
  startScan: async (cidr: string) => {
    set({ isScanning: true, scanProgress: 0 });
    try {
      const result = await invoke<ScanResponse>('start_scan', { cidr });
      set({ devices: result.devices, scanProgress: 100 });
    } finally {
      set({ isScanning: false });
    }
  },

  stopScan: () => {
    invoke('stop_scan').catch(console.error);
    set({ isScanning: false });
  },
}));
```

### 4.3 Subscription Patterns

Prefer selector functions to avoid unnecessary re-renders:

```typescript
// BAD — subscribes to entire store, re-renders on any change
const { devices, isScanning } = useScanStore();

// GOOD — selective subscription via selector
const devices = useScanStore((s) => s.devices);
const isScanning = useScanStore((s) => s.isScanning);

// GOOD — multiple selectors
const [devices, isScanning] = useScanStore((s) => [s.devices, s.isScanning]);
```

---

## 5. Tailwind CSS Guidelines

### 5.1 Class Composition

Use `clsx` and `tailwind-merge` for conditional classes:

```typescript
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

const buttonClass = (isLoading: boolean, variant: 'primary' | 'secondary') =>
  twMerge(
    clsx(
      'px-4 py-2 rounded-lg font-medium transition-colors',
      'focus:outline-none focus:ring-2 focus:ring-offset-2',
      variant === 'primary' && 'bg-blue-600 text-white hover:bg-blue-700',
      variant === 'secondary' && 'bg-gray-200 text-gray-900 hover:bg-gray-300',
      isLoading && 'opacity-50 cursor-not-allowed'
    )
  );
```

### 5.2 Design Tokens

Use consistent values from the design system:

| Token | Value | Usage |
|-------|-------|-------|
| `--color-primary` | `blue-600` | Primary actions |
| `--color-success` | `green-600` | Success states, online |
| `--color-warning` | `amber-500` | Warnings |
| `--color-danger` | `red-600` | Errors, critical |
| `--color-bg` | `gray-900` | Main background |
| `--color-surface` | `gray-800` | Cards, panels |

### 5.3 Prohibited Patterns

```typescript
// BAD — inline styles
<div style={{ backgroundColor: '#1f2937' }}>

// BAD — arbitrary string concatenation
<div className={'flex ' + (isActive ? 'bg-blue-600' : 'bg-gray-700')}>

// GOOD — tailwind-merge with clsx
<div className={twMerge(clsx('flex', isActive && 'bg-blue-600', 'bg-gray-700'))}>
```

---

## 6. Accessibility

### 6.1 Semantic HTML

Use semantic elements for their intended purpose:

```typescript
// BAD
<div onClick={handleStart}>Start Scan</div>

// GOOD
<button onClick={handleStart}>Start Scan</button>
```

### 6.2 Interactive Elements

All interactive elements must be keyboard accessible:

```typescript
// For custom interactive components
<button
  onClick={handleAction}
  onKeyDown={(e) => e.key === 'Enter' && handleAction()}
  role="button"
  tabIndex={0}
>
  Action
</button>
```

### 6.3 ARIA Attributes

Provide accessible labels for icon-only buttons and visual indicators:

```typescript
// Icon button without visible text
<button aria-label="Close panel" onClick={onClose}>
  <XIcon className="w-5 h-5" />
</button>

// Status indicators
<div
  role="status"
  aria-label={`Device ${device.hostname} is ${device.status}`}
>
  <span className="sr-only">Status:</span>
  {device.status}
</div>

// Live regions for dynamic updates
<div aria-live="polite" aria-atomic="true">
  {scanProgress}% complete
</div>
```

### 6.4 Focus Management

Manage focus for modal dialogs and panels:

```typescript
useEffect(() => {
  if (isOpen && closeButtonRef.current) {
    closeButtonRef.current.focus();
  }
}, [isOpen]);
```

---

## 7. Error Handling

### 7.1 IPC Error Handling

Always handle Tauri errors gracefully:

```typescript
interface TauriError {
  message: string;
  code?: string;
}

const isTauriError = (error: unknown): error is TauriError => {
  return typeof error === 'object' && error !== null && 'message' in error;
};

async function safeInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    if (isTauriError(error)) {
      throw new NetworkError(error.message, error.code);
    }
    throw new NetworkError('Unknown error', 'UNKNOWN');
  }
}
```

### 7.2 Error State UI

Display errors with clear, user-friendly messages:

```typescript
const ErrorDisplay: React.FC<{ error: Error; onRetry?: () => void }> = ({
  error,
  onRetry,
}) => (
  <div role="alert" className="p-4 bg-red-900/50 border border-red-700 rounded-lg">
    <p className="text-red-300">{error.message}</p>
    {onRetry && (
      <button onClick={onRetry} className="mt-2 text-sm text-red-400 hover:text-red-300">
        Retry
      </button>
    )}
  </div>
);
```

---

## 8. Performance Checklist

Before finalizing any component, verify:

- [ ] No `useEffect` with missing cleanup returning Tauri listener unlisten function
- [ ] Large device lists (100+) use `useMemo` for sorting/filtering
- [ ] Callbacks passed to child components are wrapped in `useCallback`
- [ ] No `any` types exist anywhere in the component or its imports
- [ ] All `invoke` calls have try/catch error handling
- [ ] All interactive elements have proper keyboard support and ARIA labels
- [ ] Class strings use `clsx`/`twMerge`, not string concatenation
- [ ] Stable keys used in list rendering (prefer device MAC over array index)

---

## 9. File Naming Conventions

| File Type | Convention | Example |
|-----------|------------|---------|
| Components | PascalCase | `NetworkGraph.tsx` |
| Hooks | camelCase with `use` prefix | `useDeviceSelection.ts` |
| Stores | camelCase with `Store` suffix | `scanStore.ts` |
| Utilities | camelCase | `ipValidator.ts` |
| Types | PascalCase in `types/` | `types/device.ts` |
| Constants | SCREAMING_SNAKE_CASE | `SCAN_TIMEOUT_MS` |

---

## 10. Directory Structure

```
src/
  components/
    common/          # Shared UI components (Button, Card, Input)
    network/         # Network-specific components (NetworkGraph, DeviceCard)
    scan/            # Scan-related components (ScanControls, ScanProgress)
  hooks/             # Custom React hooks
  stores/            # Zustand stores
  types/             # Shared TypeScript interfaces
  utils/             # Utility functions
  App.tsx
  main.tsx
```

---

*This skill document is aligned with the NetSentinel project architecture (React 19 + TypeScript + Tailwind CSS + Zustand + Tauri) and is mandatory for all frontend development tasks.*