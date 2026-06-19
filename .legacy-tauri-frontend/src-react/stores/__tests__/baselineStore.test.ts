import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useBaselineStore } from '../baselineStore';
import type { Baseline, BaselineDiff, Device } from '../../types/device';

// Mock Tauri APIs
const mockInvoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

function createMockDevice(overrides: Partial<Device> = {}): Device {
  return {
    ip: '192.168.1.1',
    mac: 'AA:BB:CC:DD:EE:FF',
    hostname: 'test-host',
    vendor: 'TestVendor',
    status: 'online',
    ports: [],
    lastSeen: 1700000000,
    banner_results: [],
    ...overrides,
  };
}

function createMockBaseline(overrides: Partial<Baseline> = {}): Baseline {
  return {
    id: 'baseline-1',
    name: 'Test Baseline',
    description: 'A test baseline',
    devices: [createMockDevice()],
    scanCidr: '192.168.1.0/24',
    createdAt: 1700000000,
    ...overrides,
  };
}

function createMockDiff(overrides: Partial<BaselineDiff> = {}): BaselineDiff {
  return {
    baselineId: 'baseline-1',
    baselineName: 'Test Baseline',
    newHosts: [createMockDevice({ ip: '192.168.1.50' })],
    removedHosts: [],
    changedPorts: [],
    newServices: [],
    scanTimestamp: 1700001000,
    ...overrides,
  };
}

function resetStore(): void {
  useBaselineStore.setState({
    baselines: [],
    currentDiff: null,
    isLoading: false,
    error: null,
  });
}

describe('baselineStore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetStore();
  });

  describe('fetchBaselines', () => {
    it('calls invoke and sets baselines on success', async () => {
      const baselines = [createMockBaseline(), createMockBaseline({ id: 'baseline-2', name: 'Second' })];
      mockInvoke.mockResolvedValue(baselines);

      await useBaselineStore.getState().fetchBaselines();

      expect(mockInvoke).toHaveBeenCalledWith('get_baselines');
      expect(useBaselineStore.getState().baselines).toHaveLength(2);
      expect(useBaselineStore.getState().isLoading).toBe(false);
    });

    it('sets loading state while fetching', async () => {
      mockInvoke.mockResolvedValue([]);

      const promise = useBaselineStore.getState().fetchBaselines();
      // isLoading is set synchronously before the await
      expect(useBaselineStore.getState().isLoading).toBe(true);

      await promise;
      expect(useBaselineStore.getState().isLoading).toBe(false);
    });

    it('sets error on failed invoke', async () => {
      mockInvoke.mockRejectedValue(new Error('Backend unavailable'));

      await useBaselineStore.getState().fetchBaselines();

      expect(useBaselineStore.getState().error).toBe('Backend unavailable');
      expect(useBaselineStore.getState().isLoading).toBe(false);
      expect(useBaselineStore.getState().baselines).toEqual([]);
    });
  });

  describe('saveBaseline', () => {
    it('calls invoke and adds baseline to list', async () => {
      mockInvoke.mockResolvedValue('baseline-new');
      const baseline = createMockBaseline({ id: 'temp-id', name: 'New Baseline' });

      await useBaselineStore.getState().saveBaseline(baseline);

      expect(mockInvoke).toHaveBeenCalledWith('save_baseline', { baseline });
      expect(useBaselineStore.getState().baselines).toHaveLength(1);
      expect(useBaselineStore.getState().baselines[0].id).toBe('baseline-new');
      expect(useBaselineStore.getState().baselines[0].name).toBe('New Baseline');
    });

    it('sets error and throws on failure', async () => {
      mockInvoke.mockRejectedValue(new Error('Save failed'));
      const baseline = createMockBaseline();

      await expect(useBaselineStore.getState().saveBaseline(baseline)).rejects.toThrow('Save failed');

      expect(useBaselineStore.getState().error).toBe('Save failed');
      expect(useBaselineStore.getState().isLoading).toBe(false);
    });
  });

  describe('deleteBaseline', () => {
    it('calls invoke and removes baseline from list', async () => {
      mockInvoke.mockResolvedValue(undefined);
      useBaselineStore.setState({
        baselines: [createMockBaseline({ id: 'b1' }), createMockBaseline({ id: 'b2' })],
      });

      await useBaselineStore.getState().deleteBaseline('b1');

      expect(mockInvoke).toHaveBeenCalledWith('delete_baseline', { id: 'b1' });
      expect(useBaselineStore.getState().baselines).toHaveLength(1);
      expect(useBaselineStore.getState().baselines[0].id).toBe('b2');
    });

    it('sets error and throws on failure', async () => {
      mockInvoke.mockRejectedValue(new Error('Delete failed'));
      useBaselineStore.setState({ baselines: [createMockBaseline({ id: 'b1' })] });

      await expect(useBaselineStore.getState().deleteBaseline('b1')).rejects.toThrow('Delete failed');

      expect(useBaselineStore.getState().error).toBe('Delete failed');
      // Baseline should still exist since delete failed
      expect(useBaselineStore.getState().baselines).toHaveLength(1);
    });
  });

  describe('compareBaseline', () => {
    it('calls invoke and sets currentDiff', async () => {
      const diff = createMockDiff();
      mockInvoke.mockResolvedValue(diff);

      await useBaselineStore.getState().compareBaseline('baseline-1');

      expect(mockInvoke).toHaveBeenCalledWith('compare_baseline', { id: 'baseline-1' });
      expect(useBaselineStore.getState().currentDiff).toEqual(diff);
      expect(useBaselineStore.getState().isLoading).toBe(false);
    });

    it('clears previous diff before comparing', async () => {
      useBaselineStore.setState({ currentDiff: createMockDiff({ baselineId: 'old' }) });
      mockInvoke.mockResolvedValue(createMockDiff());

      const promise = useBaselineStore.getState().compareBaseline('baseline-1');
      // currentDiff should be cleared immediately
      expect(useBaselineStore.getState().currentDiff).toBeNull();

      await promise;
      expect(useBaselineStore.getState().currentDiff?.baselineId).toBe('baseline-1');
    });

    it('sets error on failure', async () => {
      mockInvoke.mockRejectedValue(new Error('Compare failed'));

      await useBaselineStore.getState().compareBaseline('baseline-1');

      expect(useBaselineStore.getState().error).toBe('Compare failed');
      expect(useBaselineStore.getState().currentDiff).toBeNull();
    });
  });

  describe('clearDiff', () => {
    it('resets currentDiff to null', () => {
      useBaselineStore.setState({ currentDiff: createMockDiff() });

      useBaselineStore.getState().clearDiff();

      expect(useBaselineStore.getState().currentDiff).toBeNull();
    });
  });

  describe('clearError', () => {
    it('resets error to null', () => {
      useBaselineStore.setState({ error: 'Some error' });

      useBaselineStore.getState().clearError();

      expect(useBaselineStore.getState().error).toBeNull();
    });
  });
});
