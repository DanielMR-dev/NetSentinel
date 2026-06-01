import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useBannerStore } from '../bannerStore';
import type { BannerResult, CveAlertEvent } from '../../types/device';

// Mock Tauri event listener
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

function createMockBanner(overrides: Partial<BannerResult> = {}): BannerResult {
  return {
    ip: '192.168.1.1',
    port: 80,
    banner: 'Apache/2.4.51',
    service: 'http',
    osFingerprint: null,
    timestamp: 1700000000,
    tlsInfo: null,
    ...overrides,
  };
}

function createMockCveAlert(overrides: Partial<CveAlertEvent> = {}): CveAlertEvent {
  return {
    cveId: 'CVE-2021-44228',
    severity: 'critical',
    description: 'Log4Shell RCE',
    affectedSoftware: 'Apache Log4j',
    affectedVersions: ['2.0-beta9 - 2.14.1'],
    cvssScore: 10.0,
    ip: '192.168.1.1',
    port: 80,
    ...overrides,
  };
}

function resetStore(): void {
  useBannerStore.setState({
    banners: new Map(),
    cveAlerts: [],
    isLoading: false,
  });
}

describe('bannerStore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetStore();
  });

  describe('addBanner', () => {
    it('adds a banner result keyed by IP', () => {
      const banner = createMockBanner();

      useBannerStore.getState().addBanner(banner);

      const banners = useBannerStore.getState().banners;
      expect(banners.get('192.168.1.1')).toHaveLength(1);
      expect(banners.get('192.168.1.1')![0].banner).toBe('Apache/2.4.51');
    });

    it('adds multiple banners for the same IP on different ports', () => {
      useBannerStore.getState().addBanner(createMockBanner({ port: 80 }));
      useBannerStore.getState().addBanner(createMockBanner({ port: 443, banner: 'nginx/1.21' }));

      const banners = useBannerStore.getState().banners.get('192.168.1.1');
      expect(banners).toHaveLength(2);
    });

    it('deduplicates by port for the same IP', () => {
      useBannerStore.getState().addBanner(createMockBanner({ port: 80, banner: 'Apache/2.4.51' }));
      useBannerStore.getState().addBanner(createMockBanner({ port: 80, banner: 'Apache/2.4.52' }));

      const banners = useBannerStore.getState().banners.get('192.168.1.1');
      expect(banners).toHaveLength(1);
      expect(banners![0].banner).toBe('Apache/2.4.51');
    });

    it('adds banners for different IPs independently', () => {
      useBannerStore.getState().addBanner(createMockBanner({ ip: '192.168.1.1', port: 80 }));
      useBannerStore.getState().addBanner(createMockBanner({ ip: '192.168.1.2', port: 80 }));

      const banners = useBannerStore.getState().banners;
      expect(banners.get('192.168.1.1')).toHaveLength(1);
      expect(banners.get('192.168.1.2')).toHaveLength(1);
    });
  });

  describe('addCveAlert', () => {
    it('adds a CVE alert', () => {
      const alert = createMockCveAlert();

      useBannerStore.getState().addCveAlert(alert);

      expect(useBannerStore.getState().cveAlerts).toHaveLength(1);
      expect(useBannerStore.getState().cveAlerts[0].cveId).toBe('CVE-2021-44228');
    });

    it('deduplicates by cveId + ip + port', () => {
      const alert = createMockCveAlert();

      useBannerStore.getState().addCveAlert(alert);
      useBannerStore.getState().addCveAlert({ ...alert }); // exact duplicate

      expect(useBannerStore.getState().cveAlerts).toHaveLength(1);
    });

    it('allows same CVE on different ports', () => {
      useBannerStore.getState().addCveAlert(createMockCveAlert({ port: 80 }));
      useBannerStore.getState().addCveAlert(createMockCveAlert({ port: 443 }));

      expect(useBannerStore.getState().cveAlerts).toHaveLength(2);
    });

    it('allows different CVEs on same ip+port', () => {
      useBannerStore.getState().addCveAlert(createMockCveAlert({ cveId: 'CVE-2021-44228' }));
      useBannerStore.getState().addCveAlert(createMockCveAlert({ cveId: 'CVE-2021-45046' }));

      expect(useBannerStore.getState().cveAlerts).toHaveLength(2);
    });
  });

  describe('clearBanners', () => {
    it('resets the banners map', () => {
      useBannerStore.getState().addBanner(createMockBanner());
      useBannerStore.getState().addBanner(createMockBanner({ ip: '10.0.0.1' }));

      useBannerStore.getState().clearBanners();

      expect(useBannerStore.getState().banners.size).toBe(0);
    });
  });

  describe('clearCveAlerts', () => {
    it('resets the cveAlerts array', () => {
      useBannerStore.getState().addCveAlert(createMockCveAlert());
      useBannerStore.getState().addCveAlert(createMockCveAlert({ cveId: 'CVE-2022-0001' }));

      useBannerStore.getState().clearCveAlerts();

      expect(useBannerStore.getState().cveAlerts).toEqual([]);
    });
  });

  describe('getBannersForHost', () => {
    it('returns correct banners for a given IP', () => {
      useBannerStore.getState().addBanner(createMockBanner({ ip: '192.168.1.1', port: 80 }));
      useBannerStore.getState().addBanner(createMockBanner({ ip: '192.168.1.1', port: 443 }));
      useBannerStore.getState().addBanner(createMockBanner({ ip: '10.0.0.1', port: 22 }));

      const banners = useBannerStore.getState().getBannersForHost('192.168.1.1');
      expect(banners).toHaveLength(2);
    });

    it('returns empty array for unknown IP', () => {
      const banners = useBannerStore.getState().getBannersForHost('172.16.0.1');
      expect(banners).toEqual([]);
    });
  });

  describe('getCveAlertsForHost', () => {
    it('filters alerts by IP', () => {
      useBannerStore.getState().addCveAlert(createMockCveAlert({ ip: '192.168.1.1' }));
      useBannerStore.getState().addCveAlert(createMockCveAlert({ ip: '192.168.1.2', cveId: 'CVE-2022-0001' }));
      useBannerStore.getState().addCveAlert(createMockCveAlert({ ip: '192.168.1.1', cveId: 'CVE-2022-0002', port: 443 }));

      const alerts = useBannerStore.getState().getCveAlertsForHost('192.168.1.1');
      expect(alerts).toHaveLength(2);
      expect(alerts.every((a) => a.ip === '192.168.1.1')).toBe(true);
    });

    it('returns empty array for IP with no alerts', () => {
      useBannerStore.getState().addCveAlert(createMockCveAlert({ ip: '192.168.1.1' }));

      const alerts = useBannerStore.getState().getCveAlertsForHost('10.0.0.1');
      expect(alerts).toEqual([]);
    });
  });
});
