import { describe, it, expect } from 'vitest';
import {
  isValidCidr,
  isValidPort,
  isValidTimeout,
  isValidRefreshRate,
  isValidConcurrentValue,
  isValidScanConfig,
  isValidUiPreferences,
  isValidSettingsProfile,
  safeProfileFromObject,
  createDefaultProfile,
  createDefaultScanConfig,
  createDefaultUiPreferences,
} from '../settings';

describe('settings validation helpers', () => {
  describe('isValidCidr', () => {
    it('accepts valid CIDR notation', () => {
      expect(isValidCidr('192.168.1.0/24')).toBe(true);
      expect(isValidCidr('10.0.0.0/8')).toBe(true);
      expect(isValidCidr('172.16.0.0/12')).toBe(true);
      expect(isValidCidr('0.0.0.0/0')).toBe(true);
      expect(isValidCidr('255.255.255.255/32')).toBe(true);
    });

    it('rejects invalid CIDR notation', () => {
      expect(isValidCidr('192.168.1.0')).toBe(false); // no mask
      expect(isValidCidr('192.168.1.0/33')).toBe(false); // mask > 32
      expect(isValidCidr('256.168.1.0/24')).toBe(false); // octet > 255
      expect(isValidCidr('192.168.1/24')).toBe(false); // missing octet
      expect(isValidCidr('abc.def.ghi.jkl/24')).toBe(false); // non-numeric
      expect(isValidCidr('')).toBe(false);
    });
  });

  describe('isValidPort', () => {
    it('accepts valid port numbers', () => {
      expect(isValidPort(1)).toBe(true);
      expect(isValidPort(80)).toBe(true);
      expect(isValidPort(443)).toBe(true);
      expect(isValidPort(65535)).toBe(true);
    });

    it('rejects invalid port numbers', () => {
      expect(isValidPort(0)).toBe(false);
      expect(isValidPort(-1)).toBe(false);
      expect(isValidPort(65536)).toBe(false);
      expect(isValidPort(1.5)).toBe(false); // not integer
    });
  });

  describe('isValidTimeout', () => {
    it('accepts valid timeout values', () => {
      expect(isValidTimeout(100)).toBe(true);
      expect(isValidTimeout(1000)).toBe(true);
      expect(isValidTimeout(30000)).toBe(true);
    });

    it('rejects invalid timeout values', () => {
      expect(isValidTimeout(99)).toBe(false);
      expect(isValidTimeout(30001)).toBe(false);
      expect(isValidTimeout(0)).toBe(false);
    });
  });

  describe('isValidRefreshRate', () => {
    it('accepts valid refresh rate values', () => {
      expect(isValidRefreshRate(500)).toBe(true);
      expect(isValidRefreshRate(2000)).toBe(true);
      expect(isValidRefreshRate(10000)).toBe(true);
    });

    it('rejects invalid refresh rate values', () => {
      expect(isValidRefreshRate(499)).toBe(false);
      expect(isValidRefreshRate(10001)).toBe(false);
    });
  });

  describe('isValidConcurrentValue', () => {
    it('accepts values within range', () => {
      expect(isValidConcurrentValue(50, 1, 100)).toBe(true);
      expect(isValidConcurrentValue(1, 1, 100)).toBe(true);
      expect(isValidConcurrentValue(100, 1, 100)).toBe(true);
    });

    it('rejects values outside range', () => {
      expect(isValidConcurrentValue(0, 1, 100)).toBe(false);
      expect(isValidConcurrentValue(101, 1, 100)).toBe(false);
    });

    it('rejects non-integer values', () => {
      expect(isValidConcurrentValue(50.5, 1, 100)).toBe(false);
    });
  });

  describe('isValidScanConfig', () => {
    it('accepts a valid ScanConfig object', () => {
      const config = createDefaultScanConfig();
      expect(isValidScanConfig(config)).toBe(true);
    });

    it('rejects null and undefined', () => {
      expect(isValidScanConfig(null)).toBe(false);
      expect(isValidScanConfig(undefined)).toBe(false);
    });

    it('rejects non-object values', () => {
      expect(isValidScanConfig('string')).toBe(false);
      expect(isValidScanConfig(42)).toBe(false);
    });

    it('rejects objects with missing fields', () => {
      expect(isValidScanConfig({ defaultCidr: '192.168.1.0/24' })).toBe(false);
    });

    it('rejects objects with wrong types', () => {
      const config = createDefaultScanConfig();
      expect(isValidScanConfig({ ...config, timeoutMs: 'not a number' })).toBe(false);
      expect(isValidScanConfig({ ...config, scanPortsEnabled: 'yes' })).toBe(false);
    });
  });

  describe('isValidUiPreferences', () => {
    it('accepts a valid UiPreferences object', () => {
      const prefs = createDefaultUiPreferences();
      expect(isValidUiPreferences(prefs)).toBe(true);
    });

    it('rejects null and undefined', () => {
      expect(isValidUiPreferences(null)).toBe(false);
      expect(isValidUiPreferences(undefined)).toBe(false);
    });

    it('rejects objects with missing fields', () => {
      expect(isValidUiPreferences({ refreshRateMs: 2000 })).toBe(false);
    });
  });

  describe('isValidSettingsProfile', () => {
    it('accepts a valid SettingsProfile object', () => {
      const profile = createDefaultProfile('Test');
      expect(isValidSettingsProfile(profile)).toBe(true);
    });

    it('rejects null and undefined', () => {
      expect(isValidSettingsProfile(null)).toBe(false);
      expect(isValidSettingsProfile(undefined)).toBe(false);
    });

    it('rejects objects with missing top-level fields', () => {
      expect(isValidSettingsProfile({ id: '1', name: 'Test' })).toBe(false);
    });

    it('rejects objects with invalid nested scanConfig', () => {
      const profile = createDefaultProfile('Test');
      expect(isValidSettingsProfile({ ...profile, scanConfig: {} })).toBe(false);
    });

    it('rejects objects with invalid nested uiPreferences', () => {
      const profile = createDefaultProfile('Test');
      expect(isValidSettingsProfile({ ...profile, uiPreferences: {} })).toBe(false);
    });
  });

  describe('safeProfileFromObject', () => {
    it('returns the input if it is already a valid profile', () => {
      const profile = createDefaultProfile('Valid');
      const result = safeProfileFromObject(profile);
      expect(result).toEqual(profile);
    });

    it('returns a default profile for null input', () => {
      const result = safeProfileFromObject(null);
      expect(isValidSettingsProfile(result)).toBe(true);
      expect(result.name).toBe('Unknown');
    });

    it('returns a default profile for undefined input', () => {
      const result = safeProfileFromObject(undefined);
      expect(isValidSettingsProfile(result)).toBe(true);
    });

    it('salvages valid fields from a malformed object', () => {
      const malformed = {
        id: 'custom-id',
        name: 'Custom Name',
        isDefault: false,
        scanConfig: createDefaultScanConfig(),
        // Missing uiPreferences, createdAt, updatedAt
      };

      const result = safeProfileFromObject(malformed);

      expect(result.id).toBe('custom-id');
      expect(result.name).toBe('Custom Name');
      expect(result.isDefault).toBe(false);
      expect(result.scanConfig).toEqual(createDefaultScanConfig());
      // Should have valid defaults for missing fields
      expect(isValidSettingsProfile(result)).toBe(true);
    });

    it('uses fallback name when input has no valid name', () => {
      const result = safeProfileFromObject({}, 'MyFallback');
      expect(result.name).toBe('MyFallback');
    });

    it('salvages valid uiPreferences from malformed object', () => {
      const malformed = {
        id: 'test-id',
        name: 'Test',
        uiPreferences: createDefaultUiPreferences(),
      };

      const result = safeProfileFromObject(malformed);
      expect(result.uiPreferences).toEqual(createDefaultUiPreferences());
    });
  });

  describe('createDefaultProfile', () => {
    it('creates a profile with the given name', () => {
      const profile = createDefaultProfile('My Profile');
      expect(profile.name).toBe('My Profile');
    });

    it('sets isDefault based on parameter', () => {
      expect(createDefaultProfile('A', true).isDefault).toBe(true);
      expect(createDefaultProfile('B', false).isDefault).toBe(false);
      expect(createDefaultProfile('C').isDefault).toBe(false); // default param
    });

    it('generates a UUID for the id', () => {
      const profile = createDefaultProfile('Test');
      expect(profile.id).toBeTruthy();
      expect(profile.id.length).toBeGreaterThan(0);
    });

    it('sets createdAt and updatedAt to current time', () => {
      const before = Date.now();
      const profile = createDefaultProfile('Test');
      const after = Date.now();

      expect(profile.createdAt).toBeGreaterThanOrEqual(before);
      expect(profile.createdAt).toBeLessThanOrEqual(after);
      expect(profile.updatedAt).toBeGreaterThanOrEqual(before);
      expect(profile.updatedAt).toBeLessThanOrEqual(after);
    });

    it('includes valid default scanConfig and uiPreferences', () => {
      const profile = createDefaultProfile('Test');
      expect(isValidScanConfig(profile.scanConfig)).toBe(true);
      expect(isValidUiPreferences(profile.uiPreferences)).toBe(true);
    });
  });
});
