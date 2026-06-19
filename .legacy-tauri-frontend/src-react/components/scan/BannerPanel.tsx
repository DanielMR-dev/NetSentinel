import React, { useMemo, useState, useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useBannerStore } from '../../stores/bannerStore';
import type { BannerResult, TlsInfo } from '../../types/device';

interface BannerPanelProps {
  ip: string;
}

export const BannerPanel: React.FC<BannerPanelProps> = ({ ip }) => {
  const banners = useBannerStore((s) => s.banners);
  const hostBanners = useMemo(() => banners.get(ip) ?? [], [banners, ip]);

  if (hostBanners.length === 0) {
    return (
      <div className="p-4 text-center text-gray-500 dark:text-gray-500">
        <svg className="w-8 h-8 mx-auto mb-2 text-gray-400 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
        <p className="text-sm">No banners captured</p>
        <p className="text-xs text-gray-400 dark:text-gray-600 mt-1">
          Banner grabbing in progress...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2 p-2">
      {hostBanners.map((banner) => (
        <BannerEntry key={`${banner.ip}-${banner.port}`} banner={banner} />
      ))}
    </div>
  );
};

interface BannerEntryProps {
  banner: BannerResult;
}

function getTlsBadgeConfig(tls: TlsInfo): { bgClass: string; textClass: string; label: string } {
  if (tls.expired) {
    return { bgClass: 'bg-red-100 dark:bg-red-900/50', textClass: 'text-red-700 dark:text-red-300', label: 'TLS (Expired)' };
  }
  if (tls.selfSigned) {
    return { bgClass: 'bg-amber-100 dark:bg-amber-900/50', textClass: 'text-amber-700 dark:text-amber-300', label: 'TLS (Self-Signed)' };
  }
  return { bgClass: 'bg-green-100 dark:bg-green-900/50', textClass: 'text-green-700 dark:text-green-300', label: 'TLS' };
}

const BannerEntry: React.FC<BannerEntryProps> = React.memo(({ banner }) => {
  const [expanded, setExpanded] = useState(false);

  const handleToggle = useCallback(() => {
    setExpanded((prev) => !prev);
  }, []);

  const tlsBadgeConfig = banner.tlsInfo ? getTlsBadgeConfig(banner.tlsInfo) : null;

  return (
    <div className="bg-gray-50 dark:bg-gray-750 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={handleToggle}
        className="w-full px-3 py-2 flex items-center justify-between text-left hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset"
        aria-expanded={expanded}
      >
        <div className="flex items-center gap-2">
          <span className="text-blue-600 dark:text-blue-400 font-mono font-medium text-sm">
            :{banner.port}
          </span>
          {banner.service && (
            <span className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300">
              {banner.service}
            </span>
          )}
          {banner.osFingerprint && (
            <span className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-purple-100 dark:bg-purple-900/50 text-purple-700 dark:text-purple-300">
              OS: {banner.osFingerprint}
            </span>
          )}
          {tlsBadgeConfig && banner.tlsInfo && (
            <span
              className={twMerge(
                clsx(
                  'inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-medium rounded',
                  tlsBadgeConfig.bgClass,
                  tlsBadgeConfig.textClass
                )
              )}
              title={tlsBadgeConfig.label}
            >
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              {tlsBadgeConfig.label}
            </span>
          )}
        </div>
        <svg
          className={clsx('w-4 h-4 text-gray-400 transition-transform duration-200', expanded && 'rotate-180')}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="px-3 pb-2 border-t border-gray-200 dark:border-gray-700">
          <pre className="mt-2 text-xs text-gray-600 dark:text-gray-400 font-mono whitespace-pre-wrap break-all bg-gray-100 dark:bg-gray-900 p-2 rounded">
            {banner.banner}
          </pre>
          {/* TLS Summary when expanded */}
          {banner.tlsInfo && (
            <div className="mt-2 p-2 bg-gray-100 dark:bg-gray-900 rounded space-y-1">
              <div className="flex justify-between">
                <span className="text-[10px] text-gray-500 dark:text-gray-400">TLS Version</span>
                <span className="text-[10px] font-mono text-gray-700 dark:text-gray-300">{banner.tlsInfo.version}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[10px] text-gray-500 dark:text-gray-400">Issuer</span>
                <span className="text-[10px] text-gray-700 dark:text-gray-300 truncate max-w-[180px]" title={banner.tlsInfo.issuer}>{banner.tlsInfo.issuer}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[10px] text-gray-500 dark:text-gray-400">Expiry</span>
                <span className={twMerge(
                  clsx(
                    'text-[10px] font-medium',
                    banner.tlsInfo.expired
                      ? 'text-red-600 dark:text-red-400'
                      : banner.tlsInfo.daysUntilExpiry <= 30
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-green-600 dark:text-green-400'
                  )
                )}>
                  {banner.tlsInfo.expired
                    ? `Expired ${Math.abs(banner.tlsInfo.daysUntilExpiry)}d ago`
                    : `${banner.tlsInfo.daysUntilExpiry}d remaining`}
                </span>
              </div>
              <p className="text-[10px] text-blue-600 dark:text-blue-400 font-medium pt-1">
                View full certificate details in the TLS tab
              </p>
            </div>
          )}
          <div className="mt-1 text-[10px] text-gray-400 dark:text-gray-500">
            Captured: {new Date(banner.timestamp * 1000).toLocaleTimeString()}
          </div>
        </div>
      )}
    </div>
  );
});
BannerEntry.displayName = 'BannerEntry';
