import React, { useMemo, useState, useCallback } from 'react';
import { clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useBannerStore } from '../../stores/bannerStore';
import type { TlsInfo, BannerResult } from '../../types/device';

interface TlsInfoPanelProps {
  ip: string;
}

type CertStatus = 'valid' | 'expiring' | 'expired' | 'self-signed';

function getCertStatus(tls: TlsInfo): CertStatus {
  if (tls.expired) return 'expired';
  if (tls.selfSigned) return 'self-signed';
  if (tls.daysUntilExpiry <= 30) return 'expiring';
  return 'valid';
}

function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

const CERT_STATUS_CONFIG: Record<CertStatus, { label: string; bgClass: string; textClass: string }> = {
  valid: {
    label: 'Valid',
    bgClass: 'bg-green-100 dark:bg-green-900/50',
    textClass: 'text-green-700 dark:text-green-400',
  },
  expiring: {
    label: 'Expiring Soon',
    bgClass: 'bg-amber-100 dark:bg-amber-900/50',
    textClass: 'text-amber-700 dark:text-amber-400',
  },
  expired: {
    label: 'Expired',
    bgClass: 'bg-red-100 dark:bg-red-900/50',
    textClass: 'text-red-700 dark:text-red-400',
  },
  'self-signed': {
    label: 'Self-Signed',
    bgClass: 'bg-amber-100 dark:bg-amber-900/50',
    textClass: 'text-amber-700 dark:text-amber-400',
  },
};

const INSECURE_TLS_VERSIONS = new Set(['TLSv1.0', 'TLSv1.1', 'Unknown']);

interface TlsCardProps {
  banner: BannerResult;
}

const TlsCard: React.FC<TlsCardProps> = React.memo(({ banner }) => {
  const tls = banner.tlsInfo;
  const [sanExpanded, setSanExpanded] = useState(false);

  const handleToggleSan = useCallback(() => {
    setSanExpanded((prev) => !prev);
  }, []);

  if (tls === null) return null;

  const status = getCertStatus(tls);
  const statusConfig = CERT_STATUS_CONFIG[status];
  const isInsecureVersion = INSECURE_TLS_VERSIONS.has(tls.version);

  return (
    <div className="bg-gray-50 dark:bg-gray-750 border border-gray-200 dark:border-gray-700 rounded-lg p-3 space-y-3">
      {/* Header: Port + Service + Status Badge */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-blue-600 dark:text-blue-400 font-mono font-medium text-sm">
            :{banner.port}
          </span>
          {banner.service && (
            <span className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300">
              {banner.service}
            </span>
          )}
        </div>
        <span
          role="status"
          aria-label={`Certificate status: ${statusConfig.label}`}
          className={twMerge(
            clsx(
              'px-2 py-0.5 text-xs font-bold rounded-full',
              statusConfig.bgClass,
              statusConfig.textClass
            )
          )}
        >
          {statusConfig.label}
        </span>
      </div>

      {/* Certificate Details using dl/dt/dd for accessibility */}
      <dl className="space-y-2">
        {/* TLS Version */}
        <div className="flex justify-between items-center">
          <dt className="text-xs text-gray-500 dark:text-gray-400 font-medium">TLS Version</dt>
          <dd className="flex items-center gap-1.5">
            <span className={twMerge(
              clsx(
                'text-xs font-mono',
                isInsecureVersion
                  ? 'text-amber-700 dark:text-amber-400'
                  : 'text-gray-900 dark:text-gray-200'
              )
            )}>
              {tls.version}
            </span>
            {isInsecureVersion && (
              <span
                role="status"
                aria-label="Insecure TLS version"
                className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-amber-100 dark:bg-amber-900/50 text-amber-700 dark:text-amber-400"
              >
                Insecure
              </span>
            )}
          </dd>
        </div>

        {/* Cipher Suite */}
        <div className="flex justify-between items-center">
          <dt className="text-xs text-gray-500 dark:text-gray-400 font-medium">Cipher Suite</dt>
          <dd className="text-xs font-mono text-gray-900 dark:text-gray-200 text-right max-w-[200px] truncate" title={tls.cipherSuite}>
            {tls.cipherSuite}
          </dd>
        </div>

        {/* Issuer */}
        <div className="flex justify-between items-center">
          <dt className="text-xs text-gray-500 dark:text-gray-400 font-medium">Issuer</dt>
          <dd className="text-xs text-gray-900 dark:text-gray-200 text-right max-w-[200px] truncate" title={tls.issuer}>
            {tls.issuer}
          </dd>
        </div>

        {/* Subject */}
        <div className="flex justify-between items-center">
          <dt className="text-xs text-gray-500 dark:text-gray-400 font-medium">Subject</dt>
          <dd className="text-xs text-gray-900 dark:text-gray-200 text-right max-w-[200px] truncate" title={tls.subject}>
            {tls.subject}
          </dd>
        </div>

        {/* Validity Period */}
        <div className="flex justify-between items-center">
          <dt className="text-xs text-gray-500 dark:text-gray-400 font-medium">Valid From</dt>
          <dd className="text-xs text-gray-900 dark:text-gray-200">
            {formatTimestamp(tls.notBefore)}
          </dd>
        </div>
        <div className="flex justify-between items-center">
          <dt className="text-xs text-gray-500 dark:text-gray-400 font-medium">Valid Until</dt>
          <dd className="text-xs text-gray-900 dark:text-gray-200">
            {formatTimestamp(tls.notAfter)}
          </dd>
        </div>

        {/* Days Until Expiry */}
        <div className="flex justify-between items-center">
          <dt className="text-xs text-gray-500 dark:text-gray-400 font-medium">Expiry</dt>
          <dd className={twMerge(
            clsx(
              'text-xs font-medium',
              tls.expired
                ? 'text-red-600 dark:text-red-400'
                : tls.daysUntilExpiry <= 30
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-green-600 dark:text-green-400'
            )
          )}>
            {tls.expired
              ? `Expired ${Math.abs(tls.daysUntilExpiry)} day${Math.abs(tls.daysUntilExpiry) !== 1 ? 's' : ''} ago`
              : `${tls.daysUntilExpiry} day${tls.daysUntilExpiry !== 1 ? 's' : ''} remaining`}
          </dd>
        </div>

        {/* SAN Domains */}
        {tls.sanDomains.length > 0 && (
          <div>
            <div className="flex justify-between items-center">
              <dt className="text-xs text-gray-500 dark:text-gray-400 font-medium">SAN Domains</dt>
              <dd className="text-xs text-gray-900 dark:text-gray-200">
                {tls.sanDomains.length} domain{tls.sanDomains.length !== 1 ? 's' : ''}
              </dd>
            </div>
            {tls.sanDomains.length > 2 && (
              <button
                type="button"
                onClick={handleToggleSan}
                className="mt-1 text-[10px] text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 rounded"
                aria-expanded={sanExpanded}
                aria-label={sanExpanded ? 'Collapse SAN domains list' : 'Expand SAN domains list'}
              >
                {sanExpanded ? 'Show less' : `Show all ${tls.sanDomains.length}`}
              </button>
            )}
            <ul className={twMerge(
              clsx(
                'mt-1 space-y-0.5',
                !sanExpanded && tls.sanDomains.length > 2 && 'max-h-[2.5rem] overflow-hidden'
              )
            )}>
              {(sanExpanded || tls.sanDomains.length <= 2 ? tls.sanDomains : tls.sanDomains.slice(0, 2)).map((domain, index) => (
                <li key={`${domain}-${index}`} className="text-[10px] font-mono text-gray-600 dark:text-gray-400 pl-2 border-l-2 border-gray-200 dark:border-gray-700">
                  {domain}
                </li>
              ))}
            </ul>
          </div>
        )}
      </dl>
    </div>
  );
});
TlsCard.displayName = 'TlsCard';

export const TlsInfoPanel: React.FC<TlsInfoPanelProps> = ({ ip }) => {
  const banners = useBannerStore((s) => s.banners);

  const tlsBanners = useMemo(() => {
    const hostBanners = banners.get(ip) ?? [];
    return hostBanners.filter((b): b is BannerResult & { tlsInfo: TlsInfo } => b.tlsInfo !== null);
  }, [banners, ip]);

  if (tlsBanners.length === 0) {
    return (
      <div className="p-4 text-center text-gray-500 dark:text-gray-500">
        <svg className="w-8 h-8 mx-auto mb-2 text-gray-400 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
        <p className="text-sm">No TLS certificate information available</p>
        <p className="text-xs text-gray-400 dark:text-gray-600 mt-1">
          TLS analysis runs automatically on ports 443, 465, 636, 990, 993, 995, 8443, 8883
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3 p-2">
      {tlsBanners.map((banner) => (
        <TlsCard key={`tls-${banner.ip}-${banner.port}`} banner={banner} />
      ))}
    </div>
  );
};
