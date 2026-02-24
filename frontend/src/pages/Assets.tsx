import { useState, useCallback, useRef, useEffect } from 'react';
import {
  Shield, Cpu, HardDrive, MemoryStick, Wifi, Package,
  AlertTriangle, CheckCircle, XCircle, Info,
  FolderOpen, FileText, Loader2, Play, Layers,
  RefreshCw, ChevronRight, ChevronDown, Zap, Server,
} from 'lucide-react';
import { assetsAPI } from '../services/api';

/* ==================== Types ==================== */
interface HardwareInfo {
  cpu_info: {
    model: string;
    physical_cores: number;
    logical_cores: number;
    current_freq_mhz: number;
    usage_percent: number;
  };
  memory_info: {
    total_gb: number;
    used_gb: number;
    free_gb: number;
    usage_percent: number;
  };
  disk_info: Array<{
    device: string;
    mountpoint: string;
    fstype: string;
    total_gb: number;
    used_gb: number;
    free_gb: number;
    usage_percent: number;
  }>;
  system_info: {
    os_name: string;
    os_release: string;
    architecture: string;
    hostname: string;
    platform: string;
    boot_time: string;
    uptime_seconds: number;
  };
  network_info: Array<{
    interface: string;
    is_up: boolean;
    speed_mbps: number;
    addresses: Array<{ family: string; address: string }>;
  }>;
  gpu_info?: {
    available: boolean;
    gpus: Array<{ name: string; vendor: string }>;
    detection_method: string | null;
  };
}

interface AssetDetail {
  path: string;
  file_type: string;
  owner: string;
  risk_level: number;
  size: number | null;
  direct_size: number | null;
  permissions: string | null;
  real_path: string | null;
  resolved_risk: number | null;
  metadata: Record<string, any> | null;
}

interface RiskGroupDetail {
  count: number;
  percentage: number;
  description: string;
  assets: AssetDetail[];
  total_in_level: number;
}

interface ScanResult {
  status: string;
  total_scanned: number;
  total_ignored: number;
  total_assets: number;
  risk_distribution: Record<string, RiskGroupDetail>;
  message: string;
}

/* ==================== Constants ==================== */
const riskConfig: Record<number, { bg: string; border: string; text: string; dot: string; icon: typeof Shield; label: string; shortLabel: string }> = {
  0: { bg: 'bg-red-500/8', border: 'border-red-500/20', text: 'text-red-400', dot: 'bg-red-500', icon: XCircle, label: 'LEVEL 0 · System Critical', shortLabel: 'Critical' },
  1: { bg: 'bg-orange-500/8', border: 'border-orange-500/20', text: 'text-orange-400', dot: 'bg-orange-500', icon: AlertTriangle, label: 'LEVEL 1 · Sensitive Credentials', shortLabel: 'Sensitive' },
  2: { bg: 'bg-yellow-500/8', border: 'border-yellow-500/20', text: 'text-yellow-400', dot: 'bg-yellow-500', icon: Info, label: 'LEVEL 2 · User Data', shortLabel: 'User Data' },
  3: { bg: 'bg-emerald-500/8', border: 'border-emerald-500/20', text: 'text-emerald-400', dot: 'bg-emerald-500', icon: CheckCircle, label: 'LEVEL 3 · Cleanable Content', shortLabel: 'Cleanable' },
};

const tabs = [
  { id: 'scan', name: 'Files', icon: FolderOpen },
  { id: 'assess', name: 'Softwares', icon: Package },
  { id: 'hardware', name: 'Hardwares', icon: Server },
] as const;

type TabId = typeof tabs[number]['id'];

/* ==================== Helpers ==================== */
function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function ProgressBar({ percent, colorClass = 'bg-accent' }: { percent: number; colorClass?: string }) {
  return (
    <div className="w-full bg-surface-0 rounded-full h-1.5 overflow-hidden">
      <div className={`h-full rounded-full transition-all duration-500 ${colorClass}`} style={{ width: `${Math.min(percent, 100)}%` }} />
    </div>
  );
}

function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || bytes === 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let size = bytes;
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
  return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/* ==================== Sub Components ==================== */
function SummaryRow({ label, value, valueColor = 'text-text-primary' }: { label: string; value: string | number; valueColor?: string }) {
  return (
    <div className="flex items-center justify-between py-1.5">
      <span className="text-[13px] text-text-secondary">{label}</span>
      <span className={`text-[13px] font-semibold tabular-nums ${valueColor}`}>{value}</span>
    </div>
  );
}

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-surface-1 border border-border rounded-xl ${className}`}>
      {children}
    </div>
  );
}

function CardHeader({ icon: Icon, title, badge, action }: { icon: typeof Shield; title: string; badge?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between px-5 py-4 border-b border-border">
      <div className="flex items-center gap-2.5">
        <Icon className="w-4 h-4 text-accent" />
        <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
        {badge}
      </div>
      {action}
    </div>
  );
}

/* ==================== Main Page ==================== */
export default function Assets() {
  const [activeTab, setActiveTab] = useState<TabId>('scan');

  /* --- Hardware State --- */
  const [hardware, setHardware] = useState<HardwareInfo | null>(null);
  const [hwLoading, setHwLoading] = useState(false);

  /* --- Scan State --- */
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanPath, setScanPath] = useState('');
  const [expandedLevels, setExpandedLevels] = useState<Set<number>>(new Set());
  const [scanProgress, setScanProgress] = useState<{ scanned: number; ignored: number }>({ scanned: 0, ignored: 0 });
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const toggleLevel = useCallback((level: number) => {
    setExpandedLevels(prev => {
      const next = new Set(prev);
      if (next.has(level)) next.delete(level); else next.add(level);
      return next;
    });
  }, []);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => { if (pollingRef.current) clearInterval(pollingRef.current); };
  }, []);

  const loadHardware = useCallback(async () => {
    setHwLoading(true);
    try {
      const res = await assetsAPI.hardware();
      setHardware(res.data.hardware_info as any);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Hardware scan failed');
    } finally {
      setHwLoading(false);
    }
  }, []);

  const runScan = useCallback(async () => {
    setScanning(true);
    setScanProgress({ scanned: 0, ignored: 0 });
    setScanResult(null);

    try {
      // 1. Start the async scan
      const startRes = await assetsAPI.startScan({
        path: scanPath || undefined,
        scan_system_root: !scanPath,
      });
      const scanId = startRes.data.scan_id;

      // 2. Poll progress every 800ms
      pollingRef.current = setInterval(async () => {
        try {
          const prog = await assetsAPI.scanProgress(scanId);
          setScanProgress({ scanned: prog.data.scanned_count, ignored: prog.data.ignored_count });

          if (prog.data.status === 'completed' && prog.data.result) {
            if (pollingRef.current) clearInterval(pollingRef.current);
            pollingRef.current = null;
            setScanResult(prog.data.result as ScanResult);
            setScanning(false);
          } else if (prog.data.status === 'failed') {
            if (pollingRef.current) clearInterval(pollingRef.current);
            pollingRef.current = null;
            alert(prog.data.error || 'Scan failed');
            setScanning(false);
          }
        } catch {
          // network hiccup — keep polling
        }
      }, 800);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Scan failed');
      setScanning(false);
    }
  }, [scanPath]);

  return (
    <div className="min-h-screen">
      {/* ===== Header ===== */}
      <div className="border-b border-border">
        <div className="px-8 py-6">
          <div className="flex items-center gap-4">
            <h1 className="text-xl font-bold text-text-primary">Asset Shield</h1>
            <span className="text-[11px] font-semibold border border-success/40 text-success px-3 py-1 rounded-full uppercase tracking-wider">
              Active
            </span>
          </div>
          <p className="text-[13px] text-text-muted mt-2">
            Scan and inventory file system assets, software dependencies, and hardware resources.
          </p>
        </div>

        {/* Tab Bar */}
        <div className="px-8 flex items-center gap-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`
                  flex items-center gap-2 px-4 py-2.5 text-[13px] font-medium border-b-2 transition-colors
                  ${isActive
                    ? 'text-accent border-accent'
                    : 'text-text-muted border-transparent hover:text-text-secondary hover:border-border'
                  }
                `}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.name}
              </button>
            );
          })}
        </div>
      </div>

      {/* ===== Content ===== */}
      <div className="p-8">

        {/* ========== Tab: Software ========== */}
        {activeTab === 'assess' && (
          <Card>
            <div className="flex flex-col items-center justify-center py-24 text-center">
              <div className="w-16 h-16 rounded-2xl bg-surface-2 flex items-center justify-center mb-5">
                <Shield className="w-8 h-8 text-text-muted" />
              </div>
              <p className="text-sm font-medium text-text-secondary mb-2">Coming Soon</p>
              <p className="text-[12px] text-text-muted max-w-sm">
                Software inventory and dependency scanning will be available in a future update.
              </p>
            </div>
          </Card>
        )}

        {/* ========== Tab: File Scan ========== */}
        {activeTab === 'scan' && (
          <div className="grid grid-cols-12 gap-6">
            {/* Left - Scan Controls & Results */}
            <div className="col-span-7 space-y-5">
              <Card>
                <CardHeader icon={FolderOpen} title="File System Scan" />
                <div className="p-5">
                  <p className="text-[12px] text-text-muted mb-4">
                    Scan the file system and classify all assets by risk level. Includes anti-spoofing detection and symlink defense.
                  </p>
                  <div className="flex gap-2">
                    <div className="relative flex-1">
                      <FolderOpen className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
                      <input
                        type="text"
                        value={scanPath}
                        onChange={(e) => setScanPath(e.target.value)}
                        placeholder="Scan path (leave empty for home directory)"
                        className="w-full pl-10 pr-4 py-2.5 bg-surface-0 border border-border rounded-lg text-[13px] text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-accent/30 focus:border-accent/50 transition-all"
                      />
                    </div>
                    <button
                      onClick={runScan}
                      disabled={scanning}
                      className="px-5 py-2.5 bg-accent text-white rounded-lg text-[13px] font-medium hover:bg-accent-dim disabled:opacity-40 transition-all flex items-center gap-2 shadow-lg shadow-accent/20"
                    >
                      {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                      {scanning ? 'Scanning...' : 'Start Scan'}
                    </button>
                  </div>
                </div>
              </Card>

              {scanning && (
                <Card>
                  <div className="p-6">
                    {/* Header */}
                    <div className="flex items-center gap-3 mb-5">
                      <div className="w-9 h-9 rounded-xl bg-accent/15 flex items-center justify-center">
                        <Loader2 className="w-5 h-5 text-accent animate-spin" />
                      </div>
                      <div>
                        <p className="text-sm font-semibold text-text-primary">Scanning in progress…</p>
                        <p className="text-[11px] text-text-muted">Classifying files by risk level</p>
                      </div>
                    </div>

                    {/* Animated indeterminate bar */}
                    <div className="w-full bg-surface-0 rounded-full h-2 overflow-hidden mb-4">
                      <div className="h-full rounded-full bg-gradient-to-r from-accent via-purple-400 to-accent bg-[length:200%_100%] animate-[shimmer_1.5s_linear_infinite]" />
                    </div>

                    {/* Live counters */}
                    <div className="flex items-center gap-6">
                      <div className="flex items-center gap-2">
                        <span className="relative flex h-2 w-2">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75" />
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-accent" />
                        </span>
                        <span className="text-[13px] text-text-secondary">
                          Scanned: <span className="font-bold text-text-primary tabular-nums">{scanProgress.scanned.toLocaleString()}</span>
                        </span>
                      </div>
                      <div className="text-[13px] text-text-secondary">
                        Ignored: <span className="font-semibold text-text-muted tabular-nums">{scanProgress.ignored.toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                </Card>
              )}

              {scanResult && !scanning && (
                <Card>
                  <CardHeader icon={Shield} title="Risk Distribution" />
                  <div className="divide-y divide-border">
                    {Object.entries(scanResult.risk_distribution).map(([key, dist]) => {
                      const level = parseInt(key.replace('LEVEL_', ''));
                      const config = riskConfig[level];
                      const isExpanded = expandedLevels.has(level);
                      const hasAssets = dist.assets && dist.assets.length > 0;
                      return (
                        <div key={key}>
                          {/* Level header — clickable */}
                          <button
                            className="w-full text-left px-5 py-4 hover:bg-surface-2/50 transition-colors"
                            onClick={() => hasAssets && toggleLevel(level)}
                          >
                            <div className="flex items-center justify-between mb-2">
                              <div className="flex items-center gap-2.5">
                                {hasAssets ? (
                                  isExpanded
                                    ? <ChevronDown className={`w-3.5 h-3.5 ${config.text}`} />
                                    : <ChevronRight className={`w-3.5 h-3.5 ${config.text}`} />
                                ) : (
                                  <span className={`w-2 h-2 rounded-full ${config.dot}`} />
                                )}
                                <span className="text-[13px] text-text-primary font-medium">{config.label}</span>
                              </div>
                              <div className="flex items-center gap-3">
                                <span className="text-[13px] text-text-secondary tabular-nums">{dist.count.toLocaleString()}</span>
                                <span className={`text-[12px] font-semibold tabular-nums ${config.text}`}>{dist.percentage}%</span>
                              </div>
                            </div>
                            <ProgressBar
                              percent={dist.percentage}
                              colorClass={level === 0 ? 'bg-red-500' : level === 1 ? 'bg-orange-500' : level === 2 ? 'bg-yellow-500' : 'bg-emerald-500'}
                            />
                          </button>

                          {/* Expanded file list */}
                          {isExpanded && hasAssets && (
                            <div className="bg-surface-0/60 border-t border-border">
                              {/* Table header */}
                              <div className="grid grid-cols-12 gap-2 px-5 py-2 text-[10px] uppercase tracking-wider text-text-muted font-semibold border-b border-border/50">
                                <div className="col-span-6">Path</div>
                                <div className="col-span-2">Type</div>
                                <div className="col-span-2">Size</div>
                                <div className="col-span-2">Permissions</div>
                              </div>
                              {/* File rows */}
                              <div className="max-h-[360px] overflow-y-auto">
                                {dist.assets.map((asset, idx) => (
                                  <div
                                    key={idx}
                                    className="grid grid-cols-12 gap-2 px-5 py-2 text-[12px] border-b border-border/30 last:border-b-0 hover:bg-surface-2/40 transition-colors"
                                  >
                                    <div className="col-span-6 flex items-center gap-1.5 min-w-0">
                                      {asset.file_type === 'directory'
                                        ? <FolderOpen className="w-3.5 h-3.5 text-accent flex-shrink-0" />
                                        : <FileText className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />}
                                      <span className="font-mono text-text-primary truncate" title={asset.path}>{asset.path}</span>
                                    </div>
                                    <div className="col-span-2 text-text-secondary capitalize">{asset.file_type}</div>
                                    <div className="col-span-2 text-text-secondary tabular-nums">{formatBytes(asset.size ?? asset.direct_size)}</div>
                                    <div className="col-span-2 font-mono text-text-muted">{asset.permissions ?? '—'}</div>
                                  </div>
                                ))}
                              </div>
                              {/* Footer: showing N of M */}
                              {dist.total_in_level > dist.assets.length && (
                                <div className="px-5 py-2 text-[11px] text-text-muted text-center border-t border-border/50">
                                  Showing {dist.assets.length} of {dist.total_in_level.toLocaleString()} items
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </Card>
              )}

              {!scanResult && !scanning && (
                <Card>
                  <div className="flex flex-col items-center justify-center py-20 text-center">
                    <div className="w-14 h-14 rounded-2xl bg-surface-2 flex items-center justify-center mb-4">
                      <Layers className="w-7 h-7 text-text-muted" />
                    </div>
                    <p className="text-sm font-medium text-text-secondary mb-1">No scan performed yet</p>
                    <p className="text-[12px] text-text-muted max-w-xs">Click Start Scan to begin file system scanning. Assets will be automatically classified by security level</p>
                  </div>
                </Card>
              )}
            </div>

            {/* Right - Summary */}
            <div className="col-span-5 space-y-5">
              <Card>
                <CardHeader icon={Shield} title="Summary" />
                <div className="p-5">
                  {scanResult ? (
                    <>
                      {/* Stats */}
                      <div className="space-y-2 mb-5">
                        <SummaryRow label="Total Assets" value={scanResult.total_assets.toLocaleString()} valueColor="text-accent" />
                        <SummaryRow label="Scanned" value={scanResult.total_scanned.toLocaleString()} />
                        <SummaryRow label="Ignored" value={scanResult.total_ignored.toLocaleString()} />
                      </div>

                      {/* Risk Breakdown */}
                      <div className="border-t border-border pt-4">
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted mb-3">Risk Breakdown</p>
                        <div className="space-y-3">
                          {Object.entries(scanResult.risk_distribution).map(([key, dist]) => {
                            const level = parseInt(key.replace('LEVEL_', ''));
                            const config = riskConfig[level];
                            return (
                              <button
                                key={key}
                                className="flex items-center gap-3 w-full text-left hover:bg-surface-2 rounded-md px-1 -mx-1 py-0.5 transition-colors"
                                onClick={() => dist.count > 0 && toggleLevel(level)}
                              >
                                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${config.dot}`} />
                                <span className="text-[13px] text-text-secondary flex-1">{config.shortLabel}</span>
                                <span className={`text-[13px] font-bold tabular-nums ${dist.count > 0 ? config.text : 'text-text-muted'}`}>
                                  {dist.count.toLocaleString()}
                                </span>
                                {dist.count > 0 && (
                                  expandedLevels.has(level)
                                    ? <ChevronDown className="w-3 h-3 text-text-muted" />
                                    : <ChevronRight className="w-3 h-3 text-text-muted" />
                                )}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="text-center py-8">
                      <Layers className="w-8 h-8 text-text-muted mx-auto mb-3" />
                      <p className="text-[12px] text-text-muted">Run a scan to see summary</p>
                    </div>
                  )}
                </div>
              </Card>
            </div>
          </div>
        )}

        {/* ========== Tab: Hardware ========== */}
        {activeTab === 'hardware' && (
          <div className="space-y-5">
            {/* Load / Refresh Button */}
            <div className="flex justify-end">
              <button
                onClick={loadHardware}
                disabled={hwLoading}
                className="px-4 py-2 bg-surface-1 border border-border text-text-secondary rounded-lg text-[13px] font-medium hover:bg-surface-2 hover:border-border-active disabled:opacity-40 transition-all flex items-center gap-2"
              >
                {hwLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                {hardware ? 'Refresh' : 'Load Hardware Info'}
              </button>
            </div>

            {hwLoading && (
              <Card>
                <div className="p-12 flex flex-col items-center justify-center">
                  <Loader2 className="w-8 h-8 text-accent animate-spin mb-3" />
                  <p className="text-sm text-text-secondary">Scanning hardware information...</p>
                </div>
              </Card>
            )}

            {!hardware && !hwLoading && (
              <Card>
                <div className="flex flex-col items-center justify-center py-20 text-center">
                  <div className="w-14 h-14 rounded-2xl bg-surface-2 flex items-center justify-center mb-4">
                    <Cpu className="w-7 h-7 text-text-muted" />
                  </div>
                  <p className="text-sm font-medium text-text-secondary mb-1">Click the button above to load hardware info</p>
                  <p className="text-[12px] text-text-muted max-w-xs">Retrieves detailed CPU, Memory, Disk, Network, and GPU information</p>
                </div>
              </Card>
            )}

            {hardware && !hwLoading && (
              <div className="grid grid-cols-12 gap-5">
                {/* System Info */}
                <div className="col-span-12">
                  <Card>
                    <CardHeader icon={Info} title="System Information" />
                    <div className="p-5">
                      <div className="grid grid-cols-4 gap-5">
                        {[
                          { label: 'Hostname', value: hardware.system_info.hostname },
                          { label: 'OS', value: `${hardware.system_info.os_name} ${hardware.system_info.os_release}` },
                          { label: 'Architecture', value: hardware.system_info.architecture },
                          { label: 'Uptime', value: formatUptime(hardware.system_info.uptime_seconds) },
                        ].map((item) => (
                          <div key={item.label} className="bg-surface-2 rounded-lg p-4">
                            <span className="text-[11px] text-text-muted uppercase tracking-wider">{item.label}</span>
                            <p className="text-[14px] font-semibold text-text-primary mt-1.5 truncate">{item.value}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </Card>
                </div>

                {/* CPU */}
                <div className="col-span-6">
                  <Card>
                    <CardHeader icon={Cpu} title="CPU" badge={
                      <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full ${hardware.cpu_info.usage_percent > 80 ? 'bg-red-500/15 text-red-400' : 'bg-accent/15 text-accent'}`}>
                        {hardware.cpu_info.usage_percent}%
                      </span>
                    } />
                    <div className="p-5">
                      <p className="text-[13px] font-medium text-text-primary mb-4 line-clamp-1">{hardware.cpu_info.model}</p>
                      <div className="grid grid-cols-2 gap-3 mb-4">
                        <div className="bg-surface-2 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold text-text-primary">{hardware.cpu_info.physical_cores}</p>
                          <p className="text-[10px] text-text-muted uppercase tracking-wider mt-1">Physical</p>
                        </div>
                        <div className="bg-surface-2 rounded-lg p-3 text-center">
                          <p className="text-xl font-bold text-text-primary">{hardware.cpu_info.logical_cores}</p>
                          <p className="text-[10px] text-text-muted uppercase tracking-wider mt-1">Logical</p>
                        </div>
                      </div>
                      <ProgressBar percent={hardware.cpu_info.usage_percent} colorClass={hardware.cpu_info.usage_percent > 80 ? 'bg-red-500' : 'bg-accent'} />
                    </div>
                  </Card>
                </div>

                {/* Memory */}
                <div className="col-span-6">
                  <Card>
                    <CardHeader icon={MemoryStick} title="Memory" badge={
                      <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full ${hardware.memory_info.usage_percent > 80 ? 'bg-red-500/15 text-red-400' : 'bg-emerald-500/15 text-emerald-400'}`}>
                        {hardware.memory_info.usage_percent}%
                      </span>
                    } />
                    <div className="p-5">
                      <div className="flex items-baseline gap-1 mb-4">
                        <span className="text-2xl font-bold text-text-primary">{hardware.memory_info.used_gb}</span>
                        <span className="text-[13px] text-text-muted">/ {hardware.memory_info.total_gb} GB</span>
                      </div>
                      <div className="grid grid-cols-3 gap-3 mb-4">
                        {[
                          { label: 'Total', value: `${hardware.memory_info.total_gb} GB` },
                          { label: 'Used', value: `${hardware.memory_info.used_gb} GB` },
                          { label: 'Free', value: `${hardware.memory_info.free_gb} GB` },
                        ].map(item => (
                          <div key={item.label} className="bg-surface-2 rounded-lg p-2.5 text-center">
                            <p className="text-[11px] text-text-muted">{item.label}</p>
                            <p className="text-sm font-semibold text-text-primary mt-0.5">{item.value}</p>
                          </div>
                        ))}
                      </div>
                      <ProgressBar percent={hardware.memory_info.usage_percent} colorClass={hardware.memory_info.usage_percent > 80 ? 'bg-red-500' : 'bg-emerald-500'} />
                    </div>
                  </Card>
                </div>

                {/* Disks */}
                <div className="col-span-12">
                  <Card>
                    <CardHeader icon={HardDrive} title="Disk Partitions" badge={
                      <span className="text-[11px] text-text-muted bg-surface-2 px-2 py-0.5 rounded-full">{hardware.disk_info.length}</span>
                    } />
                    <div className="divide-y divide-border">
                      {hardware.disk_info.map((disk, idx) => (
                        <div key={idx} className="px-5 py-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-3">
                              <code className="text-[12px] font-mono text-accent bg-accent/10 px-2 py-0.5 rounded">{disk.mountpoint}</code>
                              <span className="text-[11px] text-text-muted">{disk.device} · {disk.fstype}</span>
                            </div>
                            <span className={`text-[12px] font-bold tabular-nums ${disk.usage_percent > 90 ? 'text-red-400' : disk.usage_percent > 70 ? 'text-yellow-400' : 'text-text-secondary'}`}>
                              {disk.usage_percent}%
                            </span>
                          </div>
                          <div className="flex items-center gap-4 mb-2">
                            <span className="text-[12px] text-text-muted">Used {disk.used_gb} GB / {disk.total_gb} GB</span>
                            <span className="text-[12px] text-text-muted">Free {disk.free_gb} GB</span>
                          </div>
                          <ProgressBar
                            percent={disk.usage_percent}
                            colorClass={disk.usage_percent > 90 ? 'bg-red-500' : disk.usage_percent > 70 ? 'bg-yellow-500' : 'bg-accent'}
                          />
                        </div>
                      ))}
                    </div>
                  </Card>
                </div>

                {/* Network */}
                <div className="col-span-7">
                  <Card>
                    <CardHeader icon={Wifi} title="Network Interfaces" />
                    <div className="divide-y divide-border">
                      {hardware.network_info.filter(n => n.is_up).map((net, idx) => (
                        <div key={idx} className="px-5 py-3 flex items-center gap-3">
                          <span className="relative flex h-2 w-2 flex-shrink-0">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-success"></span>
                          </span>
                          <span className="text-[13px] font-medium text-text-primary flex-1">{net.interface}</span>
                          {net.speed_mbps > 0 && (
                            <span className="text-[11px] text-text-muted tabular-nums">{net.speed_mbps} Mbps</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </Card>
                </div>

                {/* GPU */}
                <div className="col-span-5">
                  <Card>
                    <CardHeader icon={Zap} title="GPU" badge={
                      hardware.gpu_info?.available
                        ? <span className="text-[10px] font-semibold bg-success/15 text-success px-2 py-0.5 rounded-full">Available</span>
                        : <span className="text-[10px] font-semibold bg-surface-2 text-text-muted px-2 py-0.5 rounded-full">N/A</span>
                    } />
                    <div className="p-5">
                      {hardware.gpu_info?.available ? (
                        <div className="space-y-2">
                          {hardware.gpu_info.gpus.map((gpu, idx) => (
                            <div key={idx} className="bg-surface-2 rounded-lg p-3">
                              <p className="text-[13px] font-medium text-text-primary">{gpu.name}</p>
                              <p className="text-[11px] text-text-muted mt-0.5">{gpu.vendor}</p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-center py-6">
                          <Zap className="w-8 h-8 text-text-muted mx-auto mb-2" />
                          <p className="text-[12px] text-text-muted">No GPU detected</p>
                        </div>
                      )}
                    </div>
                  </Card>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
