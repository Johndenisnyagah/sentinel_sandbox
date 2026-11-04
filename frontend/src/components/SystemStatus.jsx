/**
 * SystemStatus component.
 * Visualizes real-time telemetry from the IDS engine including CPU usage,
 * monitored packet counts, and alert totals.
 */
import React from 'react';
import { Shield } from 'lucide-react';

const SystemStatus = ({ status }) => {
  // Backend reachable and reporting
  const isRunning = status?.ids_running;
  // Live Scapy/psutil monitor is opt-in (needs root); simulations work without it
  const liveMonitor = status?.live_monitor;

  // Formatting metrics for the vertical list display
  const metrics = [
    { label: 'IDS Engine', value: isRunning ? 'RUNNING' : 'STOPPED', highlight: isRunning },
    { label: 'Live Monitor', value: status ? (liveMonitor ? 'ON' : 'OFF') : '—', highlight: liveMonitor },
    { label: 'Packets Monitored', value: status?.packets_monitored?.toLocaleString() ?? '—' },
    { label: 'Alerts Triggered', value: status?.alerts_triggered ?? '—' },
    { label: 'Active Connections', value: status?.active_connections ?? '—' },
    { label: 'CPU Usage', value: status?.cpu_usage != null ? `${Math.round(status.cpu_usage)}%` : '—' },
    { label: 'Simulations Run', value: status?.simulations_run ?? '—' },
  ];

  return (
    <div className="cyber-panel h-full">
      {/* Panel Header */}
      <div className="flex items-center gap-2 mb-4">
        <Shield className="text-primary w-4 h-4" />
        <h2 className="text-[13px] font-bold text-text-primary uppercase tracking-wider">System Status</h2>
        {/* Real-time status indicator dot */}
        <span className={`ml-auto w-2 h-2 rounded-full ${isRunning ? 'bg-primary pulse-dot' : 'bg-severity-critical'}`}></span>
      </div>

      {/* Metrics List */}
      <div className="space-y-3">
        {metrics.map(m => (
          <div key={m.label} className="flex justify-between items-center text-[12px]">
            <span className="text-text-secondary">{m.label}</span>
            <span className={`font-bold tracking-wider ${
              m.highlight ? 'text-primary' : 'text-text-primary'
            }`}>
              {m.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SystemStatus;
