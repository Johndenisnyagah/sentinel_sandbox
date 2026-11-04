/**
 * NetworkActivity component.
 * Displays a real-time Area chart of packet volume and a list of the 
 * most active source IP addresses detected by the IDS.
 */
import React from 'react';
import { BarChart3 } from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';

const NetworkActivity = ({ trafficData, topIPs }) => {
  return (
    <div className="cyber-panel h-full flex flex-col">
      {/* Header with Live Indicator */}
      <div className="flex items-center gap-2 mb-4">
        <BarChart3 className="text-primary w-4 h-4" />
        <h2 className="text-[13px] font-bold text-text-primary uppercase tracking-wider">Network Activity</h2>
        <span className="ml-auto tag tag-primary">LIVE</span>
      </div>

      {/* Events received per 2 s (Recharts) */}
      <div className="text-[10px] text-text-muted mb-1">Events received per 2 s</div>
      <div className="h-[120px] w-full mb-3">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={trafficData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e8e8e8" vertical={false} />
            <XAxis dataKey="time" hide />
            <YAxis stroke="#ccc" fontSize={10} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#fff', border: '1px solid #e8650a', fontSize: '11px', borderRadius: '0' }}
              itemStyle={{ color: '#e8650a' }}
            />
            <Area 
              type="monotone" 
              dataKey="events"
              name="Events" 
              stroke="#e8650a" 
              fill="#e8650a15" 
              strokeWidth={1.5} 
              isAnimationActive={false} // Disabled for smoother real-time streaming feel
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Top Source IP Tracker Section */}
      <div className="flex-grow overflow-y-auto mt-2">
        <div className="text-[11px] text-text-muted uppercase mb-2 tracking-widest">Top Source IPs</div>
        <div className="space-y-1.5">
          {topIPs.length === 0 && (
            <div className="text-[9px] text-text-muted italic">No activity yet</div>
          )}
          {topIPs.map((ip, i) => (
            <div key={i} className="flex justify-between items-center text-[12px]">
              <span className="text-text-secondary font-mono">{ip.ip}</span>
              <div className="flex items-center gap-2">
                <span className="text-text-primary font-bold">{ip.count} req</span>
                {/* Visual badge for IPs involved in confirmed alerts */}
                {ip.flagged && (
                  <span className="tag tag-primary text-[9px] px-1.5 py-0.5 shadow-sm border-primary/20">FLAGGED</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default NetworkActivity;
