/**
 * ActivityFeed component.
 * Displays a real-time, auto-scrolling log of system events and alerts.
 * Uses a monospace font for a technical "low-level log" aesthetic.
 */
import React, { useRef, useEffect } from 'react';
import { ScrollText } from 'lucide-react';

// Semantic color mapping for different event types
const typeColors = {
  failed_login: 'text-severity-high',
  connection_attempt: 'text-severity-critical',
  traffic_burst: 'text-severity-medium',
  syn_burst: 'text-severity-critical',
  suspicious_query: 'text-severity-high',
  alert: 'text-severity-critical font-bold uppercase',
  info: 'text-text-secondary',
  success: 'text-primary',
  error: 'text-severity-critical',
};

const ActivityFeed = ({ events }) => {
  const feedRef = useRef(null);

  /**
   * Auto-scroll effect:
   * Ensures the latest events are always visible by scrolling to the bottom
   * whenever the events array is updated.
   */
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [events]);

  return (
    <div className="cyber-panel h-full flex flex-col">
      {/* Panel Header */}
      <div className="flex items-center gap-2 mb-3">
        <div className="flex items-center gap-2">
          <ScrollText className="text-primary w-4 h-4" />
          <h2 className="text-[13px] font-bold text-text-primary uppercase tracking-wider">Activity Feed</h2>
        </div>
        <span className="ml-auto text-[11px] text-text-muted">{events.length} entries</span>
      </div>

      {/* Log Container */}
      <div
        ref={feedRef}
        className="flex-grow overflow-y-auto font-mono text-[12px] space-y-1 custom-scrollbar scroll-smooth"
      >
        {/* Empty State */}
        {events.length === 0 && (
          <div className="text-text-muted italic text-center py-8 border border-dashed border-border-light m-2">
            Waiting for system activity...
          </div>
        )}

        {/* Event List */}
        {events.map((evt, i) => {
          const colorClass = typeColors[evt.event_type] || typeColors[evt.type] || 'text-text-secondary';
          return (
            <div 
              key={evt.id || i} 
              // 'feed-row' class in index.css handles the subtle hover highlight
              className="feed-row flex gap-2 leading-relaxed px-1.5 py-0.5 rounded transition-colors"
            >
              <span className="text-text-muted shrink-0 select-none">[{evt.time || evt.timestamp}]</span>
              <span className={`${colorClass} break-all`}>
                {evt.details || evt.text || `${evt.event_type}: ${evt.ip}`}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ActivityFeed;
