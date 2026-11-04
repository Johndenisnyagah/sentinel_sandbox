/**
 * SimulationControls component.
 * Provides interactive buttons to trigger synthetic security threats for 
 * The backend emits events only; the rule engine decides whether they alert.
 */
import React from 'react';
import { Zap, Terminal, Globe, Activity, Loader, ArrowRight, ShieldAlert } from 'lucide-react';

// Definitions for available attack simulations
const simulations = [
  { 
    id: 'BRUTE_FORCE', 
    label: 'Simulate Brute Force', 
    icon: Terminal, 
    desc: 'Rapid failed login attempts' 
  },
  { 
    id: 'PORT_SCAN', 
    label: 'Simulate Port Scan', 
    icon: Globe, 
    desc: 'Sequential probes on multiple ports' 
  },
  { 
    id: 'TRAFFIC_FLOOD', 
    label: 'Simulate Traffic Spike', 
    icon: Activity, 
    desc: 'High-volume synthetic packet bursts' 
  },
  { 
    id: 'DDOS', 
    label: 'Simulate SYN Flood', 
    icon: Zap, 
    desc: 'Rapid SYN bursts at web ports' 
  },
  { 
    id: 'SQLI', 
    label: 'Simulate SQLi Probe', 
    icon: ShieldAlert, 
    desc: 'Malicious query pattern injection' 
  },
];

const SimulationControls = ({ onSimulate, activeSimulation }) => {
  return (
    <div className="cyber-panel h-full flex flex-col">
      {/* Panel Header */}
      <div className="flex items-center gap-2 mb-4">
        <Zap className="text-primary w-4 h-4" />
        <h2 className="text-[13px] font-bold text-text-primary uppercase tracking-wider">Attack Simulation</h2>
      </div>

      {/* Simulation Button List */}
      <div className="space-y-2 flex-grow">
        {simulations.map(sim => {
          const isActive = activeSimulation === sim.id;
          return (
            <button
              key={sim.id}
              onClick={() => onSimulate(sim.id)}
              disabled={!!activeSimulation} // Disable all while one is running
              // 'sim-btn' class in index.css provides the premium shimmer effect on hover
              className={`sim-btn w-full border py-2.5 px-3 text-[12px] flex items-center gap-3 group transition-all
                ${isActive
                   ? 'border-primary bg-primary text-white shadow-lg shadow-primary/20 scale-[0.98]'
                  : 'border-border bg-bg-card disabled:opacity-40 text-text-primary'
                }`}
            >
              {/* Status Icon or Spinner */}
              {isActive ? (
                <Loader size={12} className="animate-spin" />
              ) : (
                <sim.icon size={12} className="text-primary group-hover:scale-110 transition-transform" />
              )}

              {/* Simulation Label & Info */}
              <div className="text-left flex-grow">
                <div className="font-bold uppercase tracking-tight">{sim.label}</div>
                <div className={`text-[10px] mt-0.5 ${isActive ? 'text-white/70' : 'text-text-muted'}`}>
                  {sim.desc}
                </div>
              </div>

              {/* Animated Arrow on Hover */}
              <ArrowRight 
                size={12} 
                className={`${isActive ? 'text-white' : 'text-primary'} opacity-0 group-hover:opacity-100 group-hover:translate-x-1 transition-all`} 
              />
            </button>
          );
        })}
      </div>

      {/* Progress Indicator */}
      {activeSimulation && (
        <div className="mt-4 pt-3 border-t border-border-light text-[11px] text-primary text-center font-bold tracking-[0.2em] animate-pulse">
          EXECUTING {activeSimulation}...
        </div>
      )}
    </div>
  );
};

export default SimulationControls;
