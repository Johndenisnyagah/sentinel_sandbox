/**
 * Main Application component for Sentinel_Sandbox.
 * Manages global state, WebSocket lifecycle, and orchestration of SOC dashboard panels.
 */
import React, { useState, useEffect, useRef, useCallback } from 'react'
import axios from 'axios'

import Header from './components/Header'
import SystemStatus from './components/SystemStatus'
import NetworkActivity from './components/NetworkActivity'
import AlertsPanel from './components/AlertsPanel'
import ActivityFeed from './components/ActivityFeed'
import SimulationControls from './components/SimulationControls'
import RulesViewer from './components/RulesViewer'
import AlertModal from './components/AlertModal'

// Configuration for API and WebSocket URLs
// In production (Vercel), these will be set via Environment Variables
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const WS_URL = import.meta.env.VITE_WS_URL || (API_BASE_URL.replace('http', 'ws') + '/ws/alerts')

const App = () => {
  // ── Global Dashboard State ──
  const [alerts, setAlerts] = useState([])         // Security alerts history
  const [events, setEvents] = useState([])         // Granular activity feed entries
  const [status, setStatus] = useState(null)       // IDS telemetry (CPU, Status, etc.)
  const [trafficData, setTrafficData] = useState([]) // Data series for network chart
  const [topIPs, setTopIPs] = useState([])         // IP tracking table data
  const [activeSimulation, setActiveSimulation] = useState(null) // ID of running simulation
  const [selectedAlert, setSelectedAlert] = useState(null)       // Alert object for modal view

  // ── Refs for persistence without re-renders ──
  const ws = useRef(null)
  const reconnectTimeout = useRef(null)
  const ipTracker = useRef({}) // In-memory map for source IP frequency tracking
  const connectRef = useRef(null) // Latest connectWS, so the reconnect timer can call it

  /**
   * Appends a new event to the activity feed with a unique ID and timestamp.
   * Limits the feed to the last 50 events for performance.
   */
  const addEvent = useCallback((evt) => {
    setEvents(prev => [...prev.slice(-50), {
      id: Date.now() + Math.random(),
      ...evt,
      time: evt.time || new Date().toLocaleTimeString(),
    }])
  }, [])

  /**
   * Tracks frequency of source IPs seen in the network.
   * Flags IPs explicitly identified in security alerts.
   */
  const trackIP = useCallback((ip, flagged = false) => {
    if (!ip || ip === 'N/A' || ip === 'system') return
    const tracker = ipTracker.current
    if (!tracker[ip]) tracker[ip] = { count: 0, flagged: false }
    tracker[ip].count += 1
    if (flagged) tracker[ip].flagged = true
    
    // Convert to array and sort by frequency for the UI table
    const sorted = Object.entries(tracker)
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6)
    setTopIPs(sorted)
  }, [])

  /**
   * Establishes and manages the WebSocket lifecycle.
   * Handles real-time message routing to either alerts or activity feed.
   */
  const connectWS = useCallback(() => {
    if (ws.current) ws.current.close()
    ws.current = new WebSocket(WS_URL)

    ws.current.onopen = () => {
      addEvent({ event_type: 'info', details: 'Connected to Sentinel_Sandbox_Core', ip: 'system' })
    }

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        // Ignore heartbeat pulses
        if (data.type === 'pulse') return

        // Route message based on category
        if (data.category === 'alert') {
          setAlerts(prev => [data, ...prev])
          addEvent({ event_type: 'alert', details: `ALERT: ${data.type} from ${data.source_ip || data.ip}`, ip: data.source_ip || data.ip })
          trackIP(data.source_ip || data.ip, true)
        } else {
          addEvent(data)
          trackIP(data.ip)
        }
        
        // Push a data point to the traffic graph on every incoming event/pulse
        setTrafficData(prev => [...prev.slice(-20), {
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          packets: Math.floor(Math.random() * 30) + 5,
        }])
      } catch (e) {
        console.error('Failed to parse WS message', e)
      }
    }

    ws.current.onclose = () => {
      addEvent({ event_type: 'error', details: 'Disconnected. Retrying in 5s...', ip: 'system' })
      reconnectTimeout.current = setTimeout(() => connectRef.current?.(), 5000)
    }

    ws.current.onerror = () => {
      addEvent({ event_type: 'error', details: 'WebSocket transport error', ip: 'system' })
    }
  }, [addEvent, trackIP])
  useEffect(() => { connectRef.current = connectWS }, [connectWS])

  // ── Initial Data Fetch & Connection ──
  useEffect(() => {
    axios.get(`${API_BASE_URL}/alerts`).then(res => setAlerts(res.data)).catch(() => {})
    axios.get(`${API_BASE_URL}/status`).then(res => setStatus(res.data)).catch(() => {})
    connectWS()
    
    return () => {
      // Detach onclose first so unmounting does not schedule a reconnect
      if (ws.current) { ws.current.onclose = null; ws.current.close() }
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current)
    }
  }, [connectWS, addEvent])

  // ── Periodic System Status Polling ──
  useEffect(() => {
    const interval = setInterval(() => {
      axios.get(`${API_BASE_URL}/status`).then(res => setStatus(res.data)).catch(() => {})
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  // ── Background Network Noise Simulation (UI helper) ──
  useEffect(() => {
    const interval = setInterval(() => {
      setTrafficData(prev => [...prev.slice(-20), {
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        packets: Math.floor(Math.random() * (activeSimulation ? 80 : 20)) + 3,
      }])
    }, 2000)
    return () => clearInterval(interval)
  }, [activeSimulation])

  /**
   * Triggers a specific attack simulation via the backend API.
   * Manages local UI states for simulation progress.
   */
  const handleSimulate = async (type) => {
    if (activeSimulation) return
    setActiveSimulation(type)
    addEvent({ event_type: 'info', details: `Simulation initiated: ${type}`, ip: 'system' })
    
    try {
      await axios.post(`${API_BASE_URL}/simulate?attack_type=${type}`)
      // Brief cooldown before reset to ensure backend simulation finishes
      setTimeout(() => setActiveSimulation(null), 5000)
    } catch {
      addEvent({ event_type: 'error', details: `Simulation failed: ${type}`, ip: 'system' })
      setActiveSimulation(null)
    }
  }

  return (
    <div className="min-h-screen bg-bg-main text-text-primary font-mono p-4 md:p-8 overflow-x-hidden selection:bg-primary selection:text-white">
      <div className="max-w-[1400px] mx-auto">
        <Header />

        <main className="space-y-4">
          {/* Row 1 — Real-time Security Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
            <div className="md:col-span-3">
              <SystemStatus status={status} />
            </div>
            <div className="md:col-span-4">
              <NetworkActivity trafficData={trafficData} topIPs={topIPs} />
            </div>
            <div className="md:col-span-5">
              <AlertsPanel alerts={alerts} onAlertClick={setSelectedAlert} />
            </div>
          </div>

          {/* Row 2 — Activity Logs, Controls & Policies */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 md:h-[440px]">
            <ActivityFeed events={events} />
            <SimulationControls onSimulate={handleSimulate} activeSimulation={activeSimulation} />
            <RulesViewer />
          </div>
        </main>

        <footer className="mt-8 text-center text-[12px] text-text-muted tracking-[0.3em] uppercase">
          Sentinel_Sandbox // v2.0 // SOC Dashboard
        </footer>

        {/* Investigative View Overlay */}
        {selectedAlert && (
          <AlertModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
        )}
      </div>
    </div>
  )
}

export default App
