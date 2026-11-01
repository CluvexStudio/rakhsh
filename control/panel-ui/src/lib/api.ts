import { useCallback, useEffect, useRef, useState } from "react"

export interface Lane {
  id: number
  label: string
  up_secs: number
  rtt_ms: number | null
  jitter_ms: number
  loss_pct: number
}
export interface Quota {
  scope: string
  used: number
  limit: number
  pct: number
  resets: string
}
export interface ResumeStats {
  streams: number
  resent_chunks: number
}
export interface Node {
  name: string
  offline: boolean
  role: string
  host: string
  version: string
  pid: number | string
  carrier: string
  encryption: string
  resume: boolean
  uptime_secs: number
  target_lanes: number
  lanes_up: number
  lanes_established: number
  reconnects: number
  streams: number
  // role-aware (daemon maps): rx_* = download, tx_* = upload
  rx_bps: number
  tx_bps: number
  peak_rx_bps: number
  peak_tx_bps: number
  rx_total: number
  tx_total: number
  cpu_pct: number
  rss_mb: number
  sys_cpu_pct: number
  sys_mem_pct: number
  load: [number, number, number]
  resume_stats: ResumeStats | null
  quotas: Quota[]
  links: Lane[]
}

export interface NodeHistory {
  down: number[]
  up: number[]
  cpu: number[]
  mem: number[]
}
export type LaneHistory = Record<number, number[]>

const CAP = 120
const LANE_CAP = 48

// Module-level rolling history, persisted across renders.
export const HIST: Record<string, NodeHistory> = {}
export const LANEHIST: Record<string, LaneHistory> = {}

function record(nodes: Node[]) {
  for (const n of nodes) {
    const h = (HIST[n.name] ??= { down: [], up: [], cpu: [], mem: [] })
    h.down.push(n.rx_bps || 0)
    h.up.push(n.tx_bps || 0)
    h.cpu.push(n.sys_cpu_pct || 0)
    h.mem.push(n.sys_mem_pct || 0)
    if (h.down.length > CAP) {
      h.down.shift()
      h.up.shift()
      h.cpu.shift()
      h.mem.shift()
    }
    const lh = (LANEHIST[n.name] ??= {})
    const live = new Set<number>()
    for (const l of n.links || []) {
      live.add(l.id)
      const a = (lh[l.id] ??= [])
      a.push(l.rtt_ms ?? 0)
      if (a.length > LANE_CAP) a.shift()
    }
    for (const k of Object.keys(lh)) if (!live.has(+k)) delete lh[+k]
  }
}

// ---- auth ----
let TOKEN = ""
try {
  TOKEN = localStorage.getItem("rk_token") || ""
} catch {}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  return { Authorization: "Bearer " + TOKEN, ...(extra || {}) }
}

export async function login(password: string): Promise<boolean> {
  const r = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  })
  if (!r.ok) return false
  const j = await r.json()
  TOKEN = j.token || ""
  try {
    localStorage.setItem("rk_token", TOKEN)
  } catch {}
  return !!TOKEN
}
export function logout() {
  TOKEN = ""
  try {
    localStorage.removeItem("rk_token")
  } catch {}
}

export async function runAction(node: string, action: string) {
  const r = await fetch("/api/action", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ node, action }),
  })
  if (!r.ok) throw new Error((await r.text()) || "action failed")
}

export interface SpeedResult {
  down_mbit: number | null
  up_mbit: number | null
  via?: string
}
export async function speedtest(node: string): Promise<SpeedResult> {
  const r = await fetch("/api/speedtest", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ node }),
  })
  if (!r.ok) throw new Error((await r.text()) || "speed test failed")
  return r.json()
}

export interface LogLine {
  ts: string
  level: string
  msg: string
}
export async function fetchLogs(node: string): Promise<LogLine[]> {
  const r = await fetch("/api/logs?node=" + encodeURIComponent(node), { headers: authHeaders() })
  if (!r.ok) return []
  const j = await r.json()
  return (j.lines as LogLine[]) || []
}

export async function backupUrl(): Promise<void> {
  // The browser downloads it via a hidden anchor with the token in a query the server accepts,
  // but since we gate with a header we fetch + save as a blob.
  const r = await fetch("/api/backup", { headers: authHeaders() })
  if (!r.ok) throw new Error("backup failed")
  const blob = await r.blob()
  const a = document.createElement("a")
  a.href = URL.createObjectURL(blob)
  a.download = "rakhsh-configs-" + new Date().toISOString().slice(0, 10) + ".json"
  document.body.appendChild(a)
  a.click()
  a.remove()
}

export interface FleetState {
  nodes: Node[]
  updatedAt: number
  needsLogin: boolean
  error: string | null
  tick: number
}

export function hasToken() {
  return !!TOKEN
}

/** Poll /api/status every `refreshMs`, keeping rolling history. */
export function useFleet(refreshMs: number) {
  const [state, setState] = useState<FleetState>({
    nodes: [],
    updatedAt: 0,
    needsLogin: !TOKEN,
    error: null,
    tick: 0,
  })
  const timer = useRef<number | null>(null)

  const pull = useCallback(async () => {
    try {
      const r = await fetch("/api/status", { headers: authHeaders() })
      if (r.status === 401) {
        setState((s) => ({ ...s, needsLogin: true }))
        return
      }
      if (!r.ok) throw new Error("status " + r.status)
      const nodes: Node[] = await r.json()
      record(nodes)
      setState((s) => ({
        nodes,
        updatedAt: Date.now(),
        needsLogin: false,
        error: null,
        tick: s.tick + 1,
      }))
    } catch (e: any) {
      setState((s) => ({ ...s, error: String(e?.message || e) }))
    }
  }, [])

  useEffect(() => {
    pull()
    timer.current = window.setInterval(pull, refreshMs)
    return () => {
      if (timer.current) window.clearInterval(timer.current)
    }
  }, [pull, refreshMs])

  return { ...state, refresh: pull }
}
