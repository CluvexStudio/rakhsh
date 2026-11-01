import * as React from "react"
import {
  Activity,
  ArrowDown,
  ArrowUp,
  CircleCheck,
  Gauge,
  Layers,
  type LucideIcon,
  Menu,
  Minus,
  RefreshCw,
  Route,
  ScrollText,
  Settings2,
  Shield,
  TriangleAlert,
} from "lucide-react"
import type { Lane, Node } from "@/lib/api"
import { cn, mbit, unit } from "@/lib/utils"
import { Badge, Card } from "@/components/ui"
import { Sparkline } from "@/components/charts"

export type ViewId = "overview" | "lanes" | "traffic" | "security" | "logs" | "settings"
export const VIEWS: { id: ViewId; label: string; icon: LucideIcon }[] = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "lanes", label: "Lanes", icon: Route },
  { id: "traffic", label: "Traffic", icon: Activity },
  { id: "security", label: "Security", icon: Shield },
  { id: "logs", label: "Logs", icon: ScrollText },
  { id: "settings", label: "Settings", icon: Settings2 },
]

export type Health = "good" | "warn" | "bad"
export function health(n: Node): Health {
  if (n.offline) return "bad"
  const loss = Math.max(0, ...(n.links || []).map((l) => l.loss_pct || 0))
  if (loss > 5 || n.sys_cpu_pct > 92) return "warn"
  return "good"
}
export const healthColor = (h: Health) =>
  h === "bad" ? "var(--bad)" : h === "warn" ? "var(--warn)" : "var(--good)"

export function Dot({ color, size = 9 }: { color: string; size?: number }) {
  return (
    <span
      className="inline-block rounded-full shrink-0"
      style={{ width: size, height: size, background: color, boxShadow: `0 0 10px ${color}` }}
    />
  )
}

/* ---------------- trend badge ---------------- */
export function TrendBadge({ value }: { value: number | null }) {
  if (value == null) return null
  const up = value > 4
  const dn = value < -4
  const Icon = up ? ArrowUp : dn ? ArrowDown : Minus
  const color = up ? "var(--chart-2)" : dn ? "var(--bad)" : "var(--muted-foreground)"
  return (
    <span className="ml-auto inline-flex items-center gap-0.5 text-[11px] font-medium tabular" style={{ color }}>
      <Icon className="size-3" />
      {Math.abs(value).toFixed(0)}%
    </span>
  )
}

/* ---------------- KPI tile ---------------- */
export function Kpi({
  icon: Icon,
  label,
  value,
  u,
  sub,
  color = "var(--chart-1)",
  spark,
  trend,
}: {
  icon: LucideIcon
  label: string
  value: React.ReactNode
  u?: string
  sub?: React.ReactNode
  color?: string
  spark?: number[]
  trend?: number | null
}) {
  return (
    <Card className="flex flex-col overflow-hidden">
      <div className="flex flex-col gap-3 p-4 pb-2">
        <div className="flex items-center gap-2.5">
          <span
            className="grid size-7 place-items-center rounded-lg [&>svg]:size-4"
            style={{ background: `color-mix(in oklch, ${color} 16%, transparent)`, color }}
          >
            <Icon />
          </span>
          <span className="text-[11px] font-semibold uppercase tracking-[0.09em] text-muted-foreground">
            {label}
          </span>
          {trend !== undefined ? <TrendBadge value={trend ?? null} /> : null}
        </div>
        <div>
          <span className="tabular text-[28px] font-semibold leading-none tracking-tight">{value}</span>
          {u ? <span className="ml-1.5 text-sm font-medium text-muted-foreground">{u}</span> : null}
        </div>
        <div className="text-[11.5px] text-muted-foreground">{sub}</div>
      </div>
      <div className="h-10 px-1">{spark ? <Sparkline data={spark} color={color} height={40} /> : null}</div>
    </Card>
  )
}

/* ---------------- lane metric pill ---------------- */
export function Pill({
  value,
  u,
  good,
  warn,
}: {
  value: number | null
  u: string
  good: number
  warn: number
}) {
  if (value == null)
    return <span className="inline-flex rounded-md border border-[var(--border-strong)] px-2 py-0.5 text-xs text-muted-foreground">—</span>
  const tone = value >= warn ? "bad" : value >= good ? "warn" : ("good" as const)
  const color = tone === "bad" ? "var(--bad)" : tone === "warn" ? "var(--warn)" : "var(--good)"
  const Icon = tone === "good" ? CircleCheck : TriangleAlert
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium tabular"
      style={{ borderColor: `color-mix(in oklch, ${color} 28%, transparent)`, background: `color-mix(in oklch, ${color} 12%, transparent)`, color }}
    >
      <Icon className="size-3" />
      {value.toFixed(1)}
      {u}
    </span>
  )
}

/* ---------------- sidebar ---------------- */
export function Sidebar({
  view,
  setView,
  nodes,
  hist,
  cur,
  setCur,
  open,
  onClose,
}: {
  view: ViewId
  setView: (v: ViewId) => void
  nodes: Node[]
  hist: Record<string, { down: number[] }>
  cur: number
  setCur: (i: number) => void
  open: boolean
  onClose: () => void
}) {
  const online = nodes.filter((n) => !n.offline).length
  return (
    <>
      {open ? <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={onClose} /> : null}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-[248px] flex-col border-r border-border bg-background/80 backdrop-blur-xl transition-transform lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex items-center gap-2.5 px-5 h-16 border-b border-border/70">
          <span className="grid size-8 place-items-center rounded-lg bg-primary/15 text-primary [&>svg]:size-[18px]">
            <Gauge />
          </span>
          <div>
            <div className="text-[15px] font-semibold leading-none tracking-tight">rakhsh</div>
            <div className="text-[10px] uppercase tracking-[0.16em] text-muted-foreground mt-1">
              Control Center
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-1 p-3">
          {VIEWS.map((v) => {
            const active = v.id === view
            const Icon = v.icon
            const badge = v.id === "lanes" && nodes[cur] ? nodes[cur].lanes_up : null
            return (
              <button
                key={v.id}
                onClick={() => {
                  setView(v.id)
                  onClose()
                }}
                className={cn(
                  "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors [&>svg]:size-[17px]",
                  active
                    ? "bg-primary/12 text-foreground ring-1 ring-primary/25"
                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                )}
              >
                <Icon className={active ? "text-primary" : ""} />
                {v.label}
                {badge != null ? (
                  <span className="ml-auto text-[11px] text-muted-foreground tabular">{badge}</span>
                ) : null}
              </button>
            )
          })}
        </nav>

        <div className="p-3 border-t border-border/70">
          <div className="px-2 pb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            Fleet
          </div>
          <div className="space-y-1">
            {nodes.map((n, i) => (
              <button
                key={n.name}
                onClick={() => setCur(i)}
                className={cn(
                  "flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left transition-colors",
                  i === cur ? "bg-accent/50 ring-1 ring-border-strong" : "hover:bg-accent/40"
                )}
              >
                <Dot color={healthColor(health(n))} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] font-medium">{n.name}</div>
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    {n.offline ? "offline" : n.role}
                  </div>
                </div>
                {!n.offline ? (
                  <div className="w-12 h-6 opacity-80">
                    <Sparkline data={(hist[n.name]?.down || []).slice(-20)} color="var(--chart-1)" height={24} />
                  </div>
                ) : null}
              </button>
            ))}
          </div>
          <div className="px-2 pt-3 text-[11px] text-muted-foreground">
            {nodes.length} nodes · {online} online
          </div>
        </div>
      </aside>
    </>
  )
}

/* ---------------- topbar ---------------- */
export function Topbar({
  title,
  sub,
  updatedAt,
  onRefresh,
  onMenu,
}: {
  title: string
  sub?: React.ReactNode
  updatedAt: number
  onRefresh: () => void
  onMenu: () => void
}) {
  const [, force] = React.useState(0)
  React.useEffect(() => {
    const t = setInterval(() => force((x) => x + 1), 1000)
    return () => clearInterval(t)
  }, [])
  const ago = updatedAt ? Math.max(0, Math.round((Date.now() - updatedAt) / 1000)) : null
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-border/70 bg-background/70 px-4 backdrop-blur-xl sm:px-6">
      <button className="lg:hidden text-muted-foreground [&>svg]:size-5" onClick={onMenu}>
        <Menu />
      </button>
      <div className="min-w-0">
        <h1 className="text-lg font-semibold leading-none tracking-tight">{title}</h1>
        {sub ? <div className="mt-1 truncate text-xs text-muted-foreground">{sub}</div> : null}
      </div>
      <div className="ml-auto flex items-center gap-2">
        <Badge tone="outline" className="gap-1.5">
          <span className="size-1.5 rounded-full bg-[var(--good)]" />
          {ago == null ? "—" : ago < 2 ? "updated just now" : `updated ${ago}s ago`}
        </Badge>
        <button
          onClick={onRefresh}
          className="grid size-9 place-items-center rounded-lg border text-muted-foreground transition-colors hover:bg-accent/60 hover:text-foreground [&>svg]:size-4"
        >
          <RefreshCw />
        </button>
      </div>
    </header>
  )
}

/* ---------------- node header (hero) ---------------- */
export function NodeHeader({ n, right }: { n: Node; right?: React.ReactNode }) {
  return (
    <Card className="flex flex-wrap items-center gap-x-5 gap-y-3 p-5">
      <Dot color={healthColor(health(n))} size={12} />
      <div className="min-w-0">
        <div className="text-xl font-semibold leading-tight tracking-tight">{n.name || n.host}</div>
        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <Badge tone="primary" className="uppercase tracking-wide">
            {n.role}
          </Badge>
          <span className="tabular">{n.host}</span>
          <span>·</span>
          <span>
            up <b className="tabular font-medium text-foreground/80">{durShort(n.uptime_secs)}</b>
          </span>
          <span>·</span>
          <span className="tabular">PID {n.pid}</span>
          <span>·</span>
          <span className="tabular">v{n.version}</span>
        </div>
      </div>
      <div className="ml-auto flex flex-wrap items-center gap-2">
        {n.encryption === "full" ? (
          <Badge tone="good">AES-256-GCM</Badge>
        ) : (
          <Badge tone="warn">plaintext</Badge>
        )}
        {n.resume ? <Badge tone="secondary">resume</Badge> : null}
        <Badge tone="secondary">{n.carrier}</Badge>
        {right}
      </div>
    </Card>
  )
}

function durShort(s: number) {
  s = Math.floor(s || 0)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s / 3600) % 24)
  const m = Math.floor((s / 60) % 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

/* ---------------- fleet strip ---------------- */
export function FleetStrip({
  nodes,
  hist,
  onPick,
}: {
  nodes: Node[]
  hist: Record<string, { down: number[] }>
  onPick: (i: number) => void
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {nodes.map((n, i) => (
        <button
          key={n.name}
          onClick={() => onPick(i)}
          className="flex items-center gap-3 rounded-xl border bg-card/60 p-3.5 text-left transition-colors hover:border-border-strong hover:bg-accent/30"
        >
          <Dot color={healthColor(health(n))} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13.5px] font-medium">{n.name}</div>
            <div className="truncate text-[11px] text-muted-foreground tabular">
              {n.offline
                ? "offline"
                : `${n.role} · ↓${mbit(n.rx_bps)} ↑${mbit(n.tx_bps)} ${unit(n.rx_bps)} · ${n.lanes_up}L`}
            </div>
          </div>
          <div className="h-7 w-16 shrink-0">
            <Sparkline data={(hist[n.name]?.down || []).slice(-24)} color="var(--chart-1)" height={28} />
          </div>
        </button>
      ))}
    </div>
  )
}

export function laneCarrierShort(_l: Lane) {
  return null
}
