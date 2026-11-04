import * as React from "react"
import {
  Activity,
  ArrowDown,
  ArrowUp,
  CircleCheck,
  Gauge,
  type LucideIcon,
  Menu,
  Minus,
  Moon,
  RefreshCw,
  Route,
  ScrollText,
  Settings2,
  Shield,
  Sun,
  TriangleAlert,
  X,
  Zap,
} from "lucide-react"
import type { Lane, Node } from "@/lib/api"
import { cn, mbit, unit } from "@/lib/utils"
import { Badge, Button, Card, Corner, IconTile, type Tone } from "@/components/ui"
import { Sparkline } from "@/components/charts"

export type ViewId = "overview" | "lanes" | "traffic" | "security" | "logs" | "settings"
export const VIEWS: { id: ViewId; label: string; icon: LucideIcon; tone: Tone }[] = [
  { id: "overview", label: "Overview", icon: Gauge, tone: "blue" },
  { id: "lanes", label: "Lanes", icon: Route, tone: "yellow" },
  { id: "traffic", label: "Traffic", icon: Activity, tone: "green" },
  { id: "security", label: "Security", icon: Shield, tone: "red" },
  { id: "logs", label: "Logs", icon: ScrollText, tone: "plain" },
  { id: "settings", label: "Settings", icon: Settings2, tone: "plain" },
]

export type Health = "good" | "warn" | "bad"
export function health(n: Node): Health {
  if (n.offline) return "bad"
  const loss = Math.max(0, ...(n.links || []).map((l) => l.loss_pct || 0))
  if (loss > 5 || n.sys_cpu_pct > 92) return "warn"
  return "good"
}
export const healthColor = (h: Health) =>
  h === "bad" ? "var(--fill-red)" : h === "warn" ? "var(--fill-yellow)" : "var(--fill-green)"

/** A square chip, not a glowing dot — the theme has no soft edges. */
export function Dot({ color, size = 10 }: { color: string; size?: number }) {
  return (
    <span
      className="inline-block shrink-0 border-2 border-[var(--ink)]"
      style={{ width: size + 4, height: size + 4, background: color }}
    />
  )
}

/* ---------------- theme ---------------- */
export type Theme = "light" | "dark"
const KEY = "rakhsh-theme"

export function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, set] = React.useState<Theme>(() =>
    (localStorage.getItem(KEY) as Theme) || (document.documentElement.classList.contains("dark") ? "dark" : "light")
  )
  React.useEffect(() => {
    const root = document.documentElement
    root.classList.toggle("dark", theme === "dark")
    root.style.colorScheme = theme
    localStorage.setItem(KEY, theme)
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", theme === "dark" ? "#121212" : "#e7e2d6")
  }, [theme])
  return [theme, set]
}

export function ThemeToggle({ theme, setTheme }: { theme: Theme; setTheme: (t: Theme) => void }) {
  return (
    <button
      onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
      aria-label={theme === "dark" ? "Switch to light" : "Switch to dark"}
      className={cn(
        "nb-sm nb-press grid size-9 place-items-center [&>svg]:size-4 [&>svg]:stroke-[2.5]",
        theme === "dark" ? "bg-[var(--fill-yellow)] text-[var(--on-fill)]" : "bg-[var(--fill-red)] text-[#f8f4ec]"
      )}
    >
      {theme === "dark" ? <Sun /> : <Moon />}
    </button>
  )
}

/* ---------------- trend badge ---------------- */
export function TrendBadge({ value }: { value: number | null }) {
  if (value == null) return null
  const up = value > 4
  const dn = value < -4
  const Icon = up ? ArrowUp : dn ? ArrowDown : Minus
  return (
    <span
      className={cn(
        "ml-auto inline-flex items-center gap-0.5 border-2 border-[var(--ink)] px-1.5 py-px font-mono text-[10px] font-bold tabular",
        up ? "bg-[var(--fill-green)] text-[var(--on-fill)]" : dn ? "bg-[var(--fill-red)] text-[#f8f4ec]" : "bg-[var(--surface-2)]"
      )}
    >
      <Icon className="size-3 stroke-[3]" />
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
  tone = "ink",
  color = "var(--blue)",
  spark,
  trend,
}: {
  icon: LucideIcon
  label: string
  value: React.ReactNode
  u?: string
  sub?: React.ReactNode
  tone?: Tone
  color?: string
  spark?: number[]
  trend?: number | null
}) {
  return (
    <Card className="flex flex-col overflow-hidden">
      <div className="flex flex-col gap-3 p-3.5 pb-2">
        <div className="flex items-center gap-2.5">
          <IconTile tone={tone} size="sm">
            <Icon />
          </IconTile>
          <span className="font-mono text-[11px] font-bold uppercase tracking-[0.06em] text-muted-foreground">
            {label}
          </span>
          {trend !== undefined ? <TrendBadge value={trend ?? null} /> : null}
        </div>
        <div className="truncate">
          <span className="tabular text-[30px] font-extrabold leading-none tracking-tight">{value}</span>
          {u ? <span className="ml-1.5 font-mono text-xs font-bold text-muted-foreground">{u}</span> : null}
        </div>
        <div className="truncate font-mono text-[11px] text-muted-foreground">{sub}</div>
      </div>
      {spark ? (
        <div className="mt-auto h-10 border-t-[var(--b)] border-[var(--ink)] bg-[var(--surface-2)]">
          <Sparkline data={spark} color={color} height={40} />
        </div>
      ) : null}
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
    return (
      <span className="inline-flex border-2 border-[var(--ink)] px-2 py-0.5 font-mono text-[11px] text-muted-foreground">
        —
      </span>
    )
  const bad = value >= warn
  const mid = !bad && value >= good
  const Icon = bad || mid ? TriangleAlert : CircleCheck
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 border-2 border-[var(--ink)] px-2 py-0.5 font-mono text-[11px] font-bold tabular",
        bad
          ? "bg-[var(--fill-red)] text-[#f8f4ec]"
          : mid
            ? "bg-[var(--fill-yellow)] text-[var(--on-fill)]"
            : "bg-[var(--fill-green)] text-[var(--on-fill)]"
      )}
    >
      <Icon className="size-3 stroke-[2.5]" />
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
      {open ? <div className="fixed inset-0 z-30 bg-[var(--ink)]/60 lg:hidden" onClick={onClose} /> : null}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-[252px] flex-col border-r-[var(--b)] border-[var(--ink)] bg-[var(--surface)] transition-transform lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex h-16 items-center gap-2.5 border-b-[var(--b)] border-[var(--ink)] px-4">
          <IconTile tone="red">
            <Zap />
          </IconTile>
          <div className="min-w-0">
            <div className="font-mono text-[15px] font-extrabold leading-none tracking-tight">rakhsh</div>
            <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.18em] text-muted-foreground">
              Control Center
            </div>
          </div>
          <button className="ml-auto lg:hidden [&>svg]:size-5 [&>svg]:stroke-[2.5]" onClick={onClose} aria-label="Close menu">
            <X />
          </button>
        </div>

        <nav className="flex-1 space-y-2 overflow-y-auto p-3">
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
                  "nb-press flex w-full items-center gap-2.5 border-[var(--b)] px-2.5 py-2 text-left font-mono text-[12px] font-bold uppercase tracking-[0.05em]",
                  "[&>svg]:size-[17px] [&>svg]:shrink-0 [&>svg]:stroke-[2.5]",
                  active
                    ? "border-[var(--ink)] bg-[var(--ink)] text-[var(--on-ink)] shadow-[4px_4px_0_0_var(--ink)]"
                    : "border-transparent text-muted-foreground hover:border-[var(--ink)] hover:bg-[var(--surface-2)] hover:text-[var(--ink)]"
                )}
              >
                <Icon />
                {v.label}
                {badge != null ? <span className="ml-auto tabular text-[11px]">{badge}</span> : null}
              </button>
            )
          })}
        </nav>

        <div className="border-t-[var(--b)] border-[var(--ink)] p-3">
          <div className="px-0.5 pb-2 font-mono text-[9px] font-bold uppercase tracking-[0.18em] text-muted-foreground">
            Fleet · {nodes.length} nodes · {online} online
          </div>
          <div className="space-y-2">
            {nodes.map((n, i) => (
              <button
                key={n.name}
                onClick={() => setCur(i)}
                className={cn(
                  "nb-press flex w-full items-center gap-2.5 border-[var(--b)] px-2 py-1.5 text-left",
                  i === cur
                    ? "border-[var(--ink)] bg-[var(--surface-2)] shadow-[3px_3px_0_0_var(--ink)]"
                    : "border-transparent hover:border-[var(--ink)]"
                )}
              >
                <Dot color={healthColor(health(n))} size={8} />
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-[12px] font-bold">{n.name}</div>
                  <div className="font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">
                    {n.offline ? "offline" : n.role}
                  </div>
                </div>
                {!n.offline ? (
                  <div className="h-6 w-12 shrink-0">
                    <Sparkline data={(hist[n.name]?.down || []).slice(-20)} color="var(--blue)" height={24} />
                  </div>
                ) : null}
              </button>
            ))}
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
  theme,
  setTheme,
}: {
  title: string
  sub?: React.ReactNode
  updatedAt: number
  onRefresh: () => void
  onMenu: () => void
  theme: Theme
  setTheme: (t: Theme) => void
}) {
  const [, force] = React.useState(0)
  React.useEffect(() => {
    const t = setInterval(() => force((x) => x + 1), 1000)
    return () => clearInterval(t)
  }, [])
  const ago = updatedAt ? Math.max(0, Math.round((Date.now() - updatedAt) / 1000)) : null
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b-[var(--b)] border-[var(--ink)] bg-[var(--surface)] px-3 sm:px-5">
      <button
        className="nb-flat nb-press grid size-9 place-items-center lg:hidden [&>svg]:size-5 [&>svg]:stroke-[2.5]"
        onClick={onMenu}
        aria-label="Open menu"
      >
        <Menu />
      </button>
      <div className="min-w-0">
        <h1 className="truncate font-mono text-[19px] font-extrabold uppercase leading-none tracking-[0.02em]">
          {title}
        </h1>
        {sub ? <div className="mt-1.5 truncate font-mono text-[11px] text-muted-foreground">{sub}</div> : null}
      </div>
      <div className="ml-auto flex items-center gap-2">
        <Badge tone="outline" className="hidden sm:inline-flex">
          <span
            className="size-2 border border-[var(--ink)]"
            style={{ background: ago != null && ago < 6 ? "var(--fill-green)" : "var(--fill-yellow)" }}
          />
          {ago == null ? "—" : ago < 2 ? "live" : `${ago}s ago`}
        </Badge>
        <Button variant="secondary" size="icon" onClick={onRefresh} aria-label="Refresh">
          <RefreshCw />
        </Button>
        <ThemeToggle theme={theme} setTheme={setTheme} />
      </div>
    </header>
  )
}

/* ---------------- node header (hero) ---------------- */
export function NodeHeader({ n, right }: { n: Node; right?: React.ReactNode }) {
  return (
    <Card className="overflow-hidden">
      <span className="hidden sm:block">
        <Corner tone="blue" size={104} />
      </span>
      <div className="relative flex flex-wrap items-center gap-x-5 gap-y-3 p-4">
        <Dot color={healthColor(health(n))} size={14} />
        <div className="min-w-0">
          <div className="font-mono text-[26px] font-extrabold leading-none tracking-tight">
            {n.name || n.host}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[11px] text-muted-foreground">
            <span className="tabular">{n.host}</span>
            <span>·</span>
            <span>
              up <b className="tabular text-[var(--ink)]">{durShort(n.uptime_secs)}</b>
            </span>
            <span>·</span>
            <span className="tabular">PID {n.pid}</span>
            <span>·</span>
            <span className="tabular">v{n.version}</span>
          </div>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2 pr-0 sm:pr-[104px]">
          <Badge tone="primary">{n.role}</Badge>
          <Badge tone="secondary">{n.carrier}</Badge>
          {n.encryption === "full" ? <Badge tone="good">AES-256-GCM</Badge> : <Badge tone="bad">plaintext</Badge>}
          {n.resume ? <Badge tone="secondary">resume</Badge> : null}
          {right}
        </div>
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
          className="nb-sm nb-press flex items-center gap-3 bg-[var(--surface-2)] p-3 text-left"
        >
          <Dot color={healthColor(health(n))} />
          <div className="min-w-0 flex-1">
            <div className="truncate font-mono text-[13px] font-bold">{n.name}</div>
            <div className="truncate font-mono text-[10px] tabular text-muted-foreground">
              {n.offline
                ? "offline"
                : `${n.role} · ↓${mbit(n.rx_bps)} ↑${mbit(n.tx_bps)} ${unit(n.rx_bps)} · ${n.lanes_up}L`}
            </div>
          </div>
          <div className="h-7 w-16 shrink-0">
            <Sparkline data={(hist[n.name]?.down || []).slice(-24)} color="var(--blue)" height={28} />
          </div>
        </button>
      ))}
    </div>
  )
}

export function laneCarrierShort(_l: Lane) {
  return null
}
