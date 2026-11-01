import * as React from "react"
import {
  Activity,
  ArrowDownToLine,
  CircleCheck,
  Clock,
  Cpu,
  Download,
  GitBranch,
  Globe,
  HardDrive,
  Layers,
  Lock,
  Play,
  Power,
  RotateCw,
  Route,
  ScrollText,
  Server,
  Shield,
  ShieldCheck,
  Square,
  Tag,
  Upload,
  Zap,
} from "lucide-react"
import {
  backupUrl,
  fetchLogs,
  type LogLine,
  type Node,
  runAction,
  speedtest,
  type SpeedResult,
} from "@/lib/api"
import {
  avg,
  bytes,
  clamp,
  dur,
  mbit,
  pctTone,
  rate,
  toneColor,
  trend,
  unit,
} from "@/lib/utils"
import { Badge, Button, Card, CardBody, CardHeader, Meter, Separator } from "@/components/ui"
import { AreaThroughput, Gauge, RttBars, Sparkline } from "@/components/charts"
import {
  Dot,
  FleetStrip,
  health,
  healthColor,
  Kpi,
  NodeHeader,
  Pill,
  type ViewId,
} from "@/components/app"

const BLUE = "var(--chart-1)"
const TEAL = "var(--chart-2)"
const VIOLET = "var(--chart-3)"
const AMBER = "var(--chart-4)"
const PINK = "var(--chart-5)"

function CarrierBadge({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-border-strong bg-secondary/40 px-2 py-0.5 text-xs font-medium tabular">
      <span className="size-1.5 rounded-full bg-primary/80" />
      {label}
    </span>
  )
}

function KV({ k, v }: { k: React.ReactNode; v: React.ReactNode }) {
  return (
    <div>
      <div className="text-[11px] text-muted-foreground">{k}</div>
      <div className="tabular mt-1 text-sm font-medium">{v}</div>
    </div>
  )
}

function Row({ icon, k, v }: { icon: React.ReactNode; k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3 py-2.5">
      <span className="text-muted-foreground [&>svg]:size-4">{icon}</span>
      <span className="text-sm text-muted-foreground">{k}</span>
      <span className="tabular ml-auto text-sm font-medium">{v}</span>
    </div>
  )
}

/* ====================== System card ====================== */
function SysCard({ n, cpuHist }: { n: Node; cpuHist: number[] }) {
  const cpuColor = toneColor(pctTone(n.sys_cpu_pct))
  const memColor = toneColor(pctTone(n.sys_mem_pct))
  const cores = navigator.hardwareConcurrency || 2
  const loadPct = clamp(((n.load?.[0] || 0) / cores) * 100, 0, 100)
  return (
    <Card>
      <CardHeader icon={<Cpu />} title="System" />
      <CardBody className="space-y-4">
        <div className="grid grid-cols-2 gap-2">
          <Gauge value={n.sys_cpu_pct} color={cpuColor} label="CPU" sub="system" />
          <Gauge value={n.sys_mem_pct} color={memColor} label="Memory" sub={`${n.rss_mb.toFixed(0)} MB`} />
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
            <span>CPU · last {cpuHist.length}s</span>
            <span className="tabular text-foreground/80">{n.sys_cpu_pct.toFixed(0)}%</span>
          </div>
          <div className="h-9">
            <Sparkline data={cpuHist} color={PINK} height={36} />
          </div>
        </div>
        <Meter label="Process CPU" value={`${n.cpu_pct.toFixed(1)}%`} pct={n.cpu_pct} color={VIOLET} />
        <Meter
          label="Load average"
          value={(n.load || [0, 0, 0]).map((l) => l.toFixed(2)).join("  ")}
          pct={loadPct}
          color={AMBER}
        />
      </CardBody>
    </Card>
  )
}

/* ====================== Lanes table ====================== */
function LanesTable({ n, laneHist }: { n: Node; laneHist: Record<number, number[]> }) {
  const links = n.links || []
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-[11px] uppercase tracking-wide text-muted-foreground">
            <th className="py-2 pl-5 font-medium">Lane</th>
            <th className="py-2 font-medium">Carrier</th>
            <th className="py-2 font-medium">Up</th>
            <th className="py-2 font-medium">RTT trend</th>
            <th className="py-2 font-medium">RTT</th>
            <th className="py-2 font-medium">Jitter</th>
            <th className="py-2 pr-5 font-medium">Loss</th>
          </tr>
        </thead>
        <tbody>
          {links.length === 0 ? (
            <tr>
              <td colSpan={7} className="py-10 text-center text-muted-foreground">
                no lanes up
              </td>
            </tr>
          ) : (
            links.map((l) => (
              <tr key={l.id} className="border-t border-border/60">
                <td className="py-2.5 pl-5 tabular text-muted-foreground">#{l.id}</td>
                <td className="py-2.5">
                  <CarrierBadge label={l.label} />
                </td>
                <td className="py-2.5 tabular text-muted-foreground">{dur(l.up_secs)}</td>
                <td className="py-2.5">
                  <div className="h-5 w-[72px]">
                    <Sparkline
                      data={(laneHist[l.id] || []).slice(-40)}
                      color={toneColor(l.rtt_ms != null && l.rtt_ms >= 150 ? (l.rtt_ms >= 300 ? "bad" : "warn") : "good")}
                      height={20}
                      kind="line"
                    />
                  </div>
                </td>
                <td className="py-2.5">
                  <Pill value={l.rtt_ms} u=" ms" good={150} warn={300} />
                </td>
                <td className="py-2.5">
                  <Pill value={l.jitter_ms} u=" ms" good={30} warn={80} />
                </td>
                <td className="py-2.5 pr-5">
                  <Pill value={l.loss_pct} u="%" good={1} warn={5} />
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

/* ====================== Transfer card ====================== */
function TransferCard({ n }: { n: Node }) {
  return (
    <Card>
      <CardHeader icon={<ArrowDownToLine />} title="Transfer" />
      <CardBody className="space-y-4">
        <div className="grid grid-cols-2 gap-x-5 gap-y-4">
          <KV k="Total download" v={bytes(n.rx_total)} />
          <KV k="Total upload" v={bytes(n.tx_total)} />
          <KV k="Peak download" v={rate(n.peak_rx_bps)} />
          <KV k="Peak upload" v={rate(n.peak_tx_bps)} />
          <KV k="Reconnects" v={n.reconnects} />
          <KV k="Lanes established" v={n.lanes_established} />
        </div>
        {n.resume_stats ? (
          <>
            <Separator />
            <Row
              icon={<GitBranch />}
              k="Resume"
              v={`${n.resume_stats.streams} live · ${n.resume_stats.resent_chunks} resent`}
            />
          </>
        ) : null}
        {(n.quotas || []).length ? (
          <div className="space-y-3 pt-1">
            {n.quotas.map((q) => (
              <Meter
                key={q.scope}
                label={
                  <span className="inline-flex items-center gap-1.5">
                    <Tag className="size-3" /> {q.scope}
                  </span>
                }
                value={`${bytes(q.used)} / ${bytes(q.limit)} · ${q.pct.toFixed(0)}%`}
                pct={q.pct}
                color={toneColor(pctTone(q.pct))}
              />
            ))}
          </div>
        ) : null}
      </CardBody>
    </Card>
  )
}

/* ====================== Node card ====================== */
function NodeCard({ n }: { n: Node }) {
  return (
    <Card>
      <CardHeader icon={<Server />} title="Node" />
      <CardBody className="divide-y divide-border/50">
        <Row icon={<Globe />} k="Host" v={n.host} />
        <Row icon={<Route />} k="Role" v={n.role} />
        <Row
          icon={<Lock />}
          k="Protection"
          v={
            <span className="inline-flex items-center gap-1.5">
              {n.encryption === "full" ? <Badge tone="good">AES-256-GCM</Badge> : <Badge tone="warn">plaintext</Badge>}
              {n.resume ? <Badge tone="secondary">resume</Badge> : null}
            </span>
          }
        />
        <Row icon={<Clock />} k="Uptime" v={dur(n.uptime_secs)} />
        <Row icon={<GitBranch />} k="Lanes established" v={`${n.lanes_established}`} />
        <Row icon={<Server />} k="Version / PID" v={`v${n.version} · ${n.pid}`} />
      </CardBody>
    </Card>
  )
}

/* ====================== Overview ====================== */
export function Overview({
  n,
  nodes,
  hist,
  laneHist,
  setCur,
  setView,
}: {
  n: Node
  nodes: Node[]
  hist: any
  laneHist: any
  setCur: (i: number) => void
  setView: (v: ViewId) => void
}) {
  const h = hist[n.name] || { down: [], up: [], cpu: [], mem: [] }
  const lh = laneHist[n.name] || {}
  const [sp, setSp] = React.useState<{ loading: boolean; r?: SpeedResult; err?: string }>({ loading: false })
  const runSpeed = async () => {
    setSp({ loading: true })
    try {
      setSp({ loading: false, r: await speedtest(n.name) })
    } catch (e: any) {
      setSp({ loading: false, err: String(e?.message || e) })
    }
  }

  const speedBtn = (
    <Button variant="default" size="sm" onClick={runSpeed} disabled={sp.loading}>
      <Zap /> {sp.loading ? "Testing…" : "Speed test"}
    </Button>
  )

  return (
    <div className="space-y-4">
      <NodeHeader
        n={n}
        right={
          <>
            {speedBtn}
            <Button variant="outline" size="sm" onClick={() => setView("logs")}>
              <ScrollText /> Logs
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <Kpi
          icon={Download}
          label="Download"
          value={mbit(n.rx_bps)}
          u={unit(n.rx_bps)}
          sub={`peak ${rate(n.peak_rx_bps)} · ${bytes(n.rx_total)}`}
          color={BLUE}
          spark={h.down.slice(-60)}
          trend={trend(h.down)}
        />
        <Kpi
          icon={Upload}
          label="Upload"
          value={mbit(n.tx_bps)}
          u={unit(n.tx_bps)}
          sub={`peak ${rate(n.peak_tx_bps)} · ${bytes(n.tx_total)}`}
          color={TEAL}
          spark={h.up.slice(-60)}
          trend={trend(h.up)}
        />
        <Kpi
          icon={Layers}
          label="Streams"
          value={n.streams}
          sub={`${n.resume ? "resume on" : "resume off"}${n.resume_stats ? ` · ${n.resume_stats.resent_chunks} resent` : ""}`}
          color={VIOLET}
        />
        <Kpi
          icon={GitBranch}
          label="Lanes"
          value={n.lanes_up}
          u={`/ ${n.target_lanes || n.lanes_up}`}
          sub={`${n.reconnects} reconnects · ${n.lanes_established} total`}
          color={AMBER}
        />
        <Kpi
          icon={Cpu}
          label="CPU"
          value={n.sys_cpu_pct.toFixed(0)}
          u="%"
          sub={`proc ${n.cpu_pct.toFixed(1)}% · load ${(n.load?.[0] || 0).toFixed(2)}`}
          color={PINK}
          spark={h.cpu.slice(-60)}
        />
        <Kpi
          icon={HardDrive}
          label="Memory"
          value={n.sys_mem_pct.toFixed(0)}
          u="%"
          sub={`${n.rss_mb.toFixed(0)} MB rss`}
          color={TEAL}
          spark={h.mem.slice(-60)}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.6fr_1fr]">
        <Card>
          <CardHeader
            icon={<Activity />}
            title="Throughput"
            right={
              <>
                <span className="text-[11.5px] text-muted-foreground">
                  avg ↓ <b className="tabular text-foreground/80">{rate(avg(h.down.slice(-60)))}</b>
                </span>
                <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                  <span className="inline-flex items-center gap-1.5">
                    <i className="size-2 rounded-full" style={{ background: BLUE }} /> Down
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <i className="size-2 rounded-full" style={{ background: TEAL }} /> Up
                  </span>
                </div>
                {speedBtn}
              </>
            }
          />
          <CardBody>
            <AreaThroughput down={h.down} up={h.up} height={288} />
            {sp.r || sp.err ? (
              <div className="mt-3 flex items-center gap-2 rounded-lg border bg-secondary/30 px-3 py-2 text-xs">
                <Zap className="size-3.5 text-primary" />
                {sp.err ? (
                  <span className="text-[var(--bad)]">{sp.err}</span>
                ) : (
                  <span className="tabular">
                    in-tunnel test · ↓ <b>{sp.r!.down_mbit != null ? sp.r!.down_mbit.toFixed(0) : "—"}</b> · ↑{" "}
                    <b>{sp.r!.up_mbit != null ? sp.r!.up_mbit.toFixed(0) : "—"}</b> Mb/s
                    {sp.r!.via ? <span className="text-muted-foreground"> · via {sp.r!.via}</span> : null}
                  </span>
                )}
              </div>
            ) : null}
          </CardBody>
        </Card>
        <SysCard n={n} cpuHist={h.cpu.slice(-60)} />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.6fr_1fr]">
        <Card>
          <CardHeader
            icon={<Route />}
            title="Lanes"
            sub={`${n.lanes_up} active`}
            right={
              <button
                onClick={() => setView("lanes")}
                className="text-xs font-medium text-primary hover:underline"
              >
                details →
              </button>
            }
          />
          <div className="pb-3">
            <LanesTable n={n} laneHist={lh} />
          </div>
        </Card>
        <div className="space-y-4">
          <TransferCard n={n} />
          <NodeCard n={n} />
        </div>
      </div>

      {nodes.length > 1 ? (
        <Card>
          <CardHeader icon={<Globe />} title="Fleet" />
          <CardBody>
            <FleetStrip nodes={nodes} hist={hist} onPick={setCur} />
          </CardBody>
        </Card>
      ) : null}
    </div>
  )
}

/* ====================== Lanes view ====================== */
function StatTile({
  icon,
  label,
  value,
  u,
  sub,
}: {
  icon: React.ReactNode
  label: string
  value: React.ReactNode
  u?: string
  sub?: React.ReactNode
}) {
  return (
    <Card>
      <CardBody className="p-5">
        <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.09em] text-muted-foreground [&>svg]:size-4">
          {icon}
          {label}
        </div>
        <div className="mt-3">
          <span className="tabular text-3xl font-semibold tracking-tight">{value}</span>
          {u ? <span className="ml-1 text-sm text-muted-foreground">{u}</span> : null}
        </div>
        {sub ? <div className="mt-2 text-xs text-muted-foreground">{sub}</div> : null}
      </CardBody>
    </Card>
  )
}

export function Lanes({ n, laneHist }: { n: Node; laneHist: any }) {
  const links = n.links || []
  const rtts = links.map((l) => l.rtt_ms).filter((x): x is number => x != null)
  const avgRtt = rtts.length ? avg(rtts) : 0
  const worstLoss = links.length ? Math.max(...links.map((l) => l.loss_pct)) : 0
  const lh = laneHist[n.name] || {}
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatTile icon={<Route />} label="Active lanes" value={n.lanes_up} u={`/ ${n.target_lanes || n.lanes_up}`} sub={`${n.lanes_established} established`} />
        <StatTile icon={<Clock />} label="Avg RTT" value={avgRtt.toFixed(0)} u="ms" sub={`across ${rtts.length} lanes`} />
        <StatTile icon={<Activity />} label="Worst loss" value={worstLoss.toFixed(1)} u="%" sub={worstLoss >= 5 ? "degraded" : "healthy"} />
        <StatTile icon={<RotateCw />} label="Reconnects" value={n.reconnects} sub="since start" />
      </div>
      <Card>
        <CardHeader icon={<Route />} title="All lanes" sub={`${n.lanes_up} active on ${n.name}`} />
        <div className="pb-3">
          <LanesTable n={n} laneHist={lh} />
        </div>
      </Card>
      {links.length ? (
        <Card>
          <CardHeader icon={<Activity />} title="Round-trip time by lane" />
          <CardBody>
            <RttBars lanes={links} />
          </CardBody>
        </Card>
      ) : null}
    </div>
  )
}

/* ====================== Traffic view ====================== */
export function Traffic({ n, nodes, hist }: { n: Node; nodes: Node[]; hist: any }) {
  const h = hist[n.name] || { down: [], up: [] }
  const maxRate = Math.max(1, ...nodes.flatMap((x) => [x.rx_bps, x.tx_bps]))
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatTile icon={<Download />} label="Download now" value={mbit(n.rx_bps)} u={unit(n.rx_bps)} sub={`peak ${rate(n.peak_rx_bps)}`} />
        <StatTile icon={<Upload />} label="Upload now" value={mbit(n.tx_bps)} u={unit(n.tx_bps)} sub={`peak ${rate(n.peak_tx_bps)}`} />
        <StatTile icon={<ArrowDownToLine />} label="Total down" value={bytes(n.rx_total)} sub="since start" />
        <StatTile icon={<ArrowDownToLine />} label="Total up" value={bytes(n.tx_total)} sub="since start" />
      </div>
      <Card>
        <CardHeader
          icon={<Activity />}
          title={`Throughput · ${n.name}`}
          right={
            <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <i className="size-2 rounded-full" style={{ background: BLUE }} /> Download
              </span>
              <span className="inline-flex items-center gap-1.5">
                <i className="size-2 rounded-full" style={{ background: TEAL }} /> Upload
              </span>
            </div>
          }
        />
        <CardBody>
          <AreaThroughput down={h.down} up={h.up} height={300} />
        </CardBody>
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader icon={<Globe />} title="Fleet throughput" />
          <CardBody className="space-y-5">
            {nodes.map((x) => (
              <div key={x.name} className="space-y-2">
                <div className="flex items-center gap-2">
                  <Dot color={healthColor(health(x))} />
                  <span className="text-sm font-medium">{x.name}</span>
                  <span className="text-[11px] uppercase tracking-wide text-muted-foreground">{x.role}</span>
                </div>
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2 text-xs">
                    <Download className="size-3 text-muted-foreground" />
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-secondary/70">
                      <div className="h-full rounded-full" style={{ width: (x.rx_bps / maxRate) * 100 + "%", background: BLUE }} />
                    </div>
                    <span className="tabular w-20 text-right text-muted-foreground">{rate(x.rx_bps)}</span>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <Upload className="size-3 text-muted-foreground" />
                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-secondary/70">
                      <div className="h-full rounded-full" style={{ width: (x.tx_bps / maxRate) * 100 + "%", background: TEAL }} />
                    </div>
                    <span className="tabular w-20 text-right text-muted-foreground">{rate(x.tx_bps)}</span>
                  </div>
                </div>
              </div>
            ))}
          </CardBody>
        </Card>
        <Card>
          <CardHeader icon={<Tag />} title="Quotas" />
          <CardBody className="space-y-5">
            {nodes.flatMap((x) =>
              (x.quotas || []).map((q) => (
                <Meter
                  key={x.name + q.scope}
                  label={`${x.name} · ${q.scope}`}
                  value={`${bytes(q.used)} / ${bytes(q.limit)} · ${q.pct.toFixed(0)}%`}
                  pct={q.pct}
                  color={toneColor(pctTone(q.pct))}
                />
              ))
            )}
            {nodes.every((x) => !(x.quotas || []).length) ? (
              <div className="py-6 text-center text-sm text-muted-foreground">no quotas configured</div>
            ) : null}
          </CardBody>
        </Card>
      </div>
    </div>
  )
}

/* ====================== Security view ====================== */
export function Security({ nodes }: { nodes: Node[] }) {
  const allEnc = nodes.every((n) => n.encryption === "full")
  const points = [
    ["Mutual authentication", "Every lane starts with a Noise IKpsk2 handshake — both ends pin the other's static key and mix in a shared token; the dial target travels inside the session."],
    ["Encryption by default", 'encryption = "full" puts AES-256-GCM on every record, safe even through a CDN. "none" sends records as-is (like BackPack\'s tcp) for traffic already encrypted end-to-end.'],
    ["Replay-safe", "A recorded handshake cannot open a plaintext lane — the responder demands a key confirmation first."],
    ["Bound settings", "Encryption and resume modes are bound into the handshake transcript, so mismatched ends simply fail to connect — there is nothing to downgrade."],
  ]
  return (
    <div className="space-y-4">
      <Card className="overflow-hidden">
        <CardBody className="flex items-center gap-4 p-6">
          <span
            className="grid size-12 shrink-0 place-items-center rounded-xl [&>svg]:size-6"
            style={{ background: `color-mix(in oklch, var(--good) 15%, transparent)`, color: "var(--good)" }}
          >
            <ShieldCheck />
          </span>
          <div>
            <div className="text-lg font-semibold">{allEnc ? "All lanes encrypted" : "Mixed encryption"}</div>
            <div className="text-sm text-muted-foreground">
              {allEnc
                ? "Every node runs AES-256-GCM on the wire, authenticated with pinned Noise keys."
                : "Some nodes send plaintext after the handshake — only safe for already-encrypted traffic."}
            </div>
          </div>
        </CardBody>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        {nodes.map((n) => (
          <Card key={n.name}>
            <CardBody className="flex items-center gap-4 p-5">
              <span
                className="grid size-11 shrink-0 place-items-center rounded-xl [&>svg]:size-5"
                style={{
                  background: `color-mix(in oklch, ${n.encryption === "full" ? "var(--good)" : "var(--warn)"} 14%, transparent)`,
                  color: n.encryption === "full" ? "var(--good)" : "var(--warn)",
                }}
              >
                <Lock />
              </span>
              <div className="min-w-0">
                <div className="font-semibold">{n.name}</div>
                <div className="text-xs text-muted-foreground tabular">
                  {n.role} · {n.carrier} · {n.host}
                </div>
                <div className="mt-2 flex gap-2">
                  {n.encryption === "full" ? <Badge tone="good">AES-256-GCM</Badge> : <Badge tone="warn">plaintext</Badge>}
                  {n.resume ? <Badge tone="secondary">resume</Badge> : null}
                </div>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader icon={<Shield />} title="How rakhsh secures the wire" />
        <CardBody className="divide-y divide-border/50">
          {points.map(([t, d]) => (
            <div key={t} className="flex gap-3 py-3.5">
              <CircleCheck className="mt-0.5 size-4 shrink-0 text-[var(--good)]" />
              <div>
                <span className="font-medium">{t}.</span>{" "}
                <span className="text-sm text-muted-foreground">{d}</span>
              </div>
            </div>
          ))}
        </CardBody>
      </Card>
    </div>
  )
}

/* ====================== Logs view ====================== */
export function Logs({ n }: { n: Node }) {
  const [lines, setLines] = React.useState<LogLine[]>([])
  const [auto, setAuto] = React.useState(true)
  React.useEffect(() => {
    let alive = true
    const load = async () => {
      const l = await fetchLogs(n.name)
      if (alive) setLines(l)
    }
    load()
    if (!auto) return () => { alive = false }
    const t = setInterval(load, 4000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [n.name, auto])
  const color = (lv: string) => (lv === "err" ? "var(--bad)" : lv === "warn" ? "var(--warn)" : "var(--chart-1)")
  return (
    <Card>
      <CardHeader
        icon={<ScrollText />}
        title="Service logs"
        sub={n.name}
        right={
          <button
            onClick={() => setAuto((a) => !a)}
            className="inline-flex items-center gap-2 rounded-md border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground"
          >
            <span className={`size-1.5 rounded-full ${auto ? "bg-[var(--good)]" : "bg-muted-foreground"}`} />
            {auto ? "auto" : "paused"}
          </button>
        }
      />
      <CardBody>
        <div className="max-h-[70vh] overflow-auto rounded-lg border border-border/60 bg-[oklch(0.14_0.01_260)] p-3 font-mono text-[12.5px] leading-6">
          {lines.length === 0 ? (
            <div className="py-10 text-center text-muted-foreground">no log lines</div>
          ) : (
            lines.map((l, i) => (
              <div key={i} className="flex gap-3 whitespace-pre-wrap">
                <span className="shrink-0 tabular text-muted-foreground/70">{l.ts}</span>
                <span className="w-10 shrink-0 font-semibold" style={{ color: color(l.level) }}>
                  {l.level.toUpperCase()}
                </span>
                <span className="text-foreground/90">{l.msg}</span>
              </div>
            ))
          )}
        </div>
      </CardBody>
    </Card>
  )
}

/* ====================== Settings view ====================== */
export function Settings({ nodes, onToast }: { nodes: Node[]; onToast: (ok: boolean, msg: string) => void }) {
  const [busy, setBusy] = React.useState<string | null>(null)
  const act = async (node: string, action: string) => {
    setBusy(node + action)
    try {
      await runAction(node, action)
      onToast(true, `${action} sent to ${node}`)
    } catch (e: any) {
      onToast(false, `${node}: ${e?.message || e}`)
    } finally {
      setBusy(null)
    }
  }
  const [backing, setBacking] = React.useState(false)
  const backup = async () => {
    setBacking(true)
    try {
      await backupUrl()
      onToast(true, "configs downloaded")
    } catch (e: any) {
      onToast(false, String(e?.message || e))
    } finally {
      setBacking(false)
    }
  }
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          icon={<Server />}
          title="Fleet"
          right={
            <Button variant="outline" size="sm" onClick={backup} disabled={backing}>
              <Download /> {backing ? "…" : "Backup configs"}
            </Button>
          }
        />
        <CardBody className="divide-y divide-border/50">
          {nodes.map((n) => (
            <div key={n.name} className="flex flex-wrap items-center gap-3 py-3.5">
              <Dot color={healthColor(health(n))} />
              <div className="min-w-0">
                <div className="font-medium">{n.name}</div>
                <div className="text-xs text-muted-foreground tabular">
                  {n.role} · {n.host} · {n.offline ? "offline" : `up ${dur(n.uptime_secs)}`}
                </div>
              </div>
              <div className="ml-auto flex gap-2">
                <Button size="sm" variant="secondary" onClick={() => act(n.name, "restart")} disabled={busy === n.name + "restart"}>
                  <RotateCw /> Restart
                </Button>
                <Button size="sm" variant="destructive" onClick={() => act(n.name, "stop")} disabled={busy === n.name + "stop"}>
                  <Square /> Stop
                </Button>
                <Button size="sm" variant="outline" onClick={() => act(n.name, "start")} disabled={busy === n.name + "start"}>
                  <Play /> Start
                </Button>
              </div>
            </div>
          ))}
        </CardBody>
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader icon={<Power />} title="Control center" />
          <CardBody className="divide-y divide-border/50">
            <Row icon={<Globe />} k="Address" v={location.host || "—"} />
            <Row icon={<Activity />} k="Live refresh" v="polling" />
            <Row icon={<Server />} k="Nodes" v={nodes.length} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader icon={<Shield />} title="About actions" />
          <CardBody className="space-y-3 text-sm text-muted-foreground">
            <div className="flex gap-2.5">
              <CircleCheck className="mt-0.5 size-4 shrink-0 text-[var(--good)]" />
              <span>
                <b className="text-foreground">Restart / Stop / Start</b> run <code className="rounded bg-secondary/60 px-1">systemctl</code> on the node over SSH (or locally). They need the daemon installed as a service.
              </span>
            </div>
            <div className="flex gap-2.5">
              <CircleCheck className="mt-0.5 size-4 shrink-0 text-[var(--good)]" />
              <span>
                Add or remove nodes by editing <code className="rounded bg-secondary/60 px-1">control.toml</code> and restarting the control center.
              </span>
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  )
}

/* ====================== Login ====================== */
export function Login({ onLogin }: { onLogin: (pw: string) => Promise<boolean> }) {
  const [pw, setPw] = React.useState("")
  const [err, setErr] = React.useState("")
  const [busy, setBusy] = React.useState(false)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr("")
    const ok = await onLogin(pw).catch(() => false)
    setBusy(false)
    if (!ok) setErr("Wrong password, or the server is unreachable.")
  }
  return (
    <div className="app-bg grid min-h-screen place-items-center p-4">
      <Card className="w-full max-w-sm">
        <CardBody className="p-7">
          <div className="mb-5 flex flex-col items-center text-center">
            <span className="mb-3 grid size-12 place-items-center rounded-xl bg-primary/15 text-primary [&>svg]:size-6">
              <Shield />
            </span>
            <div className="text-lg font-semibold">rakhsh Control Center</div>
            <div className="text-sm text-muted-foreground">Sign in to manage the fleet</div>
          </div>
          <form onSubmit={submit} className="space-y-3">
            <input
              type="password"
              autoFocus
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              placeholder="Panel password"
              className="h-10 w-full rounded-lg border bg-input/40 px-3 text-sm outline-none focus:ring-2 focus:ring-ring/60"
            />
            {err ? <div className="text-xs text-[var(--bad)]">{err}</div> : null}
            <Button type="submit" variant="default" size="md" className="w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </CardBody>
      </Card>
    </div>
  )
}
