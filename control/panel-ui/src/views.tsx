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
import { avg, bytes, clamp, dur, mbit, pctTone, rate, toneColor, trend, unit } from "@/lib/utils"
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  IconTile,
  Meter,
  PctBlock,
  Segmented,
  Separator,
  Stat,
  type Tone,
} from "@/components/ui"
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

const BLUE = "var(--blue)"
const GREEN = "var(--green)"
const PURPLE = "var(--purple)"
const AMBER = "var(--amber)"
const PINK = "var(--pink)"

function Swatch({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[10px] font-bold uppercase tracking-[0.06em] text-muted-foreground">
      <i className="size-2.5 border-2 border-[var(--ink)]" style={{ background: color }} />
      {label}
    </span>
  )
}

function CarrierBadge({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 border-2 border-[var(--ink)] bg-[var(--surface-2)] px-2 py-0.5 font-mono text-[11px] font-bold tabular">
      {label}
    </span>
  )
}

function KV({ k, v }: { k: React.ReactNode; v: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground">{k}</div>
      <div className="tabular mt-1 truncate text-[15px] font-bold">{v}</div>
    </div>
  )
}

function Row({ icon, k, v }: { icon: React.ReactNode; k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center gap-3 py-2.5">
      <span className="text-muted-foreground [&>svg]:size-4 [&>svg]:stroke-[2.5]">{icon}</span>
      <span className="font-mono text-[11px] uppercase tracking-[0.05em] text-muted-foreground">{k}</span>
      <span className="tabular ml-auto text-right text-[13px] font-bold">{v}</span>
    </div>
  )
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="py-10 text-center font-mono text-[12px] uppercase tracking-[0.08em] text-muted-foreground">
      {children}
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
      <CardHeader icon={<Cpu />} tone="yellow" title="System" />
      <CardBody className="space-y-4">
        <div className="grid grid-cols-2 gap-2">
          <Gauge value={n.sys_cpu_pct} color={cpuColor} label="CPU" sub="system" />
          <Gauge value={n.sys_mem_pct} color={memColor} label="Memory" sub={`${n.rss_mb.toFixed(0)} MB`} />
        </div>
        <div className="nb-flat bg-[var(--surface-2)]">
          <div className="flex items-center justify-between border-b-2 border-[var(--ink)] px-2 py-1 font-mono text-[10px] uppercase tracking-[0.06em] text-muted-foreground">
            <span>CPU · last {cpuHist.length}s</span>
            <span className="tabular font-bold text-[var(--ink)]">{n.sys_cpu_pct.toFixed(0)}%</span>
          </div>
          <div className="h-10">
            <Sparkline data={cpuHist} color={PINK} height={40} />
          </div>
        </div>
        <Meter label="Process CPU" value={`${n.cpu_pct.toFixed(1)}%`} pct={n.cpu_pct} color={PURPLE} />
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
          <tr className="border-b-[var(--b)] border-[var(--ink)] bg-[var(--surface-2)] text-left font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
            <th className="py-2 pl-4 font-bold">Lane</th>
            <th className="py-2 font-bold">Carrier</th>
            <th className="py-2 font-bold">Up</th>
            <th className="py-2 font-bold">RTT trend</th>
            <th className="py-2 font-bold">RTT</th>
            <th className="py-2 font-bold">Jitter</th>
            <th className="py-2 pr-4 font-bold">Loss</th>
          </tr>
        </thead>
        <tbody>
          {links.length === 0 ? (
            <tr>
              <td colSpan={7}>
                <Empty>no lanes up</Empty>
              </td>
            </tr>
          ) : (
            links.map((l) => (
              <tr key={l.id} className="border-b-2 border-[var(--ink)]/25 last:border-0">
                <td className="py-2.5 pl-4 font-mono text-[12px] font-bold tabular">#{l.id}</td>
                <td className="py-2.5">
                  <CarrierBadge label={l.label} />
                </td>
                <td className="py-2.5 font-mono text-[11px] tabular text-muted-foreground">{dur(l.up_secs)}</td>
                <td className="py-2.5">
                  <div className="h-5 w-[72px]">
                    <Sparkline
                      data={(laneHist[l.id] || []).slice(-40)}
                      color={toneColor(
                        l.rtt_ms != null && l.rtt_ms >= 150 ? (l.rtt_ms >= 300 ? "bad" : "warn") : "good"
                      )}
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
                <td className="py-2.5 pr-4">
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
      <CardHeader icon={<ArrowDownToLine />} tone="green" title="Transfer" />
      <CardBody className="space-y-4">
        <div className="grid grid-cols-2 gap-x-4 gap-y-4">
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
          <div className="space-y-3 border-t-[var(--b)] border-[var(--ink)] pt-4">
            {n.quotas.map((q) => (
              <div key={q.scope}>
                <Meter
                  label={
                    <span className="inline-flex items-center gap-1.5">
                      <Tag className="size-3 stroke-[2.5]" /> {q.scope}
                    </span>
                  }
                  value={`${bytes(q.used)} / ${bytes(q.limit)} · ${q.pct.toFixed(0)}%`}
                  pct={q.pct}
                  color={toneColor(pctTone(q.pct))}
                />
              </div>
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
      <CardHeader icon={<Server />} tone="plain" title="Node" />
      <CardBody className="divide-y-2 divide-[var(--ink)]/20 py-1">
        <Row icon={<Globe />} k="Host" v={n.host} />
        <Row icon={<Route />} k="Role" v={n.role} />
        <Row
          icon={<Lock />}
          k="Protection"
          v={
            <span className="inline-flex items-center gap-1.5">
              {n.encryption === "full" ? <Badge tone="good">AES-256-GCM</Badge> : <Badge tone="bad">plaintext</Badge>}
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
          <Button variant="outline" size="sm" onClick={() => setView("logs")}>
            <ScrollText /> Logs
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <Kpi
          icon={Download}
          label="Download"
          value={mbit(n.rx_bps)}
          u={unit(n.rx_bps)}
          sub={`peak ${rate(n.peak_rx_bps)} · ${bytes(n.rx_total)}`}
          tone="blue"
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
          tone="green"
          color={GREEN}
          spark={h.up.slice(-60)}
          trend={trend(h.up)}
        />
        <Kpi
          icon={Layers}
          label="Streams"
          value={n.streams}
          sub={`${n.resume ? "resume on" : "resume off"}${n.resume_stats ? ` · ${n.resume_stats.resent_chunks} resent` : ""}`}
          tone="ink"
          color={PURPLE}
        />
        <Kpi
          icon={GitBranch}
          label="Lanes"
          value={n.lanes_up}
          u={`/ ${n.target_lanes || n.lanes_up}`}
          sub={`${n.reconnects} reconnects · ${n.lanes_established} total`}
          tone="yellow"
          color={AMBER}
        />
        <Kpi
          icon={Cpu}
          label="CPU"
          value={n.sys_cpu_pct.toFixed(0)}
          u="%"
          sub={`proc ${n.cpu_pct.toFixed(1)}% · load ${(n.load?.[0] || 0).toFixed(2)}`}
          tone="red"
          color={PINK}
          spark={h.cpu.slice(-60)}
        />
        <Kpi
          icon={HardDrive}
          label="Memory"
          value={n.sys_mem_pct.toFixed(0)}
          u="%"
          sub={`${n.rss_mb.toFixed(0)} MB rss`}
          tone="plain"
          color={GREEN}
          spark={h.mem.slice(-60)}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1.6fr_1fr]">
        <Card>
          <CardHeader
            icon={<Activity />}
            tone="blue"
            title="Throughput"
            sub={`avg down ${rate(avg(h.down.slice(-60)))}`}
            right={
              <>
                <Swatch color={BLUE} label="Down" />
                <Swatch color={GREEN} label="Up" />
                {speedBtn}
              </>
            }
          />
          <CardBody>
            <AreaThroughput down={h.down} up={h.up} height={288} />
            {sp.r || sp.err ? (
              <div className="nb-flat mt-3 flex items-center gap-2 bg-[var(--surface-2)] px-3 py-2 font-mono text-[11px]">
                <Zap className="size-3.5 shrink-0 stroke-[2.5]" />
                {sp.err ? (
                  <span className="font-bold text-[var(--bad)]">{sp.err}</span>
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
        <Card className="overflow-hidden">
          <CardHeader
            icon={<Route />}
            tone="yellow"
            title="Lanes"
            sub={`${n.lanes_up} active`}
            right={
              <Button variant="outline" size="sm" onClick={() => setView("lanes")}>
                Details →
              </Button>
            }
          />
          <LanesTable n={n} laneHist={lh} />
        </Card>
        <div className="space-y-4">
          <TransferCard n={n} />
          <NodeCard n={n} />
        </div>
      </div>

      {nodes.length > 1 ? (
        <Card>
          <CardHeader icon={<Globe />} tone="blue" title="Fleet" />
          <CardBody>
            <FleetStrip nodes={nodes} hist={hist} onPick={setCur} />
          </CardBody>
        </Card>
      ) : null}
    </div>
  )
}

/* ====================== stat tile ====================== */
function StatTile({
  icon,
  tone = "ink",
  label,
  value,
  u,
  sub,
}: {
  icon: React.ReactNode
  tone?: Tone
  label: string
  value: React.ReactNode
  u?: string
  sub?: React.ReactNode
}) {
  return (
    <Card>
      <CardBody className="flex items-start gap-3">
        <IconTile tone={tone}>{icon}</IconTile>
        <div className="min-w-0">
          <div className="font-mono text-[10px] font-bold uppercase tracking-[0.08em] text-muted-foreground">
            {label}
          </div>
          <div className="mt-1.5 truncate">
            <span className="tabular text-[28px] font-extrabold leading-none tracking-tight">{value}</span>
            {u ? <span className="ml-1 font-mono text-xs font-bold text-muted-foreground">{u}</span> : null}
          </div>
          {sub ? (
            <div className="mt-1.5 truncate font-mono text-[11px] text-muted-foreground">{sub}</div>
          ) : null}
        </div>
      </CardBody>
    </Card>
  )
}

/* ====================== Lanes view ====================== */
export function Lanes({ n, laneHist }: { n: Node; laneHist: any }) {
  const links = n.links || []
  const rtts = links.map((l) => l.rtt_ms).filter((x): x is number => x != null)
  const avgRtt = rtts.length ? avg(rtts) : 0
  const worstLoss = links.length ? Math.max(...links.map((l) => l.loss_pct)) : 0
  const lh = laneHist[n.name] || {}
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatTile
          icon={<Route />}
          tone="blue"
          label="Active lanes"
          value={n.lanes_up}
          u={`/ ${n.target_lanes || n.lanes_up}`}
          sub={`${n.lanes_established} established`}
        />
        <StatTile
          icon={<Clock />}
          tone="yellow"
          label="Avg RTT"
          value={avgRtt.toFixed(0)}
          u="ms"
          sub={`across ${rtts.length} lanes`}
        />
        <StatTile
          icon={<Activity />}
          tone={worstLoss >= 5 ? "red" : "green"}
          label="Worst loss"
          value={worstLoss.toFixed(1)}
          u="%"
          sub={worstLoss >= 5 ? "degraded" : "healthy"}
        />
        <StatTile icon={<RotateCw />} tone="plain" label="Reconnects" value={n.reconnects} sub="since start" />
      </div>
      <Card className="overflow-hidden">
        <CardHeader icon={<Route />} tone="blue" title="All lanes" sub={`${n.lanes_up} active on ${n.name}`} />
        <LanesTable n={n} laneHist={lh} />
      </Card>
      {links.length ? (
        <Card>
          <CardHeader icon={<Activity />} tone="yellow" title="Round-trip time by lane" />
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
        <StatTile
          icon={<Download />}
          tone="blue"
          label="Download now"
          value={mbit(n.rx_bps)}
          u={unit(n.rx_bps)}
          sub={`peak ${rate(n.peak_rx_bps)}`}
        />
        <StatTile
          icon={<Upload />}
          tone="green"
          label="Upload now"
          value={mbit(n.tx_bps)}
          u={unit(n.tx_bps)}
          sub={`peak ${rate(n.peak_tx_bps)}`}
        />
        <StatTile icon={<ArrowDownToLine />} tone="ink" label="Total down" value={bytes(n.rx_total)} sub="since start" />
        <StatTile icon={<Upload />} tone="plain" label="Total up" value={bytes(n.tx_total)} sub="since start" />
      </div>
      <Card>
        <CardHeader
          icon={<Activity />}
          tone="blue"
          title={`Throughput · ${n.name}`}
          right={
            <>
              <Swatch color={BLUE} label="Download" />
              <Swatch color={GREEN} label="Upload" />
            </>
          }
        />
        <CardBody>
          <AreaThroughput down={h.down} up={h.up} height={300} />
        </CardBody>
      </Card>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader icon={<Globe />} tone="green" title="Fleet throughput" />
          <CardBody className="space-y-4">
            {nodes.map((x) => (
              <div key={x.name} className="space-y-2">
                <div className="flex items-center gap-2">
                  <Dot color={healthColor(health(x))} size={8} />
                  <span className="font-mono text-[12px] font-bold">{x.name}</span>
                  <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                    {x.role}
                  </span>
                </div>
                <Meter label="Download" value={rate(x.rx_bps)} pct={(x.rx_bps / maxRate) * 100} color={BLUE} />
                <Meter label="Upload" value={rate(x.tx_bps)} pct={(x.tx_bps / maxRate) * 100} color={GREEN} />
              </div>
            ))}
          </CardBody>
        </Card>
        <Card>
          <CardHeader icon={<Tag />} tone="yellow" title="Quotas" />
          <CardBody className="space-y-4">
            {nodes.flatMap((x) =>
              (x.quotas || []).map((q) => (
                <div key={x.name + q.scope} className="flex items-center gap-3">
                  <div className="min-w-0 flex-1">
                    <Meter
                      label={`${x.name} · ${q.scope}`}
                      value={`${bytes(q.used)} / ${bytes(q.limit)}`}
                      pct={q.pct}
                      color={toneColor(pctTone(q.pct))}
                    />
                  </div>
                  <PctBlock
                    pct={q.pct}
                    tone={q.pct >= 90 ? "red" : q.pct >= 75 ? "yellow" : "green"}
                  />
                </div>
              ))
            )}
            {nodes.every((x) => !(x.quotas || []).length) ? <Empty>no quotas configured</Empty> : null}
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
    [
      "Mutual authentication",
      "Every lane starts with a Noise IKpsk2 handshake — both ends pin the other's static key and mix in a shared token; the dial target travels inside the session.",
    ],
    [
      "Encryption by default",
      'encryption = "full" puts AES-256-GCM on every record, safe even through a CDN. "none" sends records as-is, for traffic already encrypted end-to-end.',
    ],
    [
      "Replay-safe",
      "A recorded handshake cannot open a plaintext lane — the responder demands a key confirmation first.",
    ],
    [
      "Bound settings",
      "Encryption and resume modes are bound into the handshake transcript, so mismatched ends simply fail to connect — there is nothing to downgrade.",
    ],
  ]
  return (
    <div className="space-y-4">
      <Card className={allEnc ? "bg-[var(--fill-green)]" : "bg-[var(--fill-yellow)]"}>
        <CardBody className="flex items-center gap-4">
          <IconTile tone="ink" size="lg">
            <ShieldCheck />
          </IconTile>
          <div className="min-w-0 text-[var(--on-fill)]">
            <div className="font-mono text-[18px] font-extrabold uppercase tracking-tight">
              {allEnc ? "All lanes encrypted" : "Mixed encryption"}
            </div>
            <div className="mt-1 text-[13px] font-medium">
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
            <CardBody className="flex items-center gap-4">
              <IconTile tone={n.encryption === "full" ? "green" : "yellow"} size="lg">
                <Lock />
              </IconTile>
              <div className="min-w-0">
                <div className="font-mono text-[15px] font-extrabold">{n.name}</div>
                <div className="font-mono text-[11px] tabular text-muted-foreground">
                  {n.role} · {n.carrier} · {n.host}
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {n.encryption === "full" ? (
                    <Badge tone="good">AES-256-GCM</Badge>
                  ) : (
                    <Badge tone="warn">plaintext</Badge>
                  )}
                  {n.resume ? <Badge tone="secondary">resume</Badge> : null}
                </div>
              </div>
            </CardBody>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader icon={<Shield />} tone="red" title="How rakhsh secures the wire" />
        <CardBody className="divide-y-2 divide-[var(--ink)]/20 py-0">
          {points.map(([t, d]) => (
            <div key={t} className="flex gap-3 py-3.5">
              <CircleCheck className="mt-0.5 size-4 shrink-0 stroke-[2.5] text-[var(--good)]" />
              <div>
                <span className="font-mono text-[13px] font-extrabold uppercase">{t}.</span>{" "}
                <span className="text-[13px] text-muted-foreground">{d}</span>
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
    if (!auto)
      return () => {
        alive = false
      }
    const t = setInterval(load, 4000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [n.name, auto])
  const tone = (lv: string) =>
    lv === "err"
      ? "bg-[var(--fill-red)] text-[#f8f4ec]"
      : lv === "warn"
        ? "bg-[var(--fill-yellow)] text-[var(--on-fill)]"
        : "bg-[var(--surface-2)] text-muted-foreground"
  return (
    <Card>
      <CardHeader
        icon={<ScrollText />}
        tone="ink"
        title="Service logs"
        sub={n.name}
        right={
          <Segmented
            options={[
              { id: "auto", label: "Auto" },
              { id: "paused", label: "Paused" },
            ]}
            value={auto ? "auto" : "paused"}
            onChange={(v) => setAuto(v === "auto")}
          />
        }
      />
      <CardBody>
        <div className="nb-flat max-h-[70vh] overflow-auto bg-[var(--surface-2)] p-3 font-mono text-[12px] leading-6">
          {lines.length === 0 ? (
            <Empty>no log lines</Empty>
          ) : (
            lines.map((l, i) => (
              <div key={i} className="flex gap-2.5 whitespace-pre-wrap">
                <span className="shrink-0 tabular text-muted-foreground">{l.ts}</span>
                <span className={`h-5 w-11 shrink-0 border border-[var(--ink)] text-center text-[10px] font-bold leading-[18px] ${tone(l.level)}`}>
                  {l.level.toUpperCase()}
                </span>
                <span>{l.msg}</span>
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
          tone="red"
          title="Fleet"
          right={
            <Button variant="secondary" size="sm" onClick={backup} disabled={backing}>
              <Download /> {backing ? "…" : "Backup configs"}
            </Button>
          }
        />
        <CardBody className="divide-y-2 divide-[var(--ink)]/20 py-0">
          {nodes.map((n) => (
            <div key={n.name} className="flex flex-wrap items-center gap-3 py-3">
              <Dot color={healthColor(health(n))} />
              <div className="min-w-0">
                <div className="font-mono text-[13px] font-extrabold">{n.name}</div>
                <div className="font-mono text-[11px] tabular text-muted-foreground">
                  {n.role} · {n.host} · {n.offline ? "offline" : `up ${dur(n.uptime_secs)}`}
                </div>
              </div>
              <div className="ml-auto flex flex-wrap gap-2">
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
          <CardHeader icon={<Power />} tone="plain" title="Control center" />
          <CardBody className="divide-y-2 divide-[var(--ink)]/20 py-0">
            <Row icon={<Globe />} k="Address" v={location.host || "—"} />
            <Row icon={<Activity />} k="Live refresh" v="polling" />
            <Row icon={<Server />} k="Nodes" v={nodes.length} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader icon={<Shield />} tone="yellow" title="About actions" />
          <CardBody className="space-y-3 text-[13px] text-muted-foreground">
            <div className="flex gap-2.5">
              <CircleCheck className="mt-0.5 size-4 shrink-0 stroke-[2.5] text-[var(--good)]" />
              <span>
                <b className="text-[var(--ink)]">Restart / Stop / Start</b> run{" "}
                <code className="border border-[var(--ink)] bg-[var(--surface-2)] px-1 font-mono text-[11px]">
                  systemctl
                </code>{" "}
                on the node over SSH (or locally). They need the daemon installed as a service.
              </span>
            </div>
            <div className="flex gap-2.5">
              <CircleCheck className="mt-0.5 size-4 shrink-0 stroke-[2.5] text-[var(--good)]" />
              <span>
                Add or remove nodes by editing{" "}
                <code className="border border-[var(--ink)] bg-[var(--surface-2)] px-1 font-mono text-[11px]">
                  control.toml
                </code>{" "}
                and restarting the control center.
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
      <div className="w-full max-w-sm">
        <div className="mb-5 flex items-center gap-3">
          <IconTile tone="red" size="lg">
            <Zap />
          </IconTile>
          <div>
            <div className="font-mono text-[26px] font-extrabold leading-none tracking-tight">rakhsh</div>
            <div className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
              Control Center
            </div>
          </div>
        </div>
        <Card>
          <CardBody className="p-5">
            <form onSubmit={submit} className="space-y-3">
              <label className="block font-mono text-[11px] font-bold uppercase tracking-[0.08em] text-muted-foreground">
                Panel password
              </label>
              <input
                type="password"
                autoFocus
                value={pw}
                onChange={(e) => setPw(e.target.value)}
                placeholder="••••••••"
                className="nb-flat h-11 w-full bg-[var(--surface-2)] px-3 font-mono text-[14px] outline-none focus:ring-4 focus:ring-[var(--fill-yellow)]"
              />
              {err ? (
                <div className="nb-flat bg-[var(--fill-red)] px-3 py-2 font-mono text-[11px] font-bold text-[#f8f4ec]">
                  {err}
                </div>
              ) : null}
              <Button type="submit" variant="default" size="md" className="w-full" disabled={busy}>
                {busy ? "Signing in…" : "Sign in"}
              </Button>
            </form>
          </CardBody>
        </Card>
      </div>
    </div>
  )
}
