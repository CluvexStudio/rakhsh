import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import type { Lane } from "@/lib/api"
import { rate, rttTone, toneColor } from "@/lib/utils"

const AXIS = { fill: "var(--ink-soft)", fontSize: 10, fontFamily: "var(--font-mono)", fontWeight: 700 }
const GRID = "color-mix(in srgb, var(--ink) 22%, transparent)"

/* ---------- throughput (download + upload) ---------- */
export function AreaThroughput({
  down,
  up,
  height = 300,
}: {
  down: number[]
  up: number[]
  height?: number
}) {
  const n = Math.max(down.length, up.length)
  const data = Array.from({ length: n }, (_, i) => ({
    i,
    down: (down[i] || 0) / 1e6,
    up: (up[i] || 0) / 1e6,
  }))
  const fmt = (v: number) => (v >= 1000 ? (v / 1000).toFixed(1) + "G" : v >= 1 ? v.toFixed(0) : "0")
  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer>
        <AreaChart data={data} margin={{ top: 8, right: 6, left: 0, bottom: 0 }}>
          <CartesianGrid stroke={GRID} strokeDasharray="4 4" vertical={false} />
          <XAxis dataKey="i" hide />
          <YAxis
            width={42}
            tickLine={false}
            axisLine={{ stroke: "var(--ink)", strokeWidth: 2 }}
            tick={AXIS}
            tickFormatter={fmt}
            tickCount={5}
          />
          <Tooltip
            cursor={{ stroke: "var(--ink)", strokeWidth: 2 }}
            content={({ active, payload }) => {
              if (!active || !payload || !payload.length) return null
              const d = (payload[0]?.payload?.down || 0) * 1e6
              const u = (payload[0]?.payload?.up || 0) * 1e6
              return (
                <div className="nb-sm bg-[var(--surface)] px-3 py-2 font-mono text-[11px] tabular">
                  <div className="flex items-center gap-2">
                    <i className="size-2.5 border border-[var(--ink)]" style={{ background: "var(--blue)" }} />
                    <span className="text-muted-foreground">DOWN</span>
                    <b className="ml-auto">{rate(d)}</b>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <i className="size-2.5 border border-[var(--ink)]" style={{ background: "var(--green)" }} />
                    <span className="text-muted-foreground">UP</span>
                    <b className="ml-auto">{rate(u)}</b>
                  </div>
                </div>
              )
            }}
          />
          <Area
            type="linear"
            dataKey="down"
            stroke="var(--blue)"
            strokeWidth={3}
            fill="var(--blue)"
            fillOpacity={0.14}
            isAnimationActive={false}
            dot={false}
            activeDot={{ r: 4, fill: "var(--blue)", stroke: "var(--ink)", strokeWidth: 2 }}
          />
          <Area
            type="linear"
            dataKey="up"
            stroke="var(--green)"
            strokeWidth={3}
            fill="var(--green)"
            fillOpacity={0.12}
            isAnimationActive={false}
            dot={false}
            activeDot={{ r: 4, fill: "var(--green)", stroke: "var(--ink)", strokeWidth: 2 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ---------- sparkline ---------- */
export function Sparkline({
  data,
  color = "var(--blue)",
  height = 40,
  kind = "area",
}: {
  data: number[]
  color?: string
  height?: number
  kind?: "area" | "line"
}) {
  const d = (data && data.length ? data : [0, 0]).map((v, i) => ({ i, v }))
  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer>
        {kind === "area" ? (
          <AreaChart data={d} margin={{ top: 4, right: 0, left: 0, bottom: 0 }}>
            <Area
              type="linear"
              dataKey="v"
              stroke={color}
              strokeWidth={2}
              fill={color}
              fillOpacity={0.25}
              isAnimationActive={false}
              dot={false}
            />
          </AreaChart>
        ) : (
          <LineChart data={d} margin={{ top: 3, right: 2, left: 2, bottom: 2 }}>
            <Line type="linear" dataKey="v" stroke={color} strokeWidth={2} isAnimationActive={false} dot={false} />
          </LineChart>
        )}
      </ResponsiveContainer>
    </div>
  )
}

/* ---------- dial: a bordered ring, drawn in CSS ---------- */
export function Gauge({
  value,
  color = "var(--fill-yellow)",
  label,
  sub,
  size = 112,
}: {
  value: number
  color?: string
  label?: string
  sub?: string
  size?: number
}) {
  const v = Math.max(0, Math.min(100, value || 0))
  return (
    <div className="flex flex-col items-center">
      <div
        className="relative grid place-items-center rounded-full border-[var(--b)] border-[var(--ink)]"
        style={{
          width: size,
          height: size,
          background: `conic-gradient(${color} ${v * 3.6}deg, var(--surface-2) 0deg)`,
        }}
      >
        <div
          className="grid place-items-center rounded-full border-[var(--b)] border-[var(--ink)] bg-[var(--surface)]"
          style={{ width: size * 0.62, height: size * 0.62 }}
        >
          <span className="tabular text-[22px] font-extrabold leading-none">{Math.round(v)}</span>
          <span className="font-mono text-[9px] font-bold text-muted-foreground">%</span>
        </div>
      </div>
      {label ? (
        <div className="mt-2 text-center">
          <div className="font-mono text-[11px] font-bold uppercase tracking-[0.06em]">{label}</div>
          {sub ? <div className="font-mono text-[10px] text-muted-foreground">{sub}</div> : null}
        </div>
      ) : null}
    </div>
  )
}

/* ---------- per-lane RTT bars ---------- */
export function RttBars({ lanes }: { lanes: Lane[] }) {
  const data = lanes.map((l) => ({
    name: `#${l.id} ${l.label.split(" ")[0]}`,
    rtt: l.rtt_ms ?? 0,
    fill: toneColor(rttTone(l.rtt_ms)),
  }))
  const h = Math.max(120, data.length * 38 + 16)
  return (
    <div style={{ width: "100%", height: h }}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 56, left: 4, bottom: 0 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            width={116}
            tickLine={false}
            axisLine={{ stroke: "var(--ink)", strokeWidth: 2 }}
            tick={AXIS}
          />
          <Bar dataKey="rtt" barSize={16} isAnimationActive={false} stroke="var(--ink)" strokeWidth={2}>
            {data.map((d, i) => (
              <Cell key={i} fill={d.fill} />
            ))}
            <LabelList
              dataKey="rtt"
              position="right"
              formatter={(v: number) => `${Math.round(v)} ms`}
              style={{
                fill: "var(--ink)",
                fontSize: 11,
                fontFamily: "var(--font-mono)",
                fontWeight: 700,
                fontVariantNumeric: "tabular-nums",
              }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
