import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  LabelList,
  Line,
  LineChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"
import type { Lane } from "@/lib/api"
import { rate, rttTone, toneColor } from "@/lib/utils"

const AXIS = "oklch(0.62 0.015 258)"

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
        <AreaChart data={data} margin={{ top: 8, right: 10, left: 2, bottom: 0 }}>
          <defs>
            <linearGradient id="gDown" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--chart-1)" stopOpacity={0.42} />
              <stop offset="100%" stopColor="var(--chart-1)" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="gUp" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--chart-2)" stopOpacity={0.3} />
              <stop offset="100%" stopColor="var(--chart-2)" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <XAxis dataKey="i" hide />
          <YAxis
            width={44}
            tickLine={false}
            axisLine={false}
            tick={{ fill: AXIS, fontSize: 11 }}
            tickFormatter={fmt}
            tickCount={5}
          />
          <Tooltip
            cursor={{ stroke: "var(--border-strong)", strokeWidth: 1 }}
            content={({ active, payload }) => {
              if (!active || !payload || !payload.length) return null
              const d = (payload[0]?.payload?.down || 0) * 1e6
              const u = (payload[0]?.payload?.up || 0) * 1e6
              return (
                <div className="rounded-lg border bg-popover/95 px-3 py-2 text-xs shadow-xl backdrop-blur tabular">
                  <div className="flex items-center gap-2">
                    <i className="size-2 rounded-full" style={{ background: "var(--chart-1)" }} />
                    <span className="text-muted-foreground">Download</span>
                    <b className="ml-auto">{rate(d)}</b>
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <i className="size-2 rounded-full" style={{ background: "var(--chart-2)" }} />
                    <span className="text-muted-foreground">Upload</span>
                    <b className="ml-auto">{rate(u)}</b>
                  </div>
                </div>
              )
            }}
          />
          <Area
            type="monotone"
            dataKey="down"
            stroke="var(--chart-1)"
            strokeWidth={2}
            fill="url(#gDown)"
            isAnimationActive={false}
            dot={false}
          />
          <Area
            type="monotone"
            dataKey="up"
            stroke="var(--chart-2)"
            strokeWidth={2}
            fill="url(#gUp)"
            isAnimationActive={false}
            dot={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

/* ---------- sparkline ---------- */
export function Sparkline({
  data,
  color = "var(--chart-1)",
  height = 40,
  kind = "area",
}: {
  data: number[]
  color?: string
  height?: number
  kind?: "area" | "line"
}) {
  const d = (data && data.length ? data : [0, 0]).map((v, i) => ({ i, v }))
  const gid = "sp" + Math.random().toString(36).slice(2, 8)
  return (
    <div style={{ width: "100%", height }}>
      <ResponsiveContainer>
        {kind === "area" ? (
          <AreaChart data={d} margin={{ top: 3, right: 1, left: 1, bottom: 0 }}>
            <defs>
              <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.35} />
                <stop offset="100%" stopColor={color} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <Area
              type="monotone"
              dataKey="v"
              stroke={color}
              strokeWidth={1.75}
              fill={`url(#${gid})`}
              isAnimationActive={false}
              dot={false}
            />
          </AreaChart>
        ) : (
          <LineChart data={d} margin={{ top: 3, right: 2, left: 2, bottom: 2 }}>
            <Line
              type="monotone"
              dataKey="v"
              stroke={color}
              strokeWidth={1.75}
              isAnimationActive={false}
              dot={false}
            />
          </LineChart>
        )}
      </ResponsiveContainer>
    </div>
  )
}

/* ---------- radial gauge ---------- */
export function Gauge({
  value,
  color = "var(--chart-1)",
  label,
  sub,
  size = 128,
}: {
  value: number
  color?: string
  label?: string
  sub?: string
  size?: number
}) {
  const v = Math.max(0, Math.min(100, value || 0))
  const data = [{ name: "v", value: v, fill: color }]
  return (
    <div className="flex flex-col items-center">
      <div style={{ width: size, height: size }} className="relative">
        <ResponsiveContainer>
          <RadialBarChart
            innerRadius="72%"
            outerRadius="100%"
            data={data}
            startAngle={230}
            endAngle={-50}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
            <RadialBar
              background={{ fill: "var(--secondary)" }}
              dataKey="value"
              cornerRadius={10}
              angleAxisId={0}
              isAnimationActive={false}
            />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="tabular text-2xl font-semibold leading-none">{Math.round(v)}</span>
          <span className="text-[10px] text-muted-foreground mt-0.5">%</span>
        </div>
      </div>
      {label ? (
        <div className="mt-1 text-center">
          <div className="text-xs font-medium">{label}</div>
          {sub ? <div className="text-[11px] text-muted-foreground">{sub}</div> : null}
        </div>
      ) : null}
    </div>
  )
}

/* ---------- per-lane RTT bars ---------- */
export function RttBars({ lanes }: { lanes: Lane[] }) {
  const data = lanes.map((l) => ({
    name: `#${l.id} ${l.label}`,
    rtt: l.rtt_ms ?? 0,
    fill: toneColor(rttTone(l.rtt_ms)),
  }))
  const h = Math.max(120, data.length * 34 + 16)
  return (
    <div style={{ width: "100%", height: h }}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 48, left: 8, bottom: 0 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            width={92}
            tickLine={false}
            axisLine={false}
            tick={{ fill: "oklch(0.72 0.02 258)", fontSize: 12 }}
          />
          <Bar dataKey="rtt" radius={[4, 4, 4, 4]} barSize={12} isAnimationActive={false}>
            {data.map((d, i) => (
              <Cell key={i} fill={d.fill} />
            ))}
            <LabelList
              dataKey="rtt"
              position="right"
              formatter={(v: number) => `${Math.round(v)} ms`}
              style={{ fill: "oklch(0.72 0.02 258)", fontSize: 11, fontVariantNumeric: "tabular-nums" }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
