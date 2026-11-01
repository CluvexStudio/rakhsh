import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export const clamp = (x: number, a: number, b: number) => Math.max(a, Math.min(b, x))

/** bits-per-second → compact number string (paired with `unit`). */
export function mbit(bps: number): string {
  const m = (bps || 0) / 1e6
  if (m >= 1000) return (m / 1000).toFixed(2)
  if (m >= 100) return m.toFixed(0)
  if (m >= 10) return m.toFixed(1)
  return m.toFixed(m >= 1 ? 1 : 2)
}
export const unit = (bps: number) => ((bps || 0) / 1e6 >= 1000 ? "Gb/s" : "Mb/s")

/** bits-per-second → "648 Mb/s" / "1.21 Gb/s". */
export function rate(bps: number): string {
  const m = (bps || 0) / 1e6
  if (m >= 1000) return (m / 1000).toFixed(2) + " Gb/s"
  return (m >= 10 ? m.toFixed(0) : m.toFixed(1)) + " Mb/s"
}

/** base-1024 bytes → "4.2 TB". */
export function bytes(n: number): string {
  const u = ["B", "KB", "MB", "GB", "TB", "PB"]
  let i = 0
  let v = n || 0
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return (v < 10 && i > 0 ? v.toFixed(1) : v.toFixed(0)) + " " + u[i]
}

/** seconds → "2d 3h" / "4h 8m" / "6m 12s". */
export function dur(s: number): string {
  s = Math.floor(s || 0)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s / 3600) % 24)
  const m = Math.floor((s / 60) % 60)
  const x = s % 60
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m ${x}s`
}

export type Tone = "good" | "warn" | "bad"
export const rttTone = (ms: number | null): Tone =>
  ms == null ? "good" : ms >= 300 ? "bad" : ms >= 150 ? "warn" : "good"
export const jitterTone = (ms: number): Tone => (ms >= 80 ? "bad" : ms >= 30 ? "warn" : "good")
export const lossTone = (p: number): Tone => (p >= 5 ? "bad" : p >= 1 ? "warn" : "good")
export const pctTone = (p: number): Tone => (p >= 90 ? "bad" : p >= 75 ? "warn" : "good")

export const toneColor = (t: Tone) =>
  t === "bad" ? "var(--bad)" : t === "warn" ? "var(--warn)" : "var(--good)"

export const avg = (a: number[]) => (a && a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0)

/** % change of the tail of a series vs. the window before it; null when too short or meaningless. */
export function trend(series: number[]): number | null {
  if (!series || series.length < 8) return null
  const a = avg(series.slice(-8, -4))
  const b = avg(series.slice(-4))
  const base = Math.max(a, b)
  if (base <= 0) return 0
  // An idle→burst (or burst→idle) baseline makes the ratio explode and tells us nothing — hide it.
  if (Math.min(a, b) < base * 0.08) return null
  const pct = ((b - a) / a) * 100
  return clamp(pct, -999, 999)
}
