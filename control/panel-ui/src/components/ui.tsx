import * as React from "react"
import { cn } from "@/lib/utils"

export type Tone = "ink" | "blue" | "yellow" | "red" | "green" | "plain"

const toneFill: Record<Tone, string> = {
  ink: "bg-[var(--ink)] text-[var(--on-ink)]",
  blue: "bg-[var(--fill-blue)] text-[#f8f4ec]",
  yellow: "bg-[var(--fill-yellow)] text-[var(--on-fill)]",
  red: "bg-[var(--fill-red)] text-[#f8f4ec]",
  green: "bg-[var(--fill-green)] text-[var(--on-fill)]",
  plain: "bg-[var(--surface-2)] text-[var(--ink)]",
}

/* ---------------- Card ---------------- */
export function Card({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("nb relative bg-card text-card-foreground", className)} {...p} />
}

/** The decorative quarter-disc that bleeds out of a card's top-right corner. */
export function Corner({ tone = "blue", size = 112 }: { tone?: Tone; size?: number }) {
  return (
    <span
      aria-hidden
      className={cn("pointer-events-none absolute right-0 top-0 rounded-bl-full", toneFill[tone])}
      style={{ width: size, height: size, borderLeft: "var(--b) solid var(--ink)", borderBottom: "var(--b) solid var(--ink)" }}
    />
  )
}

export function IconTile({
  tone = "ink",
  size = "md",
  className,
  children,
}: {
  tone?: Tone
  size?: "sm" | "md" | "lg"
  className?: string
  children: React.ReactNode
}) {
  const box = size === "lg" ? "size-12 [&>svg]:size-6" : size === "sm" ? "size-7 [&>svg]:size-4" : "size-9 [&>svg]:size-[18px]"
  return (
    <span className={cn("nb-flat grid shrink-0 place-items-center [&>svg]:stroke-[2.5]", box, toneFill[tone], className)}>
      {children}
    </span>
  )
}

export function CardHeader({
  className,
  icon,
  tone = "ink",
  title,
  right,
  sub,
}: {
  className?: string
  icon?: React.ReactNode
  tone?: Tone
  title?: React.ReactNode
  right?: React.ReactNode
  sub?: React.ReactNode
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-3 border-b-[var(--b)] border-[var(--ink)] px-4 py-3", className)}>
      {icon ? <IconTile tone={tone}>{icon}</IconTile> : null}
      <div className="min-w-0">
        <div className="font-mono text-[13px] font-extrabold uppercase leading-none tracking-[0.06em]">
          {title}
        </div>
        {sub ? <div className="mt-1.5 font-mono text-[11px] text-muted-foreground">{sub}</div> : null}
      </div>
      {right ? <div className="ml-auto flex flex-wrap items-center gap-2">{right}</div> : null}
    </div>
  )
}

export function CardBody({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("p-4", className)} {...p} />
}

/* ---------------- Button ---------------- */
type BtnVariant = "default" | "secondary" | "outline" | "ghost" | "destructive"
type BtnSize = "sm" | "md" | "icon" | "icon-lg"

const btnVariants: Record<BtnVariant, string> = {
  default: "nb-sm bg-[var(--ink)] text-[var(--on-ink)]",
  secondary: "nb-sm bg-[var(--surface)] text-[var(--ink)] hover:bg-[var(--surface-2)]",
  outline: "nb-flat bg-transparent text-[var(--ink)] hover:bg-[var(--surface-2)]",
  ghost: "border-[var(--b)] border-transparent text-muted-foreground hover:border-[var(--ink)] hover:text-[var(--ink)]",
  destructive: "nb-sm bg-[var(--fill-red)] text-[#f8f4ec]",
}
const btnSizes: Record<BtnSize, string> = {
  sm: "h-9 px-3 text-[11px] gap-1.5",
  md: "h-11 px-5 text-[13px] gap-2",
  icon: "size-9",
  "icon-lg": "size-11",
}

export function Button({
  className,
  variant = "secondary",
  size = "sm",
  ...p
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; size?: BtnSize }) {
  return (
    <button
      className={cn(
        "nb-press inline-flex items-center justify-center whitespace-nowrap font-mono font-bold uppercase tracking-[0.06em]",
        "focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-[var(--fill-yellow)] disabled:pointer-events-none",
        "[&>svg]:size-[15px] [&>svg]:shrink-0 [&>svg]:stroke-[2.5]",
        btnVariants[variant],
        btnSizes[size],
        className
      )}
      {...p}
    />
  )
}

/* ---------------- Badge ---------------- */
type BadgeTone = "default" | "secondary" | "outline" | "good" | "warn" | "bad" | "primary"
const badgeTones: Record<BadgeTone, string> = {
  default: "bg-[var(--ink)] text-[var(--on-ink)]",
  secondary: "bg-[var(--surface-2)] text-[var(--ink)]",
  outline: "bg-transparent text-[var(--ink)]",
  primary: "bg-[var(--fill-blue)] text-[#f8f4ec]",
  good: "bg-[var(--fill-green)] text-[var(--on-fill)]",
  warn: "bg-[var(--fill-yellow)] text-[var(--on-fill)]",
  bad: "bg-[var(--fill-red)] text-[#f8f4ec]",
}
export function Badge({
  className,
  tone = "default",
  ...p
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 border-2 border-[var(--ink)] px-2 py-0.5",
        "font-mono text-[11px] font-bold uppercase leading-5 tracking-[0.04em]",
        "[&>svg]:size-3 [&>svg]:stroke-[2.5]",
        badgeTones[tone],
        className
      )}
      {...p}
    />
  )
}

export function Separator({ className }: { className?: string }) {
  return <div className={cn("h-[var(--b)] w-full bg-[var(--ink)]", className)} />
}

/* ---------------- Meter ---------------- */
export function Meter({
  label,
  value,
  pct,
  color = "var(--fill-yellow)",
}: {
  label: React.ReactNode
  value?: React.ReactNode
  pct: number
  color?: string
}) {
  const w = Math.max(0, Math.min(100, pct || 0))
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-3 font-mono text-[11px]">
        <span className="min-w-0 truncate text-muted-foreground">{label}</span>
        <span className="tabular shrink-0 font-bold">{value}</span>
      </div>
      <div className="nb-flat h-[18px] bg-[var(--surface-2)] p-[3px]">
        <div className="h-full transition-[width] duration-500" style={{ width: w + "%", background: color }} />
      </div>
    </div>
  )
}

/** The big accent block that states one percentage, as on the usage card. */
export function PctBlock({ pct, tone }: { pct: number; tone: Tone }) {
  return (
    <span className={cn("nb-sm inline-flex items-baseline px-3 py-1", toneFill[tone])}>
      <b className="text-[34px] font-extrabold leading-none tracking-tight tabular">{Math.round(pct)}</b>
      <span className="ml-0.5 font-mono text-sm font-bold">%</span>
    </span>
  )
}

/* ---------------- Segmented control ---------------- */
export function Segmented<T extends string>({
  options,
  value,
  onChange,
  className,
}: {
  options: { id: T; label: string }[]
  value: T
  onChange: (v: T) => void
  className?: string
}) {
  return (
    <div className={cn("nb-flat inline-flex bg-[var(--surface)]", className)}>
      {options.map((o, i) => (
        <button
          key={o.id}
          onClick={() => onChange(o.id)}
          className={cn(
            "px-3 py-1.5 font-mono text-[11px] font-bold uppercase tracking-[0.06em] transition-colors",
            i > 0 ? "border-l-[var(--b)] border-[var(--ink)]" : "",
            o.id === value
              ? "bg-[var(--ink)] text-[var(--on-ink)]"
              : "text-muted-foreground hover:bg-[var(--surface-2)] hover:text-[var(--ink)]"
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

/** Label over value, the stat pair used across the cards. */
export function Stat({
  label,
  value,
  u,
  sub,
}: {
  label: React.ReactNode
  value: React.ReactNode
  u?: string
  sub?: React.ReactNode
}) {
  return (
    <div className="min-w-0">
      <div className="font-mono text-[11px] uppercase tracking-[0.06em] text-muted-foreground">{label}</div>
      <div className="mt-1 truncate">
        <span className="tabular text-[22px] font-extrabold leading-none tracking-tight">{value}</span>
        {u ? <span className="ml-1 font-mono text-xs font-bold text-muted-foreground">{u}</span> : null}
      </div>
      {sub ? <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">{sub}</div> : null}
    </div>
  )
}
