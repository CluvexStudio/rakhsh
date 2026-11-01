import * as React from "react"
import { cn } from "@/lib/utils"

/* ---------------- Card ---------------- */
export function Card({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-xl border bg-card text-card-foreground shadow-sm",
        "bg-gradient-to-b from-white/[0.015] to-transparent",
        className
      )}
      {...p}
    />
  )
}
export function CardHeader({
  className,
  icon,
  title,
  right,
  sub,
}: {
  className?: string
  icon?: React.ReactNode
  title?: React.ReactNode
  right?: React.ReactNode
  sub?: React.ReactNode
}) {
  return (
    <div className={cn("flex items-center gap-2.5 px-5 pt-4 pb-3", className)}>
      {icon ? <span className="text-muted-foreground [&>svg]:size-[15px]">{icon}</span> : null}
      <div className="min-w-0">
        <div className="text-[11px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
          {title}
        </div>
        {sub ? <div className="text-xs text-muted-foreground/80 mt-0.5">{sub}</div> : null}
      </div>
      {right ? <div className="ml-auto flex items-center gap-2">{right}</div> : null}
    </div>
  )
}
export function CardBody({ className, ...p }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("px-5 pb-5", className)} {...p} />
}

/* ---------------- Button ---------------- */
type BtnVariant = "default" | "secondary" | "outline" | "ghost" | "destructive"
type BtnSize = "sm" | "md" | "icon"
const btnVariants: Record<BtnVariant, string> = {
  default: "bg-primary text-primary-foreground hover:brightness-110 shadow-sm",
  secondary: "bg-secondary text-secondary-foreground hover:bg-accent",
  outline: "border bg-transparent hover:bg-accent/60 text-foreground",
  ghost: "hover:bg-accent/60 text-muted-foreground hover:text-foreground",
  destructive: "border border-[var(--bad)]/40 text-[var(--bad)] hover:bg-[var(--bad)]/12",
}
const btnSizes: Record<BtnSize, string> = {
  sm: "h-8 px-3 text-xs gap-1.5 rounded-md",
  md: "h-9 px-4 text-sm gap-2 rounded-lg",
  icon: "size-9 rounded-lg",
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
        "inline-flex items-center justify-center font-medium whitespace-nowrap transition-all",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 disabled:opacity-50 disabled:pointer-events-none",
        "[&>svg]:size-[15px] [&>svg]:shrink-0",
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
  default: "bg-secondary text-secondary-foreground border-transparent",
  secondary: "bg-accent/60 text-accent-foreground border-transparent",
  outline: "border-[var(--border-strong)] text-muted-foreground",
  primary: "border-primary/30 bg-primary/12 text-primary",
  good: "border-[var(--good)]/25 bg-[var(--good)]/12 text-[var(--good)]",
  warn: "border-[var(--warn)]/25 bg-[var(--warn)]/12 text-[var(--warn)]",
  bad: "border-[var(--bad)]/25 bg-[var(--bad)]/12 text-[var(--bad)]",
}
export function Badge({
  className,
  tone = "default",
  ...p
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium leading-5",
        "[&>svg]:size-3",
        badgeTones[tone],
        className
      )}
      {...p}
    />
  )
}

export function Separator({ className }: { className?: string }) {
  return <div className={cn("h-px w-full bg-border", className)} />
}

/* ---------------- Meter (labelled progress) ---------------- */
export function Meter({
  label,
  value,
  pct,
  color = "var(--primary)",
}: {
  label: React.ReactNode
  value?: React.ReactNode
  pct: number
  color?: string
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="tabular text-foreground/90 font-medium">{value}</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-secondary/70">
        <div
          className="h-full rounded-full transition-[width] duration-500"
          style={{ width: Math.max(0, Math.min(100, pct)) + "%", background: color }}
        />
      </div>
    </div>
  )
}
