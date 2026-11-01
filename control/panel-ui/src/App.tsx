import * as React from "react"
import { HIST, LANEHIST, login, useFleet } from "@/lib/api"
import { Sidebar, Topbar, type ViewId } from "@/components/app"
import { dur } from "@/lib/utils"
import { Lanes, Login, Logs, Overview, Security, Settings, Traffic } from "@/views"

interface Toast {
  id: number
  ok: boolean
  msg: string
}

export default function App() {
  const fleet = useFleet(2000)
  const [view, setView] = React.useState<ViewId>("overview")
  const [cur, setCur] = React.useState(0)
  const [open, setOpen] = React.useState(false)
  const [toasts, setToasts] = React.useState<Toast[]>([])

  const pushToast = (ok: boolean, msg: string) => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, ok, msg }])
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3600)
  }

  if (fleet.needsLogin) {
    return (
      <Login
        onLogin={async (pw) => {
          const ok = await login(pw)
          if (ok) await fleet.refresh()
          return ok
        }}
      />
    )
  }

  const nodes = fleet.nodes
  const idx = Math.min(cur, Math.max(0, nodes.length - 1))
  const n = nodes[idx]

  const titles: Record<ViewId, string> = {
    overview: "Overview",
    lanes: "Lanes",
    traffic: "Traffic",
    security: "Security",
    logs: "Logs",
    settings: "Settings",
  }
  const sub = !n
    ? "connecting…"
    : view === "overview"
      ? `${n.name} · ${n.role} · ${n.carrier} · up ${dur(n.uptime_secs)}`
      : view === "lanes"
        ? `${n.lanes_up} active on ${n.name}`
        : view === "traffic"
          ? `${nodes.length} nodes · live`
          : view === "security"
            ? `data protection across ${nodes.length} nodes`
            : view === "logs"
              ? `service logs · ${n.name}`
              : "fleet & panel management"

  return (
    <div className="app-bg min-h-screen">
      <Sidebar
        view={view}
        setView={setView}
        nodes={nodes}
        hist={HIST}
        cur={idx}
        setCur={setCur}
        open={open}
        onClose={() => setOpen(false)}
      />
      <div className="lg:pl-[248px]">
        <Topbar
          title={titles[view]}
          sub={sub}
          updatedAt={fleet.updatedAt}
          onRefresh={fleet.refresh}
          onMenu={() => setOpen(true)}
        />
        <main className="mx-auto max-w-[1400px] p-4 sm:p-6">
          {!n ? (
            <div className="grid place-items-center py-32 text-sm text-muted-foreground">
              {fleet.error ? `cannot reach the control center — ${fleet.error}` : "connecting to the fleet…"}
            </div>
          ) : view === "overview" ? (
            <Overview n={n} nodes={nodes} hist={HIST} laneHist={LANEHIST} setCur={setCur} setView={setView} />
          ) : view === "lanes" ? (
            <Lanes n={n} laneHist={LANEHIST} />
          ) : view === "traffic" ? (
            <Traffic n={n} nodes={nodes} hist={HIST} />
          ) : view === "security" ? (
            <Security nodes={nodes} />
          ) : view === "logs" ? (
            <Logs n={n} />
          ) : (
            <Settings nodes={nodes} onToast={pushToast} />
          )}
        </main>
      </div>

      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className="flex items-center gap-2 rounded-lg border bg-popover/95 px-3.5 py-2.5 text-sm shadow-xl backdrop-blur"
            style={{ borderColor: t.ok ? "color-mix(in oklch, var(--good) 35%, transparent)" : "color-mix(in oklch, var(--bad) 35%, transparent)" }}
          >
            <span className="size-1.5 rounded-full" style={{ background: t.ok ? "var(--good)" : "var(--bad)" }} />
            {t.msg}
          </div>
        ))}
      </div>
    </div>
  )
}
