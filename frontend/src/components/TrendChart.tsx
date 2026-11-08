import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

export type TrendPoint = { label: string; total: number; critical: number; high: number };

export default function TrendChart({ data }: { data: TrendPoint[] }) {
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
          <defs>
            <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.45} />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#1e293b" vertical={false} />
          <XAxis dataKey="label" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} minTickGap={24} />
          <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} labelStyle={{ color: '#e2e8f0' }} />
          <Area type="monotone" dataKey="total" name="All alerts" stroke="#38bdf8" strokeWidth={2} fill="url(#gTotal)" />
          <Area type="monotone" dataKey="high" name="High" stroke="#f97316" strokeWidth={1.5} fill="none" />
          <Area type="monotone" dataKey="critical" name="Critical" stroke="#ef4444" strokeWidth={1.5} fill="none" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
