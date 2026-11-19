import { useEffect, useRef } from 'react';
import type { PermissionNode } from '../engines/permissionGraphEngine';

interface ThreatTopology3DProps {
  nodes: PermissionNode[];
  blastRadiusScore: number;
}

/**
 * Lightweight 60fps 3D perspective-projected containment topology canvas.
 * Zero heavy WebGL context crashes, respects prefers-reduced-motion, interactive mouse drag/hover.
 */
export function ThreatTopology3D({ nodes, blastRadiusScore }: ThreatTopology3DProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const pointerRef = useRef({ x: 0, y: 0 });

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReduced =
      typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let animId = 0;
    let angleY = 0.4;
    let angleX = 0.25;

    const activeNodes =
      nodes.length > 0
        ? nodes
        : [
            {
              id: 'ZERO_TRUST_CORE',
              label: 'Air-Gap Clean',
              category: 'NETWORK' as const,
              risk: 'LOW' as const
            }
          ];

    // Golden-angle Fibonacci sphere distribution for crisp 3D spacing
    const points = activeNodes.map((node, i) => {
      const n = activeNodes.length;
      const y = n === 1 ? 0 : 1 - (i / (n - 1)) * 2;
      const radiusAtY = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = i * 2.399963229728653;
      return {
        node,
        x: Math.cos(theta) * radiusAtY,
        y,
        z: Math.sin(theta) * radiusAtY
      };
    });

    const isCritical = blastRadiusScore >= 70;
    const isMedium = blastRadiusScore >= 30 && blastRadiusScore < 70;
    const coreColor = isCritical ? '#EF4444' : isMedium ? '#F59E0B' : '#22C55E';
    const ringColor = isCritical
      ? 'rgba(239, 68, 68, 0.24)'
      : isMedium
        ? 'rgba(245, 158, 11, 0.24)'
        : 'rgba(34, 197, 94, 0.28)';

    const render = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const rect = canvas.getBoundingClientRect();
      const w = Math.max(260, Math.floor(rect.width));
      const h = Math.max(240, Math.floor(rect.height));

      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
      }

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const cx = w / 2;
      const cy = h / 2;
      const radius = Math.min(w, h) * 0.34;

      if (!prefersReduced) {
        angleY += 0.0055 + pointerRef.current.x * 0.004;
        angleX = 0.24 + pointerRef.current.y * 0.28;
      }

      const cosY = Math.cos(angleY);
      const sinY = Math.sin(angleY);
      const cosX = Math.cos(angleX);
      const sinX = Math.sin(angleX);

      // Subtle wireframe orbital rings
      ctx.strokeStyle = ringColor;
      ctx.lineWidth = 1;
      for (const tilt of [-0.55, 0, 0.55]) {
        ctx.beginPath();
        for (let step = 0; step <= 64; step++) {
          const t = (step / 64) * Math.PI * 2;
          const rx = Math.cos(t);
          const ry = Math.sin(t) * Math.sin(tilt);
          const rz = Math.sin(t) * Math.cos(tilt);
          const x1 = rx * cosY - rz * sinY;
          const z1 = rx * sinY + rz * cosY;
          const y2 = ry * cosX - z1 * sinX;
          const z2 = ry * sinX + z1 * cosX;
          const scale = 2.6 / (2.6 - z2 * 0.65);
          const px = cx + x1 * radius * scale;
          const py = cy + y2 * radius * scale;
          if (step === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.stroke();
      }

      // Project all permission nodes
      const projected = points.map((pt) => {
        const x1 = pt.x * cosY - pt.z * sinY;
        const z1 = pt.x * sinY + pt.z * cosY;
        const y2 = pt.y * cosX - z1 * sinX;
        const z2 = pt.y * sinX + z1 * cosX;
        const scale = 2.6 / (2.6 - z2 * 0.65);
        return {
          node: pt.node,
          px: cx + x1 * radius * scale,
          py: cy + y2 * radius * scale,
          z: z2,
          scale
        };
      });

      // Draw exfiltration tether beams from core to high-risk nodes
      for (const p of projected) {
        const isDanger = p.node.risk === 'CRITICAL' || p.node.risk === 'HIGH';
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(p.px, p.py);
        ctx.strokeStyle = isDanger
          ? `rgba(239, 68, 68, ${0.18 + (p.z + 1) * 0.22})`
          : `rgba(34, 197, 94, ${0.16 + (p.z + 1) * 0.16})`;
        ctx.lineWidth = isDanger ? 1.4 : 1;
        ctx.stroke();
      }

      // Central Device Privacy Core
      const glow = ctx.createRadialGradient(cx, cy, 4, cx, cy, 34);
      glow.addColorStop(0, coreColor);
      glow.addColorStop(1, 'rgba(7, 11, 20, 0)');
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(cx, cy, 34, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#070B14';
      ctx.strokeStyle = coreColor;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(cx, cy, 13, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      // Depth-sorted permission nodes with 2D label collision suppression
      projected.sort((a, b) => a.z - b.z);
      const placedLabels: Array<{ x: number; y: number; w: number; h: number }> = [];
      for (const p of projected) {
        const nodeColor =
          p.node.risk === 'CRITICAL'
            ? '#EF4444'
            : p.node.risk === 'HIGH'
              ? '#F59E0B'
              : p.node.risk === 'MEDIUM'
                ? '#38BDF8'
                : '#22C55E';
        const dotR = (p.node.risk === 'CRITICAL' ? 5.5 : 4.2) * p.scale;

        ctx.fillStyle = nodeColor;
        ctx.beginPath();
        ctx.arc(p.px, p.py, dotR, 0, Math.PI * 2);
        ctx.fill();

        if (p.z > -0.25 || projected.length <= 8) {
          ctx.font = '500 10px "JetBrains Mono", monospace';
          const textW = ctx.measureText(p.node.label).width;
          const lx = Math.min(w - textW - 8, Math.max(8, p.px + dotR + 6));
          const ly = Math.min(h - 14, Math.max(24, p.py + 3));
          const overlaps = placedLabels.some(
            (b) => lx < b.x + b.w + 6 && lx + textW + 6 > b.x && ly - 10 < b.y + 4 && ly + 4 > b.y - 10
          );
          if (!overlaps) {
            placedLabels.push({ x: lx, y: ly, w: textW, h: 12 });
            ctx.fillStyle = `rgba(241, 245, 249, ${Math.min(1, 0.56 + (p.z + 1) * 0.32)})`;
            ctx.fillText(p.node.label, lx, ly);
          }
        }
      }

      if (!prefersReduced) {
        animId = requestAnimationFrame(render);
      }
    };

    render();
    return () => cancelAnimationFrame(animId);
  }, [nodes, blastRadiusScore]);

  return (
    <div
      className="relative h-72 w-full overflow-hidden rounded-xl border border-slate-800/90 bg-[#060A13]"
      onMouseMove={(e) => {
        const r = e.currentTarget.getBoundingClientRect();
        pointerRef.current = {
          x: ((e.clientX - r.left) / r.width - 0.5) * 2,
          y: ((e.clientY - r.top) / r.height - 0.5) * 2
        };
      }}
      onMouseLeave={() => {
        pointerRef.current = { x: 0, y: 0 };
      }}
    >
      <canvas ref={canvasRef} className="h-full w-full" aria-label="3D Permission Containment Topology" />
      <div className="pointer-events-none absolute top-3 left-3 flex items-center gap-2 rounded-md border border-slate-800 bg-[#070B14]/85 px-2.5 py-1 text-[11px] font-mono text-slate-300">
        <span
          className={`h-2 w-2 rounded-full ${
            blastRadiusScore >= 70
              ? 'bg-red-500'
              : blastRadiusScore >= 30
                ? 'bg-amber-400'
                : 'bg-emerald-500'
          }`}
        />
        3D PERMISSION TOPOLOGY // {nodes.length} NODES
      </div>
      <div className="pointer-events-none absolute right-3 bottom-3 rounded-md border border-slate-800 bg-[#070B14]/85 px-2.5 py-1 text-[11px] font-mono text-slate-400">
        MOVE CURSOR TO ORBIT
      </div>
    </div>
  );
}
