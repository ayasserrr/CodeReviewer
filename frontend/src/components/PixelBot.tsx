/**
 * "Revi" — a tiny pixel-art code inspector that patrols the top edge of a card:
 * walks, stops to scan with its magnifier, blinks, turns around. Pure SVG + CSS
 * (no images, no JS timers); decorative only, hidden from assistive tech, and
 * frozen when the user prefers reduced motion.
 *
 * Usage: give the host element `position: relative` (the `.has-bot` class) and
 * render <PixelBot /> inside it.
 */

// 16 x 12 pixel grid; each entry is [x, y, w, h] in grid cells.
type Px = [number, number, number, number];

const ANTENNA: Px[] = [[6, 1, 1, 1]];
const ANTENNA_TIP: Px[] = [[6, 0, 1, 1]];
const HEAD: Px[] = [[2, 2, 9, 1], [1, 3, 11, 4], [2, 7, 9, 1]];
const VISOR: Px[] = [[3, 4, 7, 2]];
const EYES: Px[] = [[4, 4, 1, 2], [8, 4, 1, 2]];
const BODY: Px[] = [[3, 8, 7, 1]];
const LEGS_A: Px[] = [[3, 9, 1, 2], [8, 9, 1, 2]];
const LEGS_B: Px[] = [[4, 9, 1, 2], [9, 9, 1, 2]];
const HANDLE: Px[] = [[11, 7, 1, 1], [12, 6, 1, 1]];
const LENS_RING: Px[] = [[13, 3, 2, 1], [12, 4, 1, 2], [15, 4, 1, 2], [13, 6, 2, 1]];
const LENS_GLASS: Px[] = [[13, 4, 2, 2]];

function Pixels({ cells, className }: { cells: Px[]; className?: string }) {
  return (
    <g className={className}>
      {cells.map(([x, y, w, h]) => <rect key={`${x}-${y}`} x={x} y={y} width={w} height={h} />)}
    </g>
  );
}

export function PixelBot({ speed = "normal" }: { speed?: "normal" | "busy" }) {
  return (
    <div className={`pixelbot-track${speed === "busy" ? " busy" : ""}`} aria-hidden="true">
      <div className="pixelbot">
        <svg viewBox="0 0 16 12" width={48} height={36} shapeRendering="crispEdges">
          <Pixels cells={ANTENNA} className="pb-body" />
          <Pixels cells={ANTENNA_TIP} className="pb-tip" />
          <Pixels cells={HEAD} className="pb-body" />
          <Pixels cells={VISOR} className="pb-visor" />
          <Pixels cells={EYES} className="pb-eyes" />
          <Pixels cells={BODY} className="pb-body" />
          <Pixels cells={LEGS_A} className="pb-body pb-legs-a" />
          <Pixels cells={LEGS_B} className="pb-body pb-legs-b" />
          <g className="pb-tool">
            <Pixels cells={HANDLE} className="pb-handle" />
            <Pixels cells={LENS_RING} className="pb-handle" />
            <Pixels cells={LENS_GLASS} className="pb-glass" />
          </g>
        </svg>
      </div>
    </div>
  );
}
