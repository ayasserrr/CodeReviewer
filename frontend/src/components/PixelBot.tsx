/**
 * "Revi" — a pixel-art code inspector patrolling a lane in the page header.
 *
 * He walks (two-frame stride + bob), stops, raises his magnifier to his eye and
 * inspects a bug on the ground; the bug turns into a check, and he walks on,
 * turns around at the end of the lane and does it again. Pure SVG + CSS keyframes
 * (no JS timers), decorative only (aria-hidden), frozen under reduced motion.
 */

// 18 x 12 pixel grid, facing right; each entry is [x, y, w, h] in cells.
type Px = [number, number, number, number];

const ANTENNA: Px[] = [[6, 1, 1, 1]];
const ANTENNA_TIP: Px[] = [[6, 0, 1, 1]];
const HEAD: Px[] = [[2, 2, 9, 1], [1, 3, 11, 4], [2, 7, 9, 1]];
const VISOR: Px[] = [[3, 4, 7, 2]];
const EYE_LEFT: Px[] = [[4, 4, 1, 2]];
const EYE_RIGHT: Px[] = [[8, 4, 1, 2]];
const BODY: Px[] = [[3, 8, 7, 1]];

// Walking: stride (legs apart) and passing (legs together) frames.
const LEGS_STRIDE: Px[] = [[3, 9, 1, 1], [2, 10, 1, 1], [8, 9, 1, 1], [9, 10, 1, 1]];
const LEGS_PASS: Px[] = [[4, 9, 1, 2], [7, 9, 1, 2]];
// Magnifier carried low at his side while walking.
const CARRY_HANDLE: Px[] = [[11, 7, 1, 1], [12, 8, 1, 1]];
const CARRY_RING: Px[] = [[14, 7, 1, 1], [13, 8, 1, 1], [15, 8, 1, 1], [14, 9, 1, 1]];
const CARRY_GLASS: Px[] = [[14, 8, 1, 1]];

// Scanning: legs planted, lens raised to the right eye, eye magnified behind it.
const LEGS_PLANTED: Px[] = [[3, 9, 1, 2], [8, 9, 1, 2]];
const SCOPE_RING: Px[] = [[8, 1, 4, 1], [7, 2, 1, 5], [12, 2, 1, 5], [8, 7, 4, 1]];
const SCOPE_GLASS: Px[] = [[8, 2, 4, 5]];
const SCOPE_EYE: Px[] = [[9, 3, 2, 3]];
const SCOPE_HANDLE: Px[] = [[13, 7, 1, 1], [14, 8, 1, 1], [15, 9, 1, 1]];
const SCOPE_SHINE: Px[] = [[8, 2, 1, 1]];

// The "finding" he inspects: a pixel bug, then a check mark.
const BUG: Px[] = [[1, 0, 1, 1], [4, 0, 1, 1], [2, 1, 2, 1], [1, 2, 4, 2], [0, 2, 1, 1], [5, 2, 1, 1], [0, 4, 1, 1], [5, 4, 1, 1]];
const CHECK: Px[] = [[0, 2, 1, 1], [1, 3, 1, 1], [2, 4, 1, 1], [3, 3, 1, 1], [4, 2, 1, 1], [5, 1, 1, 1]];

function Pixels({ cells, className }: { cells: Px[]; className?: string }) {
  return (
    <g className={className}>
      {cells.map(([x, y, w, h]) => <rect key={`${x}-${y}-${w}`} x={x} y={y} width={w} height={h} />)}
    </g>
  );
}

function Finding({ spot }: { spot: 1 | 2 }) {
  return (
    <svg className={`pb-finding pb-finding-${spot}`} viewBox="0 0 6 5" width={18} height={15} shapeRendering="crispEdges">
      <Pixels cells={BUG} className="pb-bug" />
      <Pixels cells={CHECK} className="pb-check" />
    </svg>
  );
}

export function PixelBot({ busy = false, label }: { busy?: boolean; label?: string }) {
  return (
    <div className={`patrol${busy ? " busy" : ""}`} aria-hidden="true">
      <div className="patrol-ground" />
      {label && <span className="patrol-label">{label}</span>}
      <Finding spot={1} />
      <Finding spot={2} />
      <div className="pixelbot">
        <svg viewBox="0 0 18 12" width={54} height={36} shapeRendering="crispEdges">
          <Pixels cells={ANTENNA} className="pb-body" />
          <Pixels cells={ANTENNA_TIP} className="pb-tip" />
          <Pixels cells={HEAD} className="pb-body" />
          <Pixels cells={VISOR} className="pb-visor" />
          <Pixels cells={EYE_LEFT} className="pb-eyes" />
          <Pixels cells={BODY} className="pb-body" />
          <g className="pb-walk">
            <Pixels cells={EYE_RIGHT} className="pb-eyes" />
            <Pixels cells={LEGS_STRIDE} className="pb-body pb-stride" />
            <Pixels cells={LEGS_PASS} className="pb-body pb-pass" />
            <Pixels cells={CARRY_HANDLE} className="pb-metal" />
            <Pixels cells={CARRY_RING} className="pb-metal" />
            <Pixels cells={CARRY_GLASS} className="pb-glass" />
          </g>
          <g className="pb-scan">
            <Pixels cells={LEGS_PLANTED} className="pb-body" />
            <Pixels cells={SCOPE_GLASS} className="pb-glass" />
            <Pixels cells={SCOPE_EYE} className="pb-eye-big" />
            <Pixels cells={SCOPE_SHINE} className="pb-shine" />
            <Pixels cells={SCOPE_RING} className="pb-metal" />
            <Pixels cells={SCOPE_HANDLE} className="pb-metal" />
          </g>
        </svg>
      </div>
    </div>
  );
}
