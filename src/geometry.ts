/**
 * P41 + P41b: was the received picture cropped? Two independent signals, both from what the seal SIGNS:
 *  1. the aspect (P41b): the app signs round(w / h × 10000) of the composed image. A uniform resize keeps it within rounding; a crop on
 *     one axis does not.
 *  2. the QR's geometry (P41): the app places the QR deterministically (StampLayout.kt, QrRenderer.kt), from the image size and the
 *     signed stamp frame. A crop proportional on both axes keeps the aspect but makes the QR too large, or puts it in the wrong place,
 *     relative to the picture.
 * Ports below are rule for rule, in single precision where the app computes in Float (Kotlin Float = IEEE binary32).
 */
const f32 = Math.fround;
export const SEAL_SIDE_MODULES = 61;          // QrRenderer: version 9 (53 modules) + 2 × 4 quiet-zone modules
export const SYMBOL_MODULES = 53;
const QUIET = 4;
const MIN_MODULE_PX = 3;
const QR_SIDE_FRACTION = f32(0.1525);        // VerifyConfig.QR_SIDE_FRACTION
const QR_MAX_WIDTH = f32(0.25);
const MAX_PANEL_HEIGHT = f32(0.6);
const PAD = f32(0.02), MARGIN = f32(0.02);
const QR_LONG_SIDE_DIVISOR = 8;
/** Java/Kotlin Math.round(Float): floor(x + 0.5) of the exact float value. */
const roundF = (x: number) => Math.floor(x + 0.5);
/** Float.toInt(): truncation toward zero (inputs here are finite and small). */
const toInt = (x: number) => Math.trunc(x);

/** StampLayoutEngine.byFractions: the width term, or the long-side term rounded UP to whole modules when it is larger (P27a). */
function byFractions(w: number, h: number): number {
  const byWidth = roundF(f32(w * QR_SIDE_FRACTION));
  const long = Math.max(w, h);
  if (long <= QR_LONG_SIDE_DIVISOR * byWidth) return byWidth;
  const perModule = QR_LONG_SIDE_DIVISOR * SEAL_SIDE_MODULES;
  return Math.floor((long + perModule - 1) / perModule) * SEAL_SIDE_MODULES;
}
/** StampLayoutEngine.qrSidePx (P27/P27a): max(0.1525·w, 0.125·long side in whole modules), floored at 3 px/module, capped. */
export function qrSidePx(w: number, h: number): number {
  return Math.max(0, Math.min(
    Math.max(byFractions(w, h), SEAL_SIDE_MODULES * MIN_MODULE_PX),
    toInt(f32(w * QR_MAX_WIDTH)),
    toInt(f32(f32(h * MAX_PANEL_HEIGHT) - f32(f32(2 * w) * PAD))),
  ));
}
/** The QR square's left edge: floor(panelLeft + panelW − pad − side), FULL-width panel (COMPACT_END differs by float rounding only). */
export function qrLeftPx(w: number, side: number): number {
  const margin = f32(w * MARGIN), pad = f32(w * PAD);
  const panelW = f32(w - f32(2 * margin));
  return Math.floor(f32(f32(f32(margin + panelW) - pad) - side));
}
export interface Model { cell: number; symX: number; symYlo: number; symYhi: number }
/**
 * Where the app put the 53-module symbol on a w × h image whose signed frame starts at y0 (1/255ths, SealFrame.fromPanel = floor − 1):
 * the panel top lies in [(y0+1)·h/255, (y0+2)·h/255), the QR square at floor(top + pad), the symbol at the square + the centred
 * remainder (QrRenderer: (side − 61·cell) / 2) + 4 quiet modules. Null when this size draws no QR (P7: under 3 px/module).
 */
export function model(w: number, h: number, y0: number, sideOf: (w: number, h: number) => number = qrSidePx): Model | null {
  const side = sideOf(w, h); const cell = Math.floor(side / SEAL_SIDE_MODULES);
  if (cell < MIN_MODULE_PX) return null;
  const off = Math.floor((side - cell * SEAL_SIDE_MODULES) / 2) + QUIET * cell;
  const pad = f32(w * PAD);
  const lo = y0 === 0 ? 0 : ((y0 + 1) * h) / 255, hi = ((y0 + 2) * h) / 255;
  return { cell, symX: qrLeftPx(w, side) + off, symYlo: Math.floor(lo + pad) + off, symYhi: Math.floor(hi + pad) + off };
}
/** P41b: round(w / h × 10000) clamped to 1..65535, integer maths (SealFields.aspectOf). */
export const aspectOf = (w: number, h: number) => Math.min(65535, Math.max(1, Math.floor((w * 20000 + h) / (2 * h))));

export type Pt = { x: number; y: number };
/** jsQR's three finder-pattern centres, in the full-resolution coordinates of the received picture. */
export interface Finders { tl: Pt; tr: Pt; bl: Pt }
export type GeometryResult = { kind: 'ok' | 'mismatch' | 'unknown'; aspectDelta: number | null; residual: number | null };
/**
 * Calibrated tolerances (scripts/calibrate-geometry.mts, 2026-10-06; final review I5 rule):
 * corpus: 28 app-made originals — the app's 2000 × 1500 fixture (v1 payload), the 17 real Galaxy M20 photos of Task 10B (2448 × 3264,
 * pre-P27a sizing) and 10 sizes composed by the app's StampLayout in the 10C spike (portrait, landscape, panoramas, API 24, OOM step-down;
 * x and size only) — and 3 032 unedited shares of them (long side 2560…720, lanczos3/cubic/linear/nearest, JPEG q65–q92, decoded like
 * Chromium/Firefox): max aspect difference 0.0009, max QR residual 0.29 modules, 0 flagged.
 *  - ASPECT_TOL = max + 0.002 → 0.003 (relative).
 *  - GEOMETRY_TOL = max + 0.5 = 0.79, raised to the 1-module floor → 1.0 (modules of the received QR).
 * Crops at these values: 2, 3, 5 and 10 % off any one side → 100 % flagged whenever the QR survives; 5 and 10 % off two adjacent sides
 * keeping the aspect → 100 % flagged on every photo whose frame is known (the 10C spike photos carry no frame, so only x and size there).
 */
export const ASPECT_TOL = 0.003;
export const GEOMETRY_TOL = 1.0;
const dist = (a: Pt, b: Pt) => Math.hypot(a.x - b.x, a.y - b.y);

/**
 * The QR residual (in received modules) of the best explanation of what we see as an UNCROPPED resize of an app photo: over every
 * module size c the app may have used and every original width near W'·c/m', the max of the symbol-size, x and y misfits. Null when
 * the finders are not an upright square (rotated, skewed, a photo of a screen): no geometry claim is made then.
 */
export function qrResidual(f: Finders, w: number, h: number, frameY0: number | null, aspect: number,
  sideOf: (w: number, h: number) => number = qrSidePx): number | null {
  const mx = dist(f.tl, f.tr) / (SYMBOL_MODULES - 7), my = dist(f.tl, f.bl) / (SYMBOL_MODULES - 7);
  if (!(mx > 0 && my > 0) || Math.abs(mx / my - 1) > 0.03) return null;
  // Upright only: TR to the right of TL and BL below it, each within ~2°.
  if (Math.abs(f.tr.y - f.tl.y) > 0.035 * dist(f.tl, f.tr) || Math.abs(f.bl.x - f.tl.x) > 0.035 * dist(f.tl, f.bl) || f.tr.x <= f.tl.x || f.bl.y <= f.tl.y) return null;
  const m = (mx + my) / 2; const sx = f.tl.x - 3.5 * m, sy = f.tl.y - 3.5 * m;
  let best = Infinity;
  for (let c = MIN_MODULE_PX; c <= 60; c++) {
    const est = (w * c) / m; const lo = Math.max(1, Math.floor(est * 0.9)), hi = Math.ceil(est * 1.1);
    for (let W = lo; W <= hi; W++) {
      const H = Math.max(1, Math.round((W * 10000) / aspect));
      const p = model(W, H, frameY0 ?? 0, sideOf); if (!p || p.cell !== c) continue;
      const k = w / W;
      const ds = (SYMBOL_MODULES * Math.abs(m - k * c)) / m;
      const dx = Math.abs(sx - k * p.symX) / m;
      const dy = frameY0 === null ? 0 : Math.max(0, k * p.symYlo - sy, sy - k * p.symYhi) / m;   // null: calibration only (y0 unknown)
      const s = Math.max(ds, dx, dy); if (s < best) best = s;
    }
  }
  return best;
}
/**
 * Mismatch when the received aspect differs from the signed one beyond ASPECT_TOL, or (finders known) no uncropped explanation fits
 * within GEOMETRY_TOL modules. `finders` null (no QR in the picture) → only the aspect is compared.
 */
export function checkGeometry(sealed: { frame: readonly number[]; aspect: number }, finders: Finders | null, w: number, h: number): GeometryResult {
  const aspectDelta = Math.abs(aspectOf(w, h) - sealed.aspect) / sealed.aspect;
  const residual = finders ? qrResidual(finders, w, h, sealed.frame[1], sealed.aspect) : null;
  if (aspectDelta > ASPECT_TOL || (residual !== null && residual > GEOMETRY_TOL)) return { kind: 'mismatch', aspectDelta, residual };
  return { kind: residual === null ? 'unknown' : 'ok', aspectDelta, residual };
}
