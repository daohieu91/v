export function parseCheckedAt(j: unknown): string | null {
  const v = (j as { checkedAt?: unknown } | null)?.checkedAt;
  return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : null;
}
