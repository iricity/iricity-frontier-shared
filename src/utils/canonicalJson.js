function normalize(value) {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map((item) => normalize(item));
  if (typeof value !== 'object') return value;

  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = normalize(value[key]);
  }
  return sorted;
}

export function canonicalJson(value) {
  return JSON.stringify(normalize(value));
}
