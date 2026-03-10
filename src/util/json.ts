/**
 * JSON.stringify with sorted keys to match Go's json.Marshal behavior
 * Go always sorts object keys alphabetically when marshaling
 */
export function jsonStringifySorted(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => jsonStringifySorted(item)).join(',') + ']';
  }
  // Sort keys alphabetically
  const record = obj as Record<string, unknown>;
  const sortedKeys = Object.keys(record).sort();
  const pairs = sortedKeys.map(key => {
    const value = jsonStringifySorted(record[key]);
    return JSON.stringify(key) + ':' + value;
  });
  return '{' + pairs.join(',') + '}';
}
