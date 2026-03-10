/**
 * Joins JWT segments with a period separator
 */
export function joinJWTSegments(...segments: Uint8Array[]): Uint8Array {
  return joinBytes('.'.charCodeAt(0), ...segments);
}

/**
 * Joins byte arrays with a specified separator byte
 */
export function joinBytes(sep: number, ...things: Uint8Array[]): Uint8Array {
  const totalLength = things.reduce((sum, arr) => sum + arr.length, 0) + (things.length - 1);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (let i = 0; i < things.length; i++) {
    result.set(things[i], offset);
    offset += things[i].length;
    if (i < things.length - 1) {
      result[offset] = sep;
      offset++;
    }
  }
  return result;
}

/**
 * Concatenates multiple byte arrays into one
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Checks if two byte arrays are equal
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
