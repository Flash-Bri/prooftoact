export function compareCanonicalKeys(left, right) {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => compareCanonicalKeys(left, right))
      .map(
        ([key, nested]) =>
          `${JSON.stringify(key)}:${canonicalJson(nested)}`
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
