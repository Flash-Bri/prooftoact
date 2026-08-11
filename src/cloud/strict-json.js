const STRICT_JSON_MAX_DEPTH = 64;

function rejectStrictJson(code) {
  throw new Error(code);
}
function skipStrictJsonWhitespace(text, state) {
  while (
    state.index < text.length &&
    /[\u0009\u000a\u000d\u0020]/u.test(text[state.index])
  ) {
    state.index += 1;
  }
}

function scanStrictJsonString(text, state, invalidCode) {
  if (text[state.index] !== '"') {
    rejectStrictJson(invalidCode);
  }
  state.index += 1;
  let decoded = "";
  while (state.index < text.length) {
    const character = text[state.index];
    const codeUnit = text.charCodeAt(state.index);
    if (character === '"') {
      state.index += 1;
      return decoded;
    }
    if (codeUnit <= 0x1f) {
      rejectStrictJson(invalidCode);
    }
    if (character !== "\\") {
      decoded += character;
      state.index += 1;
      continue;
    }
    state.index += 1;
    const escaped = text[state.index];
    if (escaped === undefined) {
      rejectStrictJson(invalidCode);
    }
    const simpleEscapes = Object.freeze({
      '"': '"',
      "\\": "\\",
      "/": "/",
      b: "\b",
      f: "\f",
      n: "\n",
      r: "\r",
      t: "\t"
    });
    if (Object.hasOwn(simpleEscapes, escaped)) {
      decoded += simpleEscapes[escaped];
      state.index += 1;
      continue;
    }
    if (escaped !== "u") {
      rejectStrictJson(invalidCode);
    }
    const hexadecimal = text.slice(state.index + 1, state.index + 5);
    if (!/^[0-9a-fA-F]{4}$/u.test(hexadecimal)) {
      rejectStrictJson(invalidCode);
    }
    decoded += String.fromCharCode(Number.parseInt(hexadecimal, 16));
    state.index += 5;
  }
  rejectStrictJson(invalidCode);
}

function scanStrictJsonNumber(text, state, invalidCode) {
  const match = text.slice(state.index).match(
    /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u
  );
  if (match === null || !Number.isFinite(Number(match[0]))) {
    rejectStrictJson(invalidCode);
  }
  state.index += match[0].length;
}

function scanStrictJsonValue(
  text,
  state,
  { duplicateCode, invalidCode, maxDepth },
  depth = 0
) {
  if (depth > maxDepth) {
    rejectStrictJson(invalidCode);
  }
  skipStrictJsonWhitespace(text, state);
  const character = text[state.index];
  if (character === '"') {
    scanStrictJsonString(text, state, invalidCode);
    return;
  }
  if (character === "{") {
    state.index += 1;
    skipStrictJsonWhitespace(text, state);
    const members = new Set();
    if (text[state.index] === "}") {
      state.index += 1;
      return;
    }
    while (state.index < text.length) {
      const member = scanStrictJsonString(text, state, invalidCode);
      if (members.has(member)) {
        rejectStrictJson(duplicateCode);
      }
      members.add(member);
      skipStrictJsonWhitespace(text, state);
      if (text[state.index] !== ":") {
        rejectStrictJson(invalidCode);
      }
      state.index += 1;
      scanStrictJsonValue(
        text,
        state,
        { duplicateCode, invalidCode, maxDepth },
        depth + 1
      );
      skipStrictJsonWhitespace(text, state);
      if (text[state.index] === "}") {
        state.index += 1;
        return;
      }
      if (text[state.index] !== ",") {
        rejectStrictJson(invalidCode);
      }
      state.index += 1;
      skipStrictJsonWhitespace(text, state);
    }
    rejectStrictJson(invalidCode);
  }
  if (character === "[") {
    state.index += 1;
    skipStrictJsonWhitespace(text, state);
    if (text[state.index] === "]") {
      state.index += 1;
      return;
    }
    while (state.index < text.length) {
      scanStrictJsonValue(
        text,
        state,
        { duplicateCode, invalidCode, maxDepth },
        depth + 1
      );
      skipStrictJsonWhitespace(text, state);
      if (text[state.index] === "]") {
        state.index += 1;
        return;
      }
      if (text[state.index] !== ",") {
        rejectStrictJson(invalidCode);
      }
      state.index += 1;
      skipStrictJsonWhitespace(text, state);
    }
    rejectStrictJson(invalidCode);
  }
  for (const literal of ["true", "false", "null"]) {
    if (text.startsWith(literal, state.index)) {
      state.index += literal.length;
      return;
    }
  }
  scanStrictJsonNumber(text, state, invalidCode);
}

export function parseStrictJson(
  text,
  {
    duplicateCode = "STRICT_JSON_DUPLICATE_MEMBER",
    invalidCode = "STRICT_JSON_INVALID",
    maxDepth = STRICT_JSON_MAX_DEPTH
  } = {}
) {
  if (
    typeof text !== "string" ||
    typeof duplicateCode !== "string" ||
    duplicateCode.length === 0 ||
    typeof invalidCode !== "string" ||
    invalidCode.length === 0 ||
    !Number.isSafeInteger(maxDepth) ||
    maxDepth < 1
  ) {
    throw new TypeError("strict JSON parser configuration is invalid");
  }
  const state = { index: 0 };
  scanStrictJsonValue(
    text,
    state,
    { duplicateCode, invalidCode, maxDepth }
  );
  skipStrictJsonWhitespace(text, state);
  if (state.index !== text.length) {
    rejectStrictJson(invalidCode);
  }
  try {
    return JSON.parse(text);
  } catch {
    rejectStrictJson(invalidCode);
  }
}
