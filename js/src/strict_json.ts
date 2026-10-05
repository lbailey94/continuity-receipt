/**
 * Strict raw JSON parsing for signed receipt and verification inputs.
 *
 * Mirrors `continuity_receipt/strict_json.py`: duplicate object members are
 * rejected at the text boundary. On top of that it preserves number fidelity:
 * integers beyond `Number.MAX_SAFE_INTEGER` become `bigint` and any number
 * written with a fraction or exponent becomes a `JsonFloat` marker, because
 * Python's parser keeps arbitrary-precision ints and floats are later rejected
 * by canonicalization.
 */

export class StrictJsonError extends Error {
  override name = "StrictJsonError";
}

export class StrictJsonNestingError extends StrictJsonError {
  override name = "StrictJsonNestingError";
}

/** A JSON number written with `.` or an exponent (always a Python float). */
export class JsonFloat {
  constructor(readonly text: string) {}
}

const MAX_PARSE_DEPTH = 1000;

export function parseStrictJson(input: string | Uint8Array): unknown {
  let text: string;
  if (typeof input === "string") {
    text = input;
  } else {
    if (input.length >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) {
      throw new StrictJsonError("unexpected UTF-8 BOM");
    }
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input);
    } catch {
      throw new StrictJsonError("input is not valid UTF-8");
    }
  }
  if (text.charCodeAt(0) === 0xfeff) {
    throw new StrictJsonError("unexpected UTF-8 BOM");
  }

  let position = 0;

  const fail = (message: string): never => {
    throw new StrictJsonError(`${message} at position ${position}`);
  };

  const skipWhitespace = (): void => {
    while (position < text.length) {
      const code = text.charCodeAt(position);
      if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) position++;
      else break;
    }
  };

  const parseString = (): string => {
    const start = position;
    position++; // opening quote
    while (position < text.length) {
      const code = text.charCodeAt(position);
      if (code === 0x22) {
        position++;
        try {
          return JSON.parse(text.slice(start, position)) as string;
        } catch {
          return fail("malformed string");
        }
      }
      if (code === 0x5c) {
        position += 2; // JSON.parse validates the escape when the string closes
        continue;
      }
      if (code < 0x20) fail("unescaped control character in string");
      position++;
    }
    return fail("unterminated string");
  };

  const parseNumber = (): number | bigint | JsonFloat => {
    const pattern = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
    pattern.lastIndex = position;
    const match = pattern.exec(text);
    if (match === null || match.index !== position) return fail("invalid JSON number");
    position = pattern.lastIndex;
    const literal = match[0];
    const next = text[position];
    if (next !== undefined && next !== "," && next !== "]" && next !== "}" &&
        next !== " " && next !== "\t" && next !== "\n" && next !== "\r") {
      return fail("invalid JSON number");
    }
    if (literal.includes(".") || literal.includes("e") || literal.includes("E")) {
      return new JsonFloat(literal);
    }
    const big = BigInt(literal);
    if (big >= BigInt(Number.MIN_SAFE_INTEGER) && big <= BigInt(Number.MAX_SAFE_INTEGER)) {
      return Number(big);
    }
    return big;
  };

  const parseObject = (depth: number): Record<string, unknown> => {
    position++; // opening brace
    skipWhitespace();
    const object: Record<string, unknown> = {};
    if (text[position] === "}") {
      position++;
      return object;
    }
    const seen = new Set<string>();
    for (;;) {
      skipWhitespace();
      if (text[position] !== '"') return fail("expected object key");
      const key = parseString();
      if (seen.has(key)) {
        throw new StrictJsonError(`duplicate JSON object member: ${JSON.stringify(key)}`);
      }
      seen.add(key);
      skipWhitespace();
      if (text[position] !== ":") return fail("expected ':'");
      position++;
      object[key] = parseValue(depth + 1);
      skipWhitespace();
      const delimiter = text[position];
      if (delimiter === ",") {
        position++;
        continue;
      }
      if (delimiter === "}") {
        position++;
        return object;
      }
      return fail("expected ',' or '}'");
    }
  };

  const parseArray = (depth: number): unknown[] => {
    position++; // opening bracket
    skipWhitespace();
    const array: unknown[] = [];
    if (text[position] === "]") {
      position++;
      return array;
    }
    for (;;) {
      array.push(parseValue(depth + 1));
      skipWhitespace();
      const delimiter = text[position];
      if (delimiter === ",") {
        position++;
        continue;
      }
      if (delimiter === "]") {
        position++;
        return array;
      }
      return fail("expected ',' or ']'");
    }
  };

  const parseValue = (depth: number): unknown => {
    if (depth > MAX_PARSE_DEPTH) {
      throw new StrictJsonNestingError("JSON nesting exceeds the parser limit");
    }
    skipWhitespace();
    const char = text[position];
    if (char === undefined) return fail("unexpected end of JSON input");
    if (char === '"') return parseString();
    if (char === "{") return parseObject(depth);
    if (char === "[") return parseArray(depth);
    if (char === "t" && text.startsWith("true", position)) {
      position += 4;
      return true;
    }
    if (char === "f" && text.startsWith("false", position)) {
      position += 5;
      return false;
    }
    if (char === "n" && text.startsWith("null", position)) {
      position += 4;
      return null;
    }
    if (char === "-" || (char >= "0" && char <= "9")) return parseNumber();
    return fail("invalid JSON value");
  };

  const value = parseValue(0);
  skipWhitespace();
  if (position !== text.length) throw new StrictJsonError("extra data after JSON value");
  return value;
}
