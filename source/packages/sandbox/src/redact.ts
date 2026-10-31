export const MAX_OUTPUT_BYTES = 64 * 1024;

const HEAD_FRACTION = 0.25;
// How far from a cut we look for a line break, so a secret is never split in half.
const LINE_SEARCH_BYTES = 1024;

// CSI / OSC / single-char escape sequences (same shape as the ansi-regex package).
const ANSI_PATTERN =
  /[\u001B\u009B][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d/#&.:=?%@~_]*)*)?(?:\u0007|\u001B\\))|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-ntqry=><~]))/g;
// Remaining C0/C1 controls except tab and newline.
const CONTROL_PATTERN = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;

export const REDACTED = "[redacted]";

const SECRET_PATTERNS: readonly [RegExp, string][] = [
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
    REDACTED,
  ],
  [/gh[pousr]_[A-Za-z0-9]{20,}/g, REDACTED],
  [/github_pat_[A-Za-z0-9_]{20,}/g, REDACTED],
  [/sk-[A-Za-z0-9\-_]{20,}/g, REDACTED],
  [/(Bearer\s+)[A-Za-z0-9\-._~+/]{8,}=*/gi, `$1${REDACTED}`],
  // user:password@ in URLs
  [/(\/\/)[^/\s:@]+:[^/\s@]+@/g, `$1${REDACTED}@`],
];

export function stripAnsi(text: string): string {
  return text
    .replace(/\r\n/g, "\n")
    .replace(ANSI_PATTERN, "")
    .replace(/\r/g, "\n")
    .replace(CONTROL_PATTERN, "");
}

/** Replaces token-looking strings, and any exact `secrets` passed in, with a marker. */
export function redact(text: string, secrets: readonly string[] = []): string {
  let out = text;
  for (const secret of secrets) {
    if (secret.length >= 4) out = out.split(secret).join(REDACTED);
  }
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

function isContinuationByte(byte: number | undefined): boolean {
  return byte !== undefined && (byte & 0xc0) === 0x80;
}

/** Byte length of a head slice ending at a line break near `limit`, else at a UTF-8 boundary. */
function headCut(bytes: Buffer, limit: number): number {
  const windowStart = Math.max(0, limit - LINE_SEARCH_BYTES);
  const newline = bytes.lastIndexOf(0x0a, limit - 1);
  if (newline >= windowStart) return newline + 1;
  let cut = limit;
  while (cut > 0 && isContinuationByte(bytes[cut])) cut -= 1;
  return cut;
}

/** Start offset of a tail slice beginning after a line break near `start`, else at a UTF-8 boundary. */
function tailCut(bytes: Buffer, start: number): number {
  const newline = bytes.indexOf(0x0a, start);
  if (newline !== -1 && newline < start + LINE_SEARCH_BYTES) return newline + 1;
  let cut = start;
  while (cut < bytes.length && isContinuationByte(bytes[cut])) cut += 1;
  return cut;
}

export function truncationMarker(omittedBytes: number): string {
  return `\n[… truncated ${omittedBytes} bytes …]\n`;
}

/**
 * Keeps the first quarter and the last part of `text` so the result is at most
 * `maxBytes` UTF-8 bytes, with a marker saying how much was dropped.
 */
export function capOutput(
  text: string,
  maxBytes: number = MAX_OUTPUT_BYTES,
): { text: string; truncated: boolean } {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length <= maxBytes) return { text, truncated: false };
  const reserve = Buffer.byteLength(truncationMarker(bytes.length));
  const budget = Math.max(0, maxBytes - reserve);
  const headEnd = headCut(bytes, Math.floor(budget * HEAD_FRACTION));
  const tailStart = tailCut(bytes, bytes.length - (budget - headEnd));
  const omitted = tailStart - headEnd;
  return {
    text:
      bytes.subarray(0, headEnd).toString("utf8") +
      truncationMarker(omitted) +
      bytes.subarray(tailStart).toString("utf8"),
    truncated: true,
  };
}

/** strip ANSI → redact → cap: the only form in which command output leaves the sandbox. */
export function sanitizeOutput(
  text: string,
  secrets: readonly string[] = [],
  maxBytes: number = MAX_OUTPUT_BYTES,
): { text: string; truncated: boolean } {
  return capOutput(redact(stripAnsi(text), secrets), maxBytes);
}

/**
 * Collects a stream while holding at most `head + tail` bytes in memory, so a
 * chatty command cannot exhaust the host. Middle bytes are dropped at line
 * boundaries; `toString()` marks the gap.
 */
export class BoundedOutput {
  private readonly head: Buffer[] = [];
  private headBytes = 0;
  private tail: Buffer[] = [];
  private tailBytes = 0;
  private totalBytes = 0;

  constructor(
    private readonly headLimit = Math.floor(MAX_OUTPUT_BYTES * HEAD_FRACTION),
    private readonly tailLimit = MAX_OUTPUT_BYTES,
  ) {}

  push(chunk: Buffer): void {
    this.totalBytes += chunk.length;
    let rest = chunk;
    if (this.headBytes < this.headLimit) {
      const take = Math.min(rest.length, this.headLimit - this.headBytes);
      this.head.push(rest.subarray(0, take));
      this.headBytes += take;
      rest = rest.subarray(take);
    }
    if (rest.length === 0) return;
    this.tail.push(rest);
    this.tailBytes += rest.length;
    // Keep up to twice the limit before compacting, to avoid copying on every chunk.
    if (this.tailBytes > this.tailLimit * 2) {
      const joined = Buffer.concat(this.tail);
      const kept = joined.subarray(joined.length - this.tailLimit);
      this.tail = [Buffer.from(kept)];
      this.tailBytes = kept.length;
    }
  }

  get droppedBytes(): number {
    return (
      this.totalBytes -
      this.headBytes -
      Math.min(this.tailBytes, this.tailLimit)
    );
  }

  toString(): string {
    const head = Buffer.concat(this.head);
    let tail = Buffer.concat(this.tail);
    if (tail.length > this.tailLimit)
      tail = tail.subarray(tail.length - this.tailLimit);
    if (this.droppedBytes === 0)
      return Buffer.concat([head, tail]).toString("utf8");
    const headEnd = headCut(head, head.length);
    const tailStart = tailCut(tail, 0);
    const omitted = this.droppedBytes + (head.length - headEnd) + tailStart;
    return (
      head.subarray(0, headEnd).toString("utf8") +
      truncationMarker(omitted) +
      tail.subarray(tailStart).toString("utf8")
    );
  }
}
