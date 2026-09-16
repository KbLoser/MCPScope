import test from "node:test";
import assert from "node:assert/strict";
import { buildCandidates, parseArgs, redact, resolveHeaders } from "../mcp_tools_probe.js";

test("auto mode prefers Streamable HTTP and adds bounded fallbacks", () => {
  const options = parseArgs(["--url", "https://example.com/custom"]);
  assert.deepEqual(buildCandidates(options), [
    { transport: "streamable-http", url: "https://example.com/custom" },
    { transport: "streamable-http", url: "https://example.com/mcp" },
    { transport: "streamable-http", url: "https://example.com/api/mcp" },
    { transport: "sse", url: "https://example.com/sse" },
    { transport: "sse", url: "https://example.com/mcp/sse" },
  ]);
});

test("auto mode tries legacy SSE first for an explicit SSE path", () => {
  const options = parseArgs(["--url", "https://example.com/sse"]);
  assert.deepEqual(buildCandidates(options).slice(0, 2), [
    { transport: "sse", url: "https://example.com/sse" },
    { transport: "streamable-http", url: "https://example.com/sse" },
  ]);
});

test("WebSocket URLs are recognized without HTTP fallbacks", () => {
  const options = parseArgs(["--url", "wss://example.com/mcp"]);
  assert.deepEqual(buildCandidates(options), [
    { transport: "websocket", url: "wss://example.com/mcp" },
  ]);
});

test("authentication values are loaded from environment variables", () => {
  const options = parseArgs([
    "--url", "https://example.com/mcp",
    "--header", "X-Tenant: demo",
    "--bearer-env", "ACCESS_TOKEN",
    "--api-key-env", "API_SECRET",
    "--api-key-header", "X-Custom-Key",
  ]);
  const headers = resolveHeaders(options, { ACCESS_TOKEN: "token-value", API_SECRET: "key-value" });
  assert.equal(headers.Authorization, "Bearer token-value");
  assert.equal(headers["X-Custom-Key"], "key-value");
  assert.equal(headers["X-Tenant"], "demo");
});

test("stdio mode keeps command arguments separate", () => {
  const options = parseArgs([
    "--transport", "stdio",
    "--command", "npx",
    "--arg=-y",
    "--arg", "@example/mcp-server",
    "--pass-env", "SERVICE_TOKEN",
  ]);
  assert.equal(options.command, "npx");
  assert.deepEqual(options.args, ["-y", "@example/mcp-server"]);
  assert.deepEqual(options.passEnv, ["SERVICE_TOKEN"]);
});

test("stdio rejects HTTP-only options", () => {
  assert.throws(
    () => parseArgs(["--transport", "stdio", "--command", "node", "--header", "X-Key: value"]),
    /不使用 HTTP 请求头/,
  );
});

test("WebSocket rejects unsupported authentication headers", () => {
  assert.throws(
    () => parseArgs(["--transport", "websocket", "--url", "wss://example.com/mcp", "--bearer-env", "TOKEN"]),
    /不支持自定义 HTTP 请求头/,
  );
});

test("probe evidence redaction removes credentials", () => {
  const value = redact({ resource: "postgresql://user:pass@db.internal/main", instructions: "token=secret-value" });
  assert.equal(value.resource, "postgresql://***:***@db.internal/main");
  assert.equal(value.instructions, "token=***REDACTED***");
});
