import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { callOnce, redact } from "../mcp_tool_call.js";

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

test("SDK executor initializes and calls exactly one tool", async t => {
  let calls = 0;
  const server = http.createServer(async (request, response) => {
    if (request.method === "DELETE") return response.writeHead(200).end();
    const body = await readBody(request);
    if (!body) return response.writeHead(405).end();
    const value = JSON.parse(body);
    if (value.method === "initialize") {
      response.writeHead(200, { "Content-Type": "application/json", "Mcp-Session-Id": "call-test" });
      return response.end(JSON.stringify({
        jsonrpc: "2.0",
        id: value.id,
        result: {
          protocolVersion: value.params.protocolVersion,
          capabilities: { tools: {} },
          serverInfo: { name: "local-call-test", version: "1.0.0" },
        },
      }));
    }
    if (value.method === "notifications/initialized") return response.writeHead(202).end();
    if (value.method === "tools/call") {
      calls += 1;
      response.writeHead(200, { "Content-Type": "application/json" });
      return response.end(JSON.stringify({
        jsonrpc: "2.0",
        id: value.id,
        result: { content: [{ type: "text", text: "audit-safe-probe" }], isError: false },
      }));
    }
    response.writeHead(400).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  const options = {
    url: `http://127.0.0.1:${address.port}/mcp`,
    transport: "streamable-http",
    tool: "safe_echo",
    timeout: 3000,
    bearerEnv: "",
    apiKeyEnv: "",
    apiKeyHeader: "X-API-Key",
  };
  const result = await callOnce(options, { text: "audit-safe-probe" });
  assert.equal(result.status, "response_received");
  assert.equal(result.toolResult.content[0].text, "audit-safe-probe");
  assert.equal(calls, 1);
});

test("executor redacts credentials embedded in connection strings", () => {
  const value = redact({ text: "postgresql://audit-user:audit-pass@db.internal/prod" });
  assert.equal(value.text, "postgresql://***:***@db.internal/prod");
});
