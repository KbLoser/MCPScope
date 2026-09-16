import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { parseArgs, probe } from "../mcp_tools_probe.js";

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function sendJson(response, value, headers = {}) {
  response.writeHead(200, { "Content-Type": "application/json", ...headers });
  response.end(JSON.stringify(value));
}

test("probe completes Streamable HTTP initialization and pagination", async t => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const body = await readBody(request);
    if (request.method === "DELETE") {
      requests.push({ value: { method: "session/delete" }, headers: request.headers });
      response.writeHead(200).end();
      return;
    }
    if (!body) {
      requests.push({ value: { method: `${request.method?.toLowerCase()}/empty` }, headers: request.headers });
      response.writeHead(405).end();
      return;
    }
    const value = JSON.parse(body);
    requests.push({ value, headers: request.headers });
    if (value.method === "initialize") {
      sendJson(response, {
        jsonrpc: "2.0",
        id: value.id,
        result: {
          protocolVersion: value.params.protocolVersion,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: "local-http-test", version: "1.0.0" },
        },
      }, { "Mcp-Session-Id": "test-session" });
      return;
    }
    if (value.method === "notifications/initialized") {
      response.writeHead(202).end();
      return;
    }
    if (value.method === "tools/list" && !value.params?.cursor) {
      sendJson(response, {
        jsonrpc: "2.0",
        id: value.id,
        result: {
          tools: [{ name: "first", inputSchema: { type: "object", properties: {} } }],
          nextCursor: "page-2",
        },
      });
      return;
    }
    if (value.method === "tools/list" && value.params.cursor === "page-2") {
      sendJson(response, {
        jsonrpc: "2.0",
        id: value.id,
        result: { tools: [{ name: "second", inputSchema: { type: "object", properties: {} } }] },
      });
      return;
    }
    response.writeHead(400).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());

  const address = server.address();
  const options = parseArgs([
    "--transport", "streamable-http",
    "--url", `http://127.0.0.1:${address.port}/mcp`,
    "--timeout", "3000",
  ]);
  const result = await probe(options);

  assert.equal(result.status, "success");
  assert.equal(result.toolCount, 2);
  assert.equal(result.pages, 2);
  assert.deepEqual(result.tools.map(tool => tool.name), ["first", "second"]);
  assert.equal(requests.some(item => item.value.method === "initialize"), true);
  assert.equal(requests.some(item => item.value.method === "notifications/initialized"), true);
  assert.equal(requests.filter(item => item.value.method === "tools/list").length, 2);
  const secondPage = requests.find(item => item.value.params?.cursor === "page-2");
  assert.equal(secondPage.headers["mcp-session-id"], "test-session");
});

test("probe uses headers on both legacy SSE GET and message POST", async t => {
  let eventStream;
  const observedHeaders = [];
  const server = http.createServer(async (request, response) => {
    observedHeaders.push({ method: request.method, url: request.url, authorization: request.headers.authorization });
    if (request.method === "GET" && request.url === "/sse") {
      eventStream = response;
      response.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      response.write("event: endpoint\ndata: /messages\n\n");
      return;
    }
    if (request.method === "POST" && request.url === "/messages") {
      const value = JSON.parse(await readBody(request));
      response.writeHead(202).end();
      if (value.method === "initialize") {
        eventStream.write(`event: message\ndata: ${JSON.stringify({
          jsonrpc: "2.0",
          id: value.id,
          result: {
            protocolVersion: value.params.protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: "local-sse-test", version: "1.0.0" },
          },
        })}\n\n`);
      } else if (value.method === "tools/list") {
        eventStream.write(`event: message\ndata: ${JSON.stringify({
          jsonrpc: "2.0",
          id: value.id,
          result: { tools: [{ name: "legacy", inputSchema: { type: "object", properties: {} } }] },
        })}\n\n`);
      }
      return;
    }
    response.writeHead(404).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());

  const address = server.address();
  const options = parseArgs([
    "--transport", "sse",
    "--url", `http://127.0.0.1:${address.port}/sse`,
    "--bearer-env", "LOCAL_TEST_TOKEN",
    "--timeout", "3000",
  ]);
  const previousToken = process.env.LOCAL_TEST_TOKEN;
  process.env.LOCAL_TEST_TOKEN = "test-token";
  t.after(() => {
    if (previousToken === undefined) delete process.env.LOCAL_TEST_TOKEN;
    else process.env.LOCAL_TEST_TOKEN = previousToken;
  });

  const result = await probe(options);

  assert.equal(result.status, "success");
  assert.equal(result.tools[0].name, "legacy");
  assert.equal(observedHeaders.some(item => item.method === "GET" && item.authorization === "Bearer test-token"), true);
  assert.equal(observedHeaders.some(item => item.method === "POST" && item.authorization === "Bearer test-token"), true);
});

test("probe connects to a local stdio server and preserves an empty tool list", async () => {
  const serverProgram = `
let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", chunk => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf("\\n")) !== -1) {
    const line = buffer.slice(0, newline);
    buffer = buffer.slice(newline + 1);
    if (!line.trim()) continue;
    const message = JSON.parse(line);
    if (message.method === "initialize") {
      process.stdout.write(JSON.stringify({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: message.params.protocolVersion,
          capabilities: { tools: {} },
          serverInfo: { name: "local-stdio-test", version: "1.0.0" }
        }
      }) + "\\n");
    } else if (message.method === "tools/list") {
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { tools: [] } }) + "\\n");
    }
  }
});
`;
  const options = parseArgs([
    "--transport", "stdio",
    "--command", process.execPath,
    "--arg=-e",
    "--arg", serverProgram,
    "--timeout", "3000",
  ]);
  const result = await probe(options);

  assert.equal(result.status, "no_tools");
  assert.equal(result.toolCount, 0);
  assert.equal(result.pages, 1);
  assert.equal(result.serverInfo.name, "local-stdio-test");
});

test("probe inventories resources, prompts, and server instructions", async t => {
  const server = http.createServer(async (request, response) => {
    if (request.method === "DELETE") return response.writeHead(200).end();
    const body = await readBody(request);
    if (!body) return response.writeHead(405).end();
    const value = JSON.parse(body);
    if (value.method === "initialize") {
      sendJson(response, {
        jsonrpc: "2.0", id: value.id,
        result: {
          protocolVersion: value.params.protocolVersion,
          capabilities: { tools: {}, resources: {}, prompts: {} },
          serverInfo: { name: "inventory-test", version: "1.0.0" },
          instructions: "Review all returned evidence",
        },
      }, { "Mcp-Session-Id": "inventory-session" });
      return;
    }
    if (value.method === "notifications/initialized") return response.writeHead(202).end();
    if (value.method === "tools/list") return sendJson(response, { jsonrpc: "2.0", id: value.id, result: { tools: [] } });
    if (value.method === "resources/list") return sendJson(response, { jsonrpc: "2.0", id: value.id, result: { resources: [{ uri: "file:///tmp/demo", name: "demo" }] } });
    if (value.method === "prompts/list") return sendJson(response, { jsonrpc: "2.0", id: value.id, result: { prompts: [{ name: "review", arguments: [] }] } });
    response.writeHead(400).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());

  const address = server.address();
  const result = await probe(parseArgs([
    "--transport", "streamable-http",
    "--url", `http://127.0.0.1:${address.port}/mcp`,
    "--timeout", "3000",
  ]));
  assert.equal(result.resourceCount, 1);
  assert.equal(result.promptCount, 1);
  assert.equal(result.resources[0].uri, "file:///tmp/demo");
  assert.equal(result.prompts[0].name, "review");
  assert.equal(result.serverInstructions, "Review all returned evidence");
  assert.equal(result.endpointPath, "/mcp");
});
