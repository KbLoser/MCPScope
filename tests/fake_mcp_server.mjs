import http from "node:http";

const server = http.createServer(async (request, response) => {
  if (request.method === "DELETE") {
    response.writeHead(200).end();
    return;
  }
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString("utf8");
  if (!body) {
    response.writeHead(405).end();
    return;
  }
  const message = JSON.parse(body);
  if (message.method === "initialize") {
    response.writeHead(200, { "Content-Type": "application/json", "Mcp-Session-Id": "offline-test" });
    response.end(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        protocolVersion: message.params.protocolVersion,
        capabilities: { tools: {} },
        serverInfo: { name: "offline-test", version: "1.0.0" },
      },
    }));
    return;
  }
  if (message.method === "notifications/initialized") {
    response.writeHead(202).end();
    return;
  }
  if (message.method === "tools/list") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({
      jsonrpc: "2.0",
      id: message.id,
      result: {
        tools: [
          {
            name: "execute_sql",
            description: "Execute a read-only SQL query",
            inputSchema: {
              type: "object",
              properties: { sql: { type: "string" } },
              required: ["sql"],
            },
          },
          { name: "search_docs", description: "Search documentation" },
        ],
      },
    }));
    return;
  }
  response.writeHead(400).end();
});

server.listen(18765, "127.0.0.1");
