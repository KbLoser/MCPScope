#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { WebSocketClientTransport } from "@modelcontextprotocol/sdk/client/websocket.js";
import { buildCandidates } from "./mcp_tools_probe.js";

const CLIENT_INFO = { name: "authorized-mcp-tool-audit", version: "1.0.0" };

export function parseArgs(argv) {
  const options = {
    url: "",
    transport: "auto",
    tool: "",
    argumentsFile: "",
    output: "",
    timeout: 30_000,
    bearerEnv: "",
    apiKeyEnv: "",
    apiKeyHeader: "X-API-Key",
    pretty: false,
  };
  const booleans = new Set(["pretty"]);
  for (let index = 0; index < argv.length; index += 1) {
    const raw = argv[index];
    if (!raw.startsWith("--")) throw new Error(`未知参数: ${raw}`);
    const equalsIndex = raw.indexOf("=");
    const rawKey = raw.slice(2, equalsIndex === -1 ? undefined : equalsIndex);
    const key = rawKey.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (!(key in options)) throw new Error(`未知参数: --${rawKey}`);
    if (booleans.has(key)) {
      options[key] = true;
      continue;
    }
    const value = equalsIndex === -1 ? argv[++index] : raw.slice(equalsIndex + 1);
    if (value === undefined) throw new Error(`参数 --${rawKey} 缺少值`);
    options[key] = key === "timeout" ? Number(value) : value;
  }
  if (!options.url || !options.tool || !options.argumentsFile) {
    throw new Error("必须提供 --url、--tool 和 --arguments-file");
  }
  if (!Number.isInteger(options.timeout) || options.timeout < 100) {
    throw new Error("--timeout 必须是不小于 100 的整数");
  }
  return options;
}

function resolveHeaders(options) {
  const headers = { "User-Agent": `${CLIENT_INFO.name}/${CLIENT_INFO.version}` };
  if (options.bearerEnv) {
    const value = process.env[options.bearerEnv];
    if (!value) throw new Error(`环境变量 ${options.bearerEnv} 未设置`);
    headers.Authorization = `Bearer ${value}`;
  }
  if (options.apiKeyEnv) {
    const value = process.env[options.apiKeyEnv];
    if (!value) throw new Error(`环境变量 ${options.apiKeyEnv} 未设置`);
    headers[options.apiKeyHeader] = value;
  }
  return headers;
}

function controlledFetch(controller) {
  return (url, init = {}) => {
    const signals = [controller.signal, init.signal].filter(Boolean);
    return fetch(url, { ...init, signal: signals.length > 1 ? AbortSignal.any(signals) : signals[0] });
  };
}

function createTransport(candidate, headers, controller) {
  const url = new URL(candidate.url);
  if (candidate.transport === "websocket") return new WebSocketClientTransport(url);
  const fetcher = controlledFetch(controller);
  if (candidate.transport === "sse") {
    return new SSEClientTransport(url, {
      requestInit: { headers },
      eventSourceInit: { fetch: fetcher },
      fetch: fetcher,
    });
  }
  return new StreamableHTTPClientTransport(url, {
    requestInit: { headers },
    fetch: fetcher,
    reconnectionOptions: {
      maxReconnectionDelay: 1000,
      initialReconnectionDelay: 250,
      reconnectionDelayGrowFactor: 1.5,
      maxRetries: 0,
    },
  });
}

function describeError(error) {
  const values = [];
  let current = error;
  for (let depth = 0; current && depth < 4; depth += 1) {
    const value = `${current.code ? `[${current.code}] ` : ""}${current.message ?? String(current)}`;
    if (!values.includes(value)) values.push(value);
    current = current.cause;
  }
  return values.join(" <- ").slice(0, 2000);
}

function redactString(value) {
  return value
    .replace(/\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis):\/\/)[^:/@\s"']+:[^@\s"']+@/gi, "$1***:***@")
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, "***REDACTED_API_KEY***");
}

export function redact(value, key = "") {
  if (/authorization|api.?key|password|secret|token|credential|cookie|session.?id/i.test(key)) {
    return "***REDACTED***";
  }
  if (Array.isArray(value)) return value.map(item => redact(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, redact(child, childKey)]));
  }
  return typeof value === "string" ? redactString(value) : value;
}

export async function callOnce(options, argumentsValue) {
  const candidates = buildCandidates({ transport: options.transport, url: options.url });
  const headers = resolveHeaders(options);
  const attempts = [];
  for (const candidate of candidates) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error(`超时 ${options.timeout}ms`)), options.timeout);
    let transport;
    let client;
    try {
      transport = createTransport(candidate, headers, controller);
      client = new Client(CLIENT_INFO, { enforceStrictCapabilities: false });
      client.onerror = () => {};
      await client.connect(transport, {
        signal: controller.signal,
        timeout: options.timeout,
        maxTotalTimeout: options.timeout,
      });
      let toolResult;
      try {
        toolResult = await client.callTool(
          { name: options.tool, arguments: argumentsValue },
          undefined,
          { signal: controller.signal, timeout: options.timeout, maxTotalTimeout: options.timeout },
        );
      } catch (error) {
        return {
          status: "call_failed",
          transport: candidate.transport,
          endpoint: candidate.url,
          tool: options.tool,
          arguments: argumentsValue,
          error: describeError(error),
          attempts: [...attempts, { ...candidate, status: "connected_call_failed" }],
          fetchedAt: new Date().toISOString(),
        };
      }
      return {
        status: "response_received",
        transport: candidate.transport,
        endpoint: candidate.url,
        protocolVersion: transport.protocolVersion ?? transport._protocolVersion ?? null,
        serverInfo: client.getServerVersion() ?? null,
        serverCapabilities: client.getServerCapabilities() ?? null,
        tool: options.tool,
        arguments: argumentsValue,
        toolResult,
        attempts: [...attempts, { ...candidate, status: "response_received" }],
        fetchedAt: new Date().toISOString(),
      };
    } catch (error) {
      attempts.push({ ...candidate, status: "connection_failed", error: describeError(error) });
    } finally {
      clearTimeout(timer);
      controller.abort();
      await transport?.close().catch(() => {});
    }
  }
  return {
    status: "connection_failed",
    endpoint: null,
    tool: options.tool,
    arguments: argumentsValue,
    attempts,
    error: attempts.at(-1)?.error ?? "没有可用候选端点",
    fetchedAt: new Date().toISOString(),
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const plan = JSON.parse(fs.readFileSync(options.argumentsFile, "utf8"));
  const argumentsValue = plan.arguments ?? plan;
  if (!argumentsValue || typeof argumentsValue !== "object" || Array.isArray(argumentsValue)) {
    throw new Error("参数文件必须是对象，或包含 arguments 对象");
  }
  const result = redact(await callOnce(options, argumentsValue));
  const json = JSON.stringify(result, null, options.pretty ? 2 : 0);
  if (options.output) {
    fs.mkdirSync(path.dirname(path.resolve(options.output)), { recursive: true });
    fs.writeFileSync(options.output, `${json}\n`);
    console.error(`结果已写入 ${options.output}: status=${result.status}`);
  } else {
    console.log(json);
  }
  if (result.status === "connection_failed") process.exitCode = 2;
}

const entryUrl = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : "";
if (import.meta.url === entryUrl) {
  main().catch(error => {
    console.error(describeError(error));
    process.exitCode = 1;
  });
}
