#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { WebSocketClientTransport } from "@modelcontextprotocol/sdk/client/websocket.js";
import { z } from "zod";

const CLIENT_INFO = { name: "mcp-tools-list-learning-probe", version: "1.0.0" };
const USER_AGENT = `${CLIENT_INFO.name}/${CLIENT_INFO.version}`;
const TRANSPORTS = new Set(["auto", "streamable-http", "sse", "websocket", "stdio"]);
const LIST_TOOLS_RESULT_SCHEMA = z.object({
  tools: z.array(z.unknown()),
  nextCursor: z.unknown().optional(),
}).passthrough();

function usage() {
  return `仅连接 MCP 服务并读取 tools/list，不调用任何工具。

远程服务：
  node mcp_tools_probe.js --url https://example.com/mcp [选项]

本地 stdio 服务：
  node mcp_tools_probe.js --transport stdio --command npx --arg=-y --arg @example/mcp-server

选项：
  --transport <auto|streamable-http|sse|websocket|stdio>  默认 auto
  --url <URL>                 远程端点；auto 会尝试有限的标准候选路径
  --command <可执行文件>      stdio 服务命令
  --arg <参数>                stdio 参数，可重复
  --cwd <目录>                stdio 子进程工作目录
  --pass-env <变量名>         把当前环境变量传给 stdio 子进程，可重复
  --header <名称: 值>         HTTP/SSE 请求头，可重复；敏感值更推荐下面两项
  --bearer-env <变量名>       从环境变量读取 Bearer token
  --api-key-env <变量名>      从环境变量读取 API key
  --api-key-header <名称>     API key 请求头名称，默认 X-API-Key
  --timeout <毫秒>            每个候选端点的总超时，默认 15000
  --max-pages <页数>          tools/list 最大分页数，默认 100
  --output <文件>             写入完整 JSON；不设置则输出到 stdout
  --pretty                     格式化 JSON
  --help                       显示帮助

环境变量的值不会写入输出。WebSocket 传输不支持自定义 HTTP 请求头。`;
}

export function parseArgs(argv) {
  const options = {
    transport: "auto",
    url: "",
    command: "",
    args: [],
    cwd: "",
    passEnv: [],
    headers: [],
    bearerEnv: "",
    apiKeyEnv: "",
    apiKeyHeader: "X-API-Key",
    timeout: 15_000,
    maxPages: 100,
    output: "",
    pretty: false,
    help: false,
  };
  const repeatable = new Set(["arg", "passEnv", "header"]);
  const booleans = new Set(["pretty", "help"]);

  for (let index = 0; index < argv.length; index += 1) {
    const raw = argv[index];
    if (!raw.startsWith("--")) throw new Error(`未知参数: ${raw}`);
    const equalsIndex = raw.indexOf("=");
    const rawKey = raw.slice(2, equalsIndex === -1 ? undefined : equalsIndex);
    const key = rawKey.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    if (!(key in options) && !repeatable.has(key)) throw new Error(`未知参数: --${rawKey}`);
    if (booleans.has(key)) {
      options[key] = true;
      continue;
    }
    const value = equalsIndex === -1 ? argv[++index] : raw.slice(equalsIndex + 1);
    if (value === undefined) throw new Error(`参数 --${rawKey} 缺少值`);
    if (repeatable.has(key)) options[key === "arg" ? "args" : key === "header" ? "headers" : "passEnv"].push(value);
    else if (["timeout", "maxPages"].includes(key)) options[key] = Number(value);
    else options[key] = value;
  }

  if (options.help) return options;
  if (!TRANSPORTS.has(options.transport)) throw new Error(`不支持的传输方式: ${options.transport}`);
  if (!Number.isInteger(options.timeout) || options.timeout < 100) throw new Error("--timeout 必须是不小于 100 的整数");
  if (!Number.isInteger(options.maxPages) || options.maxPages < 1 || options.maxPages > 1000) {
    throw new Error("--max-pages 必须是 1 到 1000 之间的整数");
  }
  if (options.transport === "stdio") {
    if (!options.command) throw new Error("stdio 传输必须提供 --command");
    if (options.url) throw new Error("stdio 传输不能同时提供 --url");
    if (options.headers.length || options.bearerEnv || options.apiKeyEnv) {
      throw new Error("stdio 传输不使用 HTTP 请求头；请用 --pass-env 传递所需环境变量");
    }
  } else {
    if (!options.url) throw new Error("远程传输必须提供 --url");
    if (options.command || options.args.length || options.passEnv.length || options.cwd) {
      throw new Error("远程传输不能使用 --command、--arg、--cwd 或 --pass-env");
    }
  }
  if (options.transport === "websocket" && (options.headers.length || options.bearerEnv || options.apiKeyEnv)) {
    throw new Error("当前 SDK 的 WebSocket 传输不支持自定义 HTTP 请求头");
  }
  return options;
}

function addCandidate(candidates, seen, transport, value) {
  const url = new URL(value);
  const valid = transport === "websocket" ? /^wss?:$/.test(url.protocol) : /^https?:$/.test(url.protocol);
  if (!valid) return;
  url.hash = "";
  const key = `${transport}:${url.href}`;
  if (!seen.has(key)) {
    seen.add(key);
    candidates.push({ transport, url: url.href });
  }
}

function atPath(value, pathname) {
  const url = new URL(value);
  url.pathname = pathname;
  url.search = "";
  url.hash = "";
  return url;
}

export function buildCandidates(options) {
  if (options.transport === "stdio") return [{ transport: "stdio", command: options.command }];
  const initial = new URL(options.url);
  const candidates = [];
  const seen = new Set();

  if (options.transport !== "auto") {
    addCandidate(candidates, seen, options.transport, initial);
    if (!candidates.length) throw new Error(`${options.transport} 与 URL 协议 ${initial.protocol} 不匹配`);
    return candidates;
  }
  if (/^wss?:$/.test(initial.protocol)) {
    addCandidate(candidates, seen, "websocket", initial);
    return candidates;
  }
  if (!/^https?:$/.test(initial.protocol)) throw new Error("--url 只支持 http、https、ws 或 wss");

  if (/(?:^|\/)sse(?:\/|$)/i.test(initial.pathname)) {
    addCandidate(candidates, seen, "sse", initial);
    addCandidate(candidates, seen, "streamable-http", initial);
  } else {
    addCandidate(candidates, seen, "streamable-http", initial);
  }
  for (const pathname of ["/mcp", "/api/mcp"]) {
    addCandidate(candidates, seen, "streamable-http", atPath(initial, pathname));
  }
  for (const pathname of ["/sse", "/mcp/sse"]) {
    addCandidate(candidates, seen, "sse", atPath(initial, pathname));
  }
  return candidates;
}

export function resolveHeaders(options, environment = process.env) {
  const headers = { "User-Agent": USER_AGENT };
  for (const item of options.headers) {
    const separator = item.indexOf(":");
    if (separator < 1) throw new Error(`请求头格式应为“名称: 值”: ${item}`);
    headers[item.slice(0, separator).trim()] = item.slice(separator + 1).trim();
  }
  if (options.bearerEnv) {
    const token = environment[options.bearerEnv];
    if (!token) throw new Error(`环境变量 ${options.bearerEnv} 未设置或为空`);
    headers.Authorization = `Bearer ${token}`;
  }
  if (options.apiKeyEnv) {
    const token = environment[options.apiKeyEnv];
    if (!token) throw new Error(`环境变量 ${options.apiKeyEnv} 未设置或为空`);
    headers[options.apiKeyHeader] = token;
  }
  return headers;
}

function controlledFetch(controller, observe = () => {}) {
  return async (url, init = {}) => {
    const signals = [controller.signal, init.signal].filter(Boolean);
    const response = await fetch(url, { ...init, signal: signals.length > 1 ? AbortSignal.any(signals) : signals[0] });
    observe(response);
    return response;
  };
}

function createRemoteTransport(candidate, headers, controller, observe) {
  const url = new URL(candidate.url);
  if (candidate.transport === "websocket") return new WebSocketClientTransport(url);
  const requestInit = { headers };
  const fetcher = controlledFetch(controller, observe);
  if (candidate.transport === "sse") {
    return new SSEClientTransport(url, {
      requestInit,
      eventSourceInit: { fetch: fetcher },
      fetch: fetcher,
    });
  }
  return new StreamableHTTPClientTransport(url, {
    requestInit,
    fetch: fetcher,
    reconnectionOptions: {
      maxReconnectionDelay: 1000,
      initialReconnectionDelay: 250,
      reconnectionDelayGrowFactor: 1.5,
      maxRetries: 0,
    },
  });
}

function createStdioTransport(options) {
  const env = getDefaultEnvironment();
  for (const name of options.passEnv) {
    if (!(name in process.env)) throw new Error(`环境变量 ${name} 不存在，无法传给 stdio 服务`);
    env[name] = process.env[name];
  }
  const transport = new StdioClientTransport({
    command: options.command,
    args: options.args,
    cwd: options.cwd || undefined,
    env,
    stderr: "pipe",
  });
  transport.stderr?.on("data", chunk => process.stderr.write(chunk));
  return transport;
}

async function listAllTools(client, options, controller, warnings) {
  const tools = [];
  const seenCursors = new Set();
  let cursor;
  for (let page = 1; page <= options.maxPages; page += 1) {
    const response = await client.request(
      { method: "tools/list", params: cursor ? { cursor } : {} },
      LIST_TOOLS_RESULT_SCHEMA,
      { signal: controller.signal, timeout: options.timeout, maxTotalTimeout: options.timeout },
    );
    const valid = response.tools.filter(tool => tool && typeof tool === "object" && !Array.isArray(tool));
    tools.push(...valid);
    if (valid.length !== response.tools.length) {
      warnings.push(`第 ${page} 页忽略了 ${response.tools.length - valid.length} 个非对象工具条目`);
    }
    const nextCursor = typeof response.nextCursor === "string" && response.nextCursor ? response.nextCursor : undefined;
    if (response.nextCursor != null && !nextCursor) warnings.push("服务返回了非字符串 nextCursor，已停止分页");
    if (!nextCursor) return { tools, pages: page };
    if (seenCursors.has(nextCursor)) throw new Error(`服务重复返回分页游标: ${nextCursor}`);
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  }
  throw new Error(`tools/list 超过 --max-pages=${options.maxPages}，为避免无限分页已停止`);
}

async function listPrimitive(client, kind, options, controller, warnings) {
  const values = [];
  const seenCursors = new Set();
  let cursor;
  const method = kind === "resources" ? client.listResources.bind(client) : client.listPrompts.bind(client);
  for (let page = 1; page <= options.maxPages; page += 1) {
    try {
      const response = await method(
        cursor ? { cursor } : {},
        { signal: controller.signal, timeout: options.timeout, maxTotalTimeout: options.timeout },
      );
      const pageValues = Array.isArray(response[kind]) ? response[kind].filter(item => item && typeof item === "object") : [];
      values.push(...pageValues);
      const nextCursor = typeof response.nextCursor === "string" && response.nextCursor ? response.nextCursor : undefined;
      if (!nextCursor) return { values, pages: page };
      if (seenCursors.has(nextCursor)) {
        warnings.push(`${kind}/list 返回重复分页游标，已停止`);
        return { values, pages: page };
      }
      seenCursors.add(nextCursor);
      cursor = nextCursor;
    } catch (error) {
      warnings.push(`${kind}/list 失败: ${describeError(error)}`);
      return { values, pages: values.length ? page : 0 };
    }
  }
  warnings.push(`${kind}/list 达到 --max-pages=${options.maxPages}`);
  return { values, pages: options.maxPages };
}

async function attempt(candidate, options, headers) {
  const startedAt = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`连接超时 ${options.timeout}ms`)), options.timeout);
  const warnings = [];
  const network = { finalUrl: candidate.url ?? null, redirected: false, statuses: [], server: null, cloudflare: false, authChallenge: null };
  const observe = response => {
    network.finalUrl = response.url || network.finalUrl;
    network.redirected ||= response.redirected;
    network.statuses.push(response.status);
    network.server ||= response.headers.get("server");
    network.cloudflare ||= Boolean(response.headers.get("cf-ray")) || /cloudflare/i.test(network.server || "");
    network.authChallenge ||= response.headers.get("www-authenticate");
  };
  let transport;
  try {
    transport = candidate.transport === "stdio"
      ? createStdioTransport(options)
      : createRemoteTransport(candidate, headers, controller, observe);
    const client = new Client(CLIENT_INFO, { enforceStrictCapabilities: false });
    client.onerror = () => {};
    await client.connect(transport, {
      signal: controller.signal,
      timeout: options.timeout,
      maxTotalTimeout: options.timeout,
    });
    const listed = await listAllTools(client, options, controller, warnings);
    const capabilities = client.getServerCapabilities() ?? {};
    const resources = capabilities.resources
      ? await listPrimitive(client, "resources", options, controller, warnings)
      : { values: [], pages: 0 };
    const prompts = capabilities.prompts
      ? await listPrimitive(client, "prompts", options, controller, warnings)
      : { values: [], pages: 0 };
    return {
      status: listed.tools.length ? "success" : "no_tools",
      transport: candidate.transport,
      endpoint: candidate.url ?? null,
      command: candidate.transport === "stdio" ? options.command : null,
      protocolVersion: transport.protocolVersion ?? transport._protocolVersion ?? null,
      sessionId: transport.sessionId ?? null,
      serverInfo: client.getServerVersion() ?? null,
      serverCapabilities: capabilities,
      serverInstructions: client.getInstructions() ?? null,
      finalUrl: network.finalUrl,
      redirected: network.redirected,
      redirectCount: network.redirected ? 1 : 0,
      endpointPath: candidate.url ? new URL(candidate.url).pathname : null,
      behindCloudflare: network.cloudflare,
      httpServer: network.server,
      authChallenge: network.authChallenge,
      authenticationProvided: Boolean(options.headers.length || options.bearerEnv || options.apiKeyEnv),
      toolCount: listed.tools.length,
      pages: listed.pages,
      tools: listed.tools,
      resourceCount: resources.values.length,
      resourcePages: resources.pages,
      resources: resources.values,
      promptCount: prompts.values.length,
      promptPages: prompts.pages,
      prompts: prompts.values,
      warnings,
      durationMs: Date.now() - startedAt,
      fetchedAt: new Date().toISOString(),
    };
  } catch (error) {
    if (error && typeof error === "object") {
      error.probeMetadata = network;
      throw error;
    }
    const wrapped = new Error(String(error));
    wrapped.probeMetadata = network;
    throw wrapped;
  } finally {
    clearTimeout(timer);
    controller.abort();
    await transport?.close().catch(() => {});
  }
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
    .replace(/\b((?:api[_ -]?key|password|secret|token|credential)\s*[=:]\s*)\S+/gi, "$1***REDACTED***")
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, "***REDACTED_API_KEY***");
}

export function redact(value, key = "") {
  if (/authorization|api.?key|password|secret|token|credential|cookie|session.?id/i.test(key)) return "***REDACTED***";
  if (Array.isArray(value)) return value.map(item => redact(item));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, redact(child, childKey)]));
  return typeof value === "string" ? redactString(value) : value;
}

export async function probe(options) {
  const candidates = buildCandidates(options);
  const headers = options.transport === "stdio" ? {} : resolveHeaders(options);
  const attempts = [];
  for (const candidate of candidates) {
    const startedAt = Date.now();
    try {
      const result = await attempt(candidate, options, headers);
      return { ...result, attempts: [...attempts, { ...candidate, status: result.status, durationMs: result.durationMs }] };
    } catch (error) {
      attempts.push({ ...candidate, status: "failed", durationMs: Date.now() - startedAt, error: describeError(error), ...(error.probeMetadata || {}) });
    }
  }
  return {
    status: "failed",
    transport: null,
    endpoint: null,
    command: options.transport === "stdio" ? options.command : null,
    toolCount: 0,
    tools: [],
    attempts,
    error: attempts.at(-1)?.error ?? "没有可用候选端点",
    fetchedAt: new Date().toISOString(),
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return;
  }
  const result = await probe(options);
  const json = JSON.stringify(redact(result), null, options.pretty ? 2 : 0);
  if (options.output) {
    fs.mkdirSync(path.dirname(path.resolve(options.output)), { recursive: true });
    fs.writeFileSync(options.output, `${json}\n`);
    console.error(`结果已写入 ${options.output}：status=${result.status} tools=${result.toolCount}`);
  } else {
    console.log(json);
  }
  if (result.status === "failed") process.exitCode = 2;
}

const entryUrl = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : "";
if (import.meta.url === entryUrl) {
  main().catch(error => {
    console.error(describeError(error));
    process.exitCode = 1;
  });
}
