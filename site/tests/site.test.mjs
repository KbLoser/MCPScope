import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";


const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");


test("research site contains the required narrative sections", async () => {
  const html = await readFile(path.join(siteRoot, "index.html"), "utf8");
  for (const id of ["overview", "problem", "method", "dataset", "findings", "cases", "boundaries"]) {
    assert.match(html, new RegExp(`id=["']${id}["']`));
  }
  assert.match(html, /<h1[^>]*>MCPScope<\/h1>/);
  assert.match(html, /network-canvas/);
  assert.match(html, /public-summary\.json|data-metric/);
  assert.match(html, /public-summary\.js/);

  const problem = html.slice(html.indexOf('id="problem"'), html.indexOf('id="method"'));
  const method = html.slice(html.indexOf('id="method"'), html.indexOf('id="dataset"'));
  assert.match(problem, /真实权限被工具接口遮蔽/);
  assert.doesNotMatch(problem, /发现不等于扫描|候选不等于漏洞|验证不等于利用/);
  assert.match(method, /判定原则/);
  assert.match(method, /发现不等于扫描|候选不等于漏洞|验证不等于利用/);
});


test("redacted record page publishes only masked tool names", async () => {
  const html = await readFile(path.join(siteRoot, "records.html"), "utf8");
  const raw = await readFile(path.join(siteRoot, "data", "public-records.json"), "utf8");
  const geographyRaw = await readFile(path.join(siteRoot, "data", "public-geography.json"), "utf8");
  const mapRaw = await readFile(path.join(siteRoot, "data", "world-map.js"), "utf8");
  const data = JSON.parse(raw);
  const geography = JSON.parse(geographyRaw);
  const map = JSON.parse(mapRaw.slice(mapRaw.indexOf("=") + 1).replace(/;\s*$/, ""));
  assert.match(html, /脱敏记录/);
  assert.match(html, /public-records\.js/);
  assert.match(html, /world-map/);
  assert.match(html, /public-geography\.js/);
  assert.match(html, /record-table/);
  assert.equal(data.records.length, 619);
  assert.ok(data.records.every((record) => /\*{3,}/.test(record.masked_tool_name)));
  assert.ok(data.records.every((record) => record.masked_target && /\*/.test(record.masked_target)));
  assert.equal(data.records[0].masked_target, "m***p.w***e.c***p.a***e.com");
  assert.doesNotMatch(raw, /https?:\/\//);
  assert.doesNotMatch(raw, /"(?:mcp_id|tool_id|target|hostname|raw_tool_name)"/);
  assert.equal(geography.totals.records, 619);
  assert.equal(geography.totals.unresolved, 39);
  assert.ok(geography.countries.some((country) => country.label === "中国" && country.count === 32));
  assert.doesNotMatch(geographyRaw, /San Jose|目标地址|IPv4地址|城市/);
  assert.ok(map.countries.some((country) => country.id === "156"));
  assert.ok(!map.countries.some((country) => country.id === "158"));
});


test("navigation only restores the top position for a URL without an anchor", async () => {
  const javascript = await readFile(path.join(siteRoot, "js", "main.js"), "utf8");
  assert.match(javascript, /if \(!window\.location\.hash\)/);
  assert.match(javascript, /history\.scrollRestoration = "manual"/);
  assert.match(javascript, /pageshow/);
});


test("published dataset is aggregate-only and has expected reconciled totals", async () => {
  const raw = await readFile(path.join(siteRoot, "data", "public-summary.json"), "utf8");
  const data = JSON.parse(raw);

  assert.equal(data.publication.raw_targets_published, false);
  assert.deepEqual(data.headline, {
    services: 619,
    records: 619,
    unique_tools: 457,
    findings: 619,
    categories: 10,
  });
  assert.equal(data.record_sources.reduce((sum, item) => sum + item.value, 0), 619);
  assert.equal(data.finding_categories.reduce((sum, item) => sum + item.value, 0), 619);
  assert.equal(data.finding_categories.length, 10);
  assert.doesNotMatch(raw, /https?:\/\//);
  assert.doesNotMatch(raw, /\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  assert.doesNotMatch(raw, /SDK原始结果|测试证据\.json/);
});


test("site styling avoids gradients and unstable viewport-scaled type", async () => {
  const css = await readFile(path.join(siteRoot, "css", "site.css"), "utf8");
  const recordsCss = await readFile(path.join(siteRoot, "css", "records.css"), "utf8");
  assert.doesNotMatch(css, /gradient\s*\(/i);
  assert.doesNotMatch(css, /font-size\s*:[^;]*(?:vw|vh)/i);
  assert.doesNotMatch(css, /letter-spacing\s*:\s*-/i);
  assert.match(recordsCss, /\.record-source\s*\{[^}]*white-space:\s*nowrap/s);
  assert.match(recordsCss, /\.record-table\s*\{[^}]*overflow-x:\s*auto/s);
});
