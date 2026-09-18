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
});


test("published dataset is aggregate-only and has expected reconciled totals", async () => {
  const raw = await readFile(path.join(siteRoot, "data", "public-summary.json"), "utf8");
  const data = JSON.parse(raw);

  assert.equal(data.publication.raw_targets_published, false);
  assert.deepEqual(data.headline, {
    services: 383,
    candidates: 1160,
    unique_tools: 692,
    findings: 142,
    operation_evidence: 73,
  });
  assert.equal(data.evidence_scopes.reduce((sum, item) => sum + item.value, 0), 142);
  assert.equal(data.service_outcomes.reduce((sum, item) => sum + item.value, 0), 383);
  assert.doesNotMatch(raw, /https?:\/\//);
  assert.doesNotMatch(raw, /\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  assert.doesNotMatch(raw, /SDK原始结果|测试证据\.json/);
});


test("site styling avoids gradients and unstable viewport-scaled type", async () => {
  const css = await readFile(path.join(siteRoot, "css", "site.css"), "utf8");
  assert.doesNotMatch(css, /gradient\s*\(/i);
  assert.doesNotMatch(css, /font-size\s*:[^;]*(?:vw|vh)/i);
  assert.doesNotMatch(css, /letter-spacing\s*:\s*-/i);
});
