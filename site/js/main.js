const DATA_URL = "data/public-summary.json";
const COLORS = ["#bd4a40", "#2f7f78", "#397799", "#c58c28", "#688078", "#855f84"];

if (!window.location.hash) {
  history.scrollRestoration = "manual";
  window.scrollTo(0, 0);
  window.addEventListener("pageshow", () => {
    if (!window.location.hash) window.scrollTo(0, 0);
  }, { once: true });
}

const state = {
  data: null,
  chartRenderers: [],
};

function formatNumber(value) {
  return new Intl.NumberFormat("zh-CN").format(value);
}

function setCanvasSize(canvas) {
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const rect = canvas.getBoundingClientRect();
  const width = Math.max(280, Math.round(rect.width));
  const height = Math.max(220, Math.round(rect.height));
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  const context = canvas.getContext("2d");
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  return { context, width, height };
}

function roundRect(context, x, y, width, height, radius) {
  const safeRadius = Math.min(radius, width / 2, height / 2);
  context.beginPath();
  context.moveTo(x + safeRadius, y);
  context.arcTo(x + width, y, x + width, y + height, safeRadius);
  context.arcTo(x + width, y + height, x, y + height, safeRadius);
  context.arcTo(x, y + height, x, y, safeRadius);
  context.arcTo(x, y, x + width, y, safeRadius);
  context.closePath();
}

function drawHorizontalBars(canvas, items, options = {}) {
  const { context, width, height } = setCanvasSize(canvas);
  const compact = width < 480;
  const labelWidth = compact ? Math.min(132, width * 0.42) : Math.min(190, width * 0.4);
  const right = 42;
  const top = 18;
  const bottom = 22;
  const chartWidth = width - labelWidth - right;
  const rowHeight = (height - top - bottom) / items.length;
  const max = Math.max(...items.map((item) => item.value), 1);

  context.clearRect(0, 0, width, height);
  context.font = `${compact ? 11 : 12}px "Helvetica Neue", Arial, sans-serif`;
  context.textBaseline = "middle";

  items.forEach((item, index) => {
    const y = top + index * rowHeight;
    const barHeight = Math.max(8, Math.min(18, rowHeight * 0.46));
    const barY = y + (rowHeight - barHeight) / 2;
    const valueWidth = Math.max(3, chartWidth * (item.value / max));
    const label = item.label.length > (compact ? 12 : 18)
      ? `${item.label.slice(0, compact ? 11 : 17)}…`
      : item.label;

    context.fillStyle = "#526159";
    context.fillText(label, 0, y + rowHeight / 2);

    context.fillStyle = "#e1e6e3";
    roundRect(context, labelWidth, barY, chartWidth, barHeight, 2);
    context.fill();

    context.fillStyle = options.colors?.[index] || (index < 3 ? COLORS[index] : "#688078");
    roundRect(context, labelWidth, barY, valueWidth, barHeight, 2);
    context.fill();

    context.fillStyle = "#17201c";
    context.font = `700 ${compact ? 11 : 12}px "Helvetica Neue", Arial, sans-serif`;
    context.textAlign = "right";
    context.fillText(formatNumber(item.value), width, y + rowHeight / 2);
    context.textAlign = "left";
    context.font = `${compact ? 11 : 12}px "Helvetica Neue", Arial, sans-serif`;
  });
}

function wrapLabel(label) {
  if (label.length <= 6) return [label];
  const split = Math.ceil(label.length / 2);
  return [label.slice(0, split), label.slice(split)];
}

function drawVerticalBars(canvas, items) {
  const { context, width, height } = setCanvasSize(canvas);
  const compact = width < 480;
  const left = 38;
  const right = 12;
  const top = 22;
  const bottom = compact ? 82 : 72;
  const chartHeight = height - top - bottom;
  const chartWidth = width - left - right;
  const max = Math.max(...items.map((item) => item.value), 1);
  const band = chartWidth / items.length;
  const barWidth = Math.min(52, band * 0.58);

  context.clearRect(0, 0, width, height);
  context.strokeStyle = "#dce2de";
  context.lineWidth = 1;
  context.font = "11px \"Helvetica Neue\", Arial, sans-serif";
  context.fillStyle = "#637069";
  context.textBaseline = "middle";

  for (let step = 0; step <= 4; step += 1) {
    const value = Math.round((max * step) / 4);
    const y = top + chartHeight - (chartHeight * step) / 4;
    context.beginPath();
    context.moveTo(left, y);
    context.lineTo(width - right, y);
    context.stroke();
    context.textAlign = "right";
    context.fillText(String(value), left - 7, y);
  }

  items.forEach((item, index) => {
    const x = left + index * band + (band - barWidth) / 2;
    const barHeight = chartHeight * (item.value / max);
    const y = top + chartHeight - barHeight;
    context.fillStyle = COLORS[index % COLORS.length];
    roundRect(context, x, y, barWidth, barHeight, 3);
    context.fill();

    context.fillStyle = "#17201c";
    context.font = "700 12px \"Helvetica Neue\", Arial, sans-serif";
    context.textAlign = "center";
    context.fillText(formatNumber(item.value), x + barWidth / 2, y - 10);

    context.font = `${compact ? 10 : 11}px "Helvetica Neue", Arial, sans-serif`;
    context.fillStyle = "#526159";
    wrapLabel(item.label).forEach((line, lineIndex) => {
      context.fillText(line, x + barWidth / 2, top + chartHeight + 20 + lineIndex * 15);
    });
  });
}

function drawDonut(canvas, items) {
  const { context, width, height } = setCanvasSize(canvas);
  const total = items.reduce((sum, item) => sum + item.value, 0);
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) * 0.32;
  const thickness = Math.max(24, radius * 0.36);
  let angle = -Math.PI / 2;

  context.clearRect(0, 0, width, height);
  items.forEach((item, index) => {
    const slice = (item.value / total) * Math.PI * 2;
    context.beginPath();
    context.arc(centerX, centerY, radius, angle, angle + slice - 0.018);
    context.strokeStyle = COLORS[index % COLORS.length];
    context.lineWidth = thickness;
    context.lineCap = "butt";
    context.stroke();
    angle += slice;
  });

  context.textAlign = "center";
  context.textBaseline = "middle";
  context.fillStyle = "#17201c";
  context.font = "700 36px \"Helvetica Neue\", Arial, sans-serif";
  context.fillText(formatNumber(total), centerX, centerY - 7);
  context.fillStyle = "#637069";
  context.font = "12px \"Helvetica Neue\", Arial, sans-serif";
  context.fillText("安全发现", centerX, centerY + 25);
}

function renderLegend(element, items) {
  element.replaceChildren();
  items.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = "legend-item";
    const color = document.createElement("span");
    color.className = "legend-color";
    color.style.backgroundColor = COLORS[index % COLORS.length];
    const label = document.createElement("span");
    label.textContent = item.label;
    const value = document.createElement("strong");
    value.textContent = formatNumber(item.value);
    row.append(color, label, value);
    element.append(row);
  });
}

function renderCases(cases) {
  const container = document.querySelector("#case-grid");
  container.replaceChildren();
  cases.forEach((item) => {
    const article = document.createElement("article");
    article.className = "case-card";

    const header = document.createElement("div");
    header.className = "case-card-header";
    const id = document.createElement("span");
    id.textContent = item.id;
    const category = document.createElement("span");
    category.textContent = item.category;
    header.append(id, category);

    const content = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = item.title;
    const summary = document.createElement("p");
    summary.textContent = item.summary;
    content.append(title, summary);

    const footer = document.createElement("div");
    footer.className = "case-evidence";
    const label = document.createElement("span");
    label.textContent = "证据类型";
    const evidence = document.createElement("span");
    evidence.textContent = item.evidence;
    footer.append(label, evidence);

    article.append(header, content, footer);
    container.append(article);
  });
}

function renderLimitations(items) {
  const list = document.querySelector("#limitations-list");
  list.replaceChildren();
  items.forEach((item, index) => {
    const row = document.createElement("li");
    const number = document.createElement("span");
    number.textContent = String(index + 1).padStart(2, "0");
    const text = document.createElement("p");
    text.textContent = item;
    row.append(number, text);
    list.append(row);
  });
}

function updateNumbers(data) {
  document.querySelectorAll("[data-metric]").forEach((element) => {
    const key = element.dataset.metric;
    if (Object.hasOwn(data.headline, key)) {
      element.textContent = formatNumber(data.headline[key]);
    }
  });

  document.querySelectorAll("[data-severity]").forEach((element) => {
    const item = data.candidate_severity.find((entry) => entry.label === element.dataset.severity);
    if (item) element.textContent = formatNumber(item.value);
  });

  document.querySelectorAll("[data-evidence]").forEach((element) => {
    const item = data.evidence_scopes.find((entry) => entry.label === element.dataset.evidence);
    if (item) element.textContent = formatNumber(item.value);
  });

  document.querySelectorAll("[data-publication-label]").forEach((element) => {
    element.textContent = data.publication.label;
  });
}

function renderData(data) {
  updateNumbers(data);
  renderCases(data.case_studies);
  renderLimitations(data.limitations);

  const serviceCanvas = document.querySelector("#service-outcomes-chart");
  const riskCanvas = document.querySelector("#risk-types-chart");
  const categoryCanvas = document.querySelector("#finding-categories-chart");
  const riskTypes = data.candidate_risk_types.slice(0, 9);

  state.chartRenderers = [
    () => drawVerticalBars(serviceCanvas, data.service_outcomes),
    () => drawHorizontalBars(riskCanvas, riskTypes),
    () => drawDonut(categoryCanvas, data.finding_categories),
  ];
  state.chartRenderers.forEach((render) => render());
  renderLegend(document.querySelector("#service-outcomes-legend"), data.service_outcomes);
  renderLegend(document.querySelector("#finding-categories-legend"), data.finding_categories);
}

function showDataError() {
  const target = document.querySelector("#dataset .section-inner");
  const message = document.createElement("p");
  message.className = "data-error";
  message.textContent = "脱敏统计数据加载失败，请通过本地静态服务器或 GitHub Pages 访问。";
  target.prepend(message);
}

function seededRandom(seed) {
  let value = seed >>> 0;
  return () => {
    value = (value * 1664525 + 1013904223) >>> 0;
    return value / 4294967296;
  };
}

function setupNetworkCanvas() {
  const canvas = document.querySelector("#network-canvas");
  const hero = document.querySelector("#overview");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let context;
  let width;
  let height;
  let nodes = [];
  let animationFrame;
  let pointer = { x: -1000, y: -1000 };
  let start = performance.now();

  function resize() {
    const size = setCanvasSize(canvas);
    context = size.context;
    width = size.width;
    height = size.height;
    const random = seededRandom(width * 31 + height * 17);
    const count = width < 640 ? 34 : width < 980 ? 52 : 72;
    nodes = Array.from({ length: count }, (_, index) => ({
      x: random() * width,
      y: random() * height,
      baseX: random() * width,
      baseY: random() * height,
      radius: index % 11 === 0 ? 3.6 : 1.8 + random() * 1.2,
      phase: random() * Math.PI * 2,
      speed: 0.08 + random() * 0.14,
      alert: index % 11 === 0,
    }));
    nodes.forEach((node) => {
      node.baseX = node.x;
      node.baseY = node.y;
    });
  }

  function draw(time) {
    const elapsed = (time - start) / 1000;
    context.fillStyle = "#10231d";
    context.fillRect(0, 0, width, height);

    nodes.forEach((node, index) => {
      const movement = reducedMotion ? 0 : 12;
      node.x = node.baseX + Math.sin(elapsed * node.speed + node.phase) * movement;
      node.y = node.baseY + Math.cos(elapsed * node.speed * 0.8 + node.phase) * movement;
      const pointerDistance = Math.hypot(node.x - pointer.x, node.y - pointer.y);
      if (!reducedMotion && pointerDistance < 130) {
        const force = (130 - pointerDistance) / 130;
        node.x += (node.x - pointer.x) * force * 0.08;
        node.y += (node.y - pointer.y) * force * 0.08;
      }

      for (let next = index + 1; next < nodes.length; next += 1) {
        const other = nodes[next];
        const distance = Math.hypot(node.x - other.x, node.y - other.y);
        if (distance < 138) {
          context.beginPath();
          context.moveTo(node.x, node.y);
          context.lineTo(other.x, other.y);
          context.strokeStyle = `rgba(111, 181, 172, ${0.19 * (1 - distance / 138)})`;
          context.lineWidth = 1;
          context.stroke();
        }
      }
    });

    nodes.forEach((node) => {
      context.beginPath();
      context.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      context.fillStyle = node.alert ? "rgba(211, 91, 77, 0.88)" : "rgba(137, 208, 199, 0.72)";
      context.fill();
      if (node.alert) {
        context.beginPath();
        const pulse = reducedMotion ? 9 : 8 + ((elapsed * 10 + node.phase * 4) % 16);
        context.arc(node.x, node.y, pulse, 0, Math.PI * 2);
        context.strokeStyle = `rgba(211, 91, 77, ${reducedMotion ? 0.18 : Math.max(0, 0.28 - pulse / 90)})`;
        context.stroke();
      }
    });

    if (!reducedMotion) animationFrame = requestAnimationFrame(draw);
  }

  hero.addEventListener("pointermove", (event) => {
    const rect = hero.getBoundingClientRect();
    pointer = { x: event.clientX - rect.left, y: event.clientY - rect.top };
  });
  hero.addEventListener("pointerleave", () => {
    pointer = { x: -1000, y: -1000 };
  });

  resize();
  draw(performance.now());
  window.addEventListener("resize", () => {
    cancelAnimationFrame(animationFrame);
    resize();
    draw(performance.now());
  });
}

function setupNavigation() {
  const header = document.querySelector("[data-header]");
  const button = document.querySelector("[data-menu-button]");
  const navigation = document.querySelector("[data-navigation]");
  const icon = button.querySelector(".menu-icon");
  const sections = Array.from(document.querySelectorAll("main section[id]"));
  const links = Array.from(navigation.querySelectorAll("a[href^='#']"));

  function setMenu(open) {
    button.setAttribute("aria-expanded", String(open));
    navigation.classList.toggle("open", open);
    document.body.classList.toggle("menu-open", open);
    icon.textContent = open ? "×" : "☰";
    button.querySelector(".sr-only").textContent = open ? "关闭导航" : "打开导航";
  }

  button.addEventListener("click", () => setMenu(button.getAttribute("aria-expanded") !== "true"));
  links.forEach((link) => link.addEventListener("click", () => setMenu(false)));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setMenu(false);
  });

  const observer = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    links.forEach((link) => {
      link.classList.toggle("active", link.getAttribute("href") === `#${visible.target.id}`);
    });
  }, { rootMargin: "-25% 0px -60% 0px", threshold: [0.05, 0.25, 0.5] });
  sections.forEach((section) => observer.observe(section));

  window.addEventListener("scroll", () => header.classList.toggle("scrolled", window.scrollY > 20), { passive: true });
}

function setupResizeRendering() {
  let timer;
  window.addEventListener("resize", () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => state.chartRenderers.forEach((render) => render()), 120);
  });
}

async function main() {
  setupNavigation();
  setupNetworkCanvas();
  setupResizeRendering();
  try {
    const response = await fetch(DATA_URL, { cache: "no-store" });
    if (!response.ok) throw new Error(`data request failed: ${response.status}`);
    state.data = await response.json();
    renderData(state.data);
  } catch (error) {
    console.error(error);
    showDataError();
  }
}

main();
