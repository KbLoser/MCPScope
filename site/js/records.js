const RECORDS_URL = "data/public-records.json";
const GEOGRAPHY_URL = "data/public-geography.json";
const PAGE_SIZE = 24;

const state = {
  records: [],
  filtered: [],
  page: 1,
};

function setMenu(open) {
  const button = document.querySelector("[data-menu-button]");
  const navigation = document.querySelector("[data-navigation]");
  const icon = button.querySelector(".menu-icon");
  button.setAttribute("aria-expanded", String(open));
  navigation.classList.toggle("open", open);
  document.body.classList.toggle("menu-open", open);
  icon.textContent = open ? "×" : "☰";
  button.querySelector(".sr-only").textContent = open ? "关闭导航" : "打开导航";
}

function setupNavigation() {
  const button = document.querySelector("[data-menu-button]");
  const navigation = document.querySelector("[data-navigation]");
  button.addEventListener("click", () => setMenu(button.getAttribute("aria-expanded") !== "true"));
  navigation.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => setMenu(false)));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setMenu(false);
  });
  const header = document.querySelector("[data-header]");
  window.addEventListener("scroll", () => header.classList.toggle("scrolled", window.scrollY > 20), { passive: true });
}

function populateSelect(select, values) {
  values.forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.append(option);
  });
}

function formatNumber(value) {
  return new Intl.NumberFormat("zh-CN").format(value);
}

function renderMapDetail(country) {
  document.querySelector("#map-detail-title").textContent = country.label;
  document.querySelector("#map-detail-count").textContent = formatNumber(country.count);
  document.querySelector("#map-detail-note").textContent = "仅展示国家级脱敏统计，不显示原始目标、城市或工具名称。";
  const sources = document.querySelector("#map-detail-sources");
  sources.replaceChildren();
  country.source_counts.forEach((source) => {
    const row = document.createElement("div");
    row.className = "map-detail-source";
    const label = document.createElement("span");
    label.textContent = source.label;
    const value = document.createElement("strong");
    value.textContent = formatNumber(source.value);
    row.append(label, value);
    sources.append(row);
  });
}

function renderGeography(data) {
  const countryData = new Map(data.countries.map((country) => [country.id, country]));
  document.querySelector("#map-record-count").textContent = formatNumber(data.totals.records);
  document.querySelector("#map-country-count").textContent = formatNumber(data.totals.countries);
  document.querySelector("#map-unresolved-count").textContent = formatNumber(data.totals.unresolved);

  const land = document.querySelector("[data-map-land]");
  const countries = document.querySelector("[data-map-countries]");
  land.setAttribute("d", window.MCPSCOPE_WORLD_MAP.land_path);
  countries.replaceChildren();

  const mapped = data.countries.filter((country) => country.id !== "unresolved" && countryData.has(country.id));
  const max = Math.max(...mapped.map((country) => country.count), 1);
  const levelFor = (count) => {
    const ratio = count / max;
    if (ratio >= 0.5) return "4";
    if (ratio >= 0.2) return "3";
    if (ratio >= 0.05) return "2";
    return "1";
  };

  window.MCPSCOPE_WORLD_MAP.countries.forEach((countryShape) => {
    const country = countryData.get(countryShape.id) || (countryShape.id === "158" ? countryData.get("156") : null);
    if (!country) return;
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.classList.add("world-country");
    path.setAttribute("d", countryShape.path);
    path.setAttribute("tabindex", "0");
    path.setAttribute("role", "button");
    path.setAttribute("aria-label", `${country.label}，${formatNumber(country.count)} 条记录`);
    path.dataset.level = levelFor(country.count);
    const activate = () => {
      document.querySelectorAll(".world-country.is-active").forEach((item) => item.classList.remove("is-active"));
      path.classList.add("is-active");
      renderMapDetail(country);
    };
    path.addEventListener("pointerenter", activate);
    path.addEventListener("focus", activate);
    path.addEventListener("click", activate);
    countries.append(path);
  });

  const largest = data.countries.find((country) => country.id !== "unresolved");
  if (largest) renderMapDetail(largest);
}

function createRecordRow(record) {
  const row = document.createElement("article");
  row.className = "record-row";

  const id = document.createElement("span");
  id.className = "record-id";
  id.textContent = record.record_id;

  const tool = document.createElement("span");
  tool.className = "record-tool";
  tool.textContent = record.masked_tool_name;

  const target = document.createElement("span");
  target.className = "record-target";
  target.textContent = record.masked_target;

  const category = document.createElement("span");
  category.className = "record-category";
  category.textContent = record.category;

  const source = document.createElement("span");
  source.className = "record-source";
  source.textContent = record.source;

  row.append(id, tool, target, category, source);
  return row;
}

function renderPagination(totalPages) {
  const container = document.querySelector("#page-buttons");
  container.replaceChildren();
  const visiblePages = new Set([1, totalPages, state.page - 1, state.page, state.page + 1]);
  const pages = [...visiblePages].filter((page) => page > 0 && page <= totalPages).sort((a, b) => a - b);
  let previous = 0;

  pages.forEach((page) => {
    if (page - previous > 1) {
      const ellipsis = document.createElement("span");
      ellipsis.className = "page-number";
      ellipsis.textContent = "…";
      ellipsis.setAttribute("aria-hidden", "true");
      container.append(ellipsis);
    }
    const button = document.createElement("button");
    button.className = "page-number";
    button.type = "button";
    button.textContent = String(page);
    button.setAttribute("aria-label", `第 ${page} 页`);
    button.setAttribute("aria-current", page === state.page ? "page" : "false");
    if (page === state.page) button.classList.add("active");
    button.addEventListener("click", () => {
      state.page = page;
      renderRecords();
      window.scrollTo({ top: document.querySelector(".records-section").offsetTop - 80, behavior: "smooth" });
    });
    container.append(button);
    previous = page;
  });

  document.querySelector("#previous-page").disabled = state.page === 1;
  document.querySelector("#next-page").disabled = state.page === totalPages;
}

function renderRecords() {
  const totalPages = Math.max(1, Math.ceil(state.filtered.length / PAGE_SIZE));
  state.page = Math.min(state.page, totalPages);
  const start = (state.page - 1) * PAGE_SIZE;
  const visible = state.filtered.slice(start, start + PAGE_SIZE);
  const list = document.querySelector("#record-list");
  list.replaceChildren();

  if (!visible.length) {
    const empty = document.createElement("p");
    empty.className = "record-empty";
    empty.textContent = "没有符合当前筛选条件的脱敏记录。";
    list.append(empty);
  } else {
    visible.forEach((record) => list.append(createRecordRow(record)));
  }

  document.querySelector("#result-count").textContent = `显示 ${state.filtered.length} 条记录`;
  document.querySelector("#page-status").textContent = `第 ${state.page} / ${totalPages} 页`;
  renderPagination(totalPages);
}

function applyFilters() {
  const query = document.querySelector("#record-search").value.trim().toLowerCase();
  const category = document.querySelector("#category-filter").value;
  const source = document.querySelector("#source-filter").value;
  state.filtered = state.records.filter((record) => {
    const matchesQuery = !query || `${record.record_id} ${record.masked_tool_name} ${record.masked_target}`.toLowerCase().includes(query);
    return matchesQuery && (!category || record.category === category) && (!source || record.source === source);
  });
  state.page = 1;
  renderRecords();
}

function renderData(data) {
  state.records = data.records;
  state.filtered = data.records.slice();
  const categories = [...new Set(data.records.map((record) => record.category))];
  const sources = [...new Set(data.records.map((record) => record.source))];
  populateSelect(document.querySelector("#category-filter"), categories);
  populateSelect(document.querySelector("#source-filter"), sources);
  document.querySelector("#total-count").textContent = String(data.records.length);
  document.querySelector("#category-count").textContent = String(categories.length);
  document.querySelector("#source-count").textContent = String(sources.length);
  renderRecords();
}

function showError() {
  document.querySelector("#records-error").hidden = false;
  document.querySelector("#record-list").replaceChildren();
}

async function main() {
  setupNavigation();
  const fallback = window.MCPSCOPE_PUBLIC_RECORDS;
  const geographyFallback = window.MCPSCOPE_PUBLIC_GEOGRAPHY;
  if (window.location.protocol === "file:" && fallback && geographyFallback) {
    renderData(fallback);
    renderGeography(geographyFallback);
    return;
  }
  try {
    const [recordsResponse, geographyResponse] = await Promise.all([
      fetch(RECORDS_URL, { cache: "no-store" }),
      fetch(GEOGRAPHY_URL, { cache: "no-store" }),
    ]);
    if (!recordsResponse.ok) throw new Error(`record request failed: ${recordsResponse.status}`);
    if (!geographyResponse.ok) throw new Error(`geography request failed: ${geographyResponse.status}`);
    renderData(await recordsResponse.json());
    renderGeography(await geographyResponse.json());
  } catch (error) {
    if (fallback && geographyFallback) {
      renderData(fallback);
      renderGeography(geographyFallback);
    }
    else {
      console.error(error);
      showError();
    }
  }
}

document.querySelector("#record-search").addEventListener("input", applyFilters);
document.querySelector("#category-filter").addEventListener("change", applyFilters);
document.querySelector("#source-filter").addEventListener("change", applyFilters);
document.querySelector("#reset-filters").addEventListener("click", () => {
  document.querySelector("#record-search").value = "";
  document.querySelector("#category-filter").value = "";
  document.querySelector("#source-filter").value = "";
  applyFilters();
});
document.querySelector("#previous-page").addEventListener("click", () => {
  if (state.page > 1) {
    state.page -= 1;
    renderRecords();
  }
});
document.querySelector("#next-page").addEventListener("click", () => {
  if (state.page < Math.ceil(state.filtered.length / PAGE_SIZE)) {
    state.page += 1;
    renderRecords();
  }
});

main();
