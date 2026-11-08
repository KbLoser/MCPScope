const RECORDS_URL = "data/public-records.json";
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

function createRecordRow(record) {
  const row = document.createElement("article");
  row.className = "record-row";

  const id = document.createElement("span");
  id.className = "record-id";
  id.textContent = record.record_id;

  const tool = document.createElement("span");
  tool.className = "record-tool";
  tool.textContent = record.masked_tool_name;

  const category = document.createElement("span");
  category.className = "record-category";
  category.textContent = record.category;

  const source = document.createElement("span");
  source.className = "record-source";
  source.textContent = record.source;

  row.append(id, tool, category, source);
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
    const matchesQuery = !query || `${record.record_id} ${record.masked_tool_name}`.toLowerCase().includes(query);
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
  if (window.location.protocol === "file:" && fallback) {
    renderData(fallback);
    return;
  }
  try {
    const response = await fetch(RECORDS_URL, { cache: "no-store" });
    if (!response.ok) throw new Error(`record request failed: ${response.status}`);
    renderData(await response.json());
  } catch (error) {
    if (fallback) renderData(fallback);
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
