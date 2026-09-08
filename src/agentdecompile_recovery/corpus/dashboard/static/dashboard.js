(function () {
  "use strict";

  document.documentElement.classList.add("js");

  function mainElement() {
    return document.querySelector("main") || document.querySelector("#app");
  }

  function installSkipLink() {
    const main = mainElement();
    if (!main) return;
    if (!main.id) main.id = "main-content";
    if (!main.hasAttribute("tabindex")) main.tabIndex = -1;
    if (document.querySelector(".skip-link")) return;

    const skip = document.createElement("a");
    skip.className = "skip-link";
    skip.href = "#" + main.id;
    skip.textContent = "Skip to main content";
    skip.addEventListener("click", function () {
      window.setTimeout(function () { main.focus(); }, 0);
    });
    document.body.prepend(skip);
  }

  function installNavigation() {
    const topbar = document.querySelector(".topbar");
    const nav = topbar && topbar.querySelector("nav");
    if (!topbar || !nav) return;

    if (!nav.id) nav.id = "site-navigation";
    const currentPath = window.location.pathname.replace(/\/$/, "") || "/";
    nav.querySelectorAll("a[href]").forEach(function (link) {
      let path;
      try {
        path = new URL(link.href, window.location.href).pathname.replace(/\/$/, "") || "/";
      } catch (_) {
        return;
      }
      const exact = path === currentPath;
      const section = path !== "/" && currentPath.startsWith(path + "/");
      if (exact || section) link.setAttribute("aria-current", "page");
    });

    let toggle = topbar.querySelector(".nav-toggle");
    if (!toggle) {
      toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "nav-toggle";
      toggle.setAttribute("aria-expanded", "false");
      toggle.textContent = "Menu";
      topbar.insertBefore(toggle, nav);
    }
    toggle.setAttribute("aria-controls", nav.id);

    function setOpen(open) {
      topbar.dataset.navOpen = open ? "true" : "false";
      toggle.setAttribute("aria-expanded", String(open));
      toggle.textContent = open ? "Close menu" : "Menu";
    }

    toggle.addEventListener("click", function () {
      setOpen(toggle.getAttribute("aria-expanded") !== "true");
    });
    nav.addEventListener("click", function (event) {
      if (event.target.closest("a")) setOpen(false);
    });
    window.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
        setOpen(false);
        toggle.focus();
      }
    });
  }

  function announceRegion() {
    let region = document.querySelector("#ui-status");
    if (region) return region;
    region = document.createElement("div");
    region.id = "ui-status";
    region.className = "sr-only";
    region.setAttribute("role", "status");
    region.setAttribute("aria-live", "polite");
    region.setAttribute("aria-atomic", "true");
    document.body.appendChild(region);
    return region;
  }

  function announce(message) {
    const region = announceRegion();
    region.textContent = "";
    window.setTimeout(function () { region.textContent = String(message || ""); }, 20);
  }

  function setBusy(element, busy, message) {
    if (!element) return;
    element.setAttribute("aria-busy", busy ? "true" : "false");
    element.classList.toggle("loading-indicator", Boolean(busy));
    if (message) announce(message);
  }

  function syncPanelBusy(root) {
    (root || document).querySelectorAll(".sec-body, [data-loading]").forEach(function (body) {
      const busy = body.dataset.loading === "1" || body.getAttribute("data-loading") === "true";
      body.setAttribute("aria-busy", String(busy));
    });
  }

  function installBusyObserver() {
    syncPanelBusy(document);
    const observer = new MutationObserver(function (records) {
      records.forEach(function (record) {
        if (record.type === "attributes") syncPanelBusy(record.target.parentElement || document);
        record.addedNodes.forEach(function (node) {
          if (node.nodeType === Node.ELEMENT_NODE) syncPanelBusy(node);
        });
      });
    });
    observer.observe(document.body, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ["data-loading"]
    });
  }

  function tableLabel(table) {
    if (table.querySelector("caption")) return table.querySelector("caption").textContent.trim();
    const heading = table.closest("section, article, main")?.querySelector("h1, h2, h3");
    return heading ? heading.textContent.trim() + " data table" : "Scrollable data table";
  }

  function enhanceTables() {
    document.querySelectorAll("table").forEach(function (table) {
      let wrap = table.parentElement;
      if (!wrap.classList.contains("tablewrap")) {
        wrap = document.createElement("div");
        wrap.className = "tablewrap";
        table.before(wrap);
        wrap.appendChild(table);
      }
      wrap.setAttribute("role", "region");
      wrap.setAttribute("aria-label", tableLabel(table));
      function syncScrollable() {
        if (wrap.scrollWidth > wrap.clientWidth + 1) {
          wrap.tabIndex = 0;
          wrap.dataset.scrollable = "true";
        } else {
          wrap.removeAttribute("tabindex");
          delete wrap.dataset.scrollable;
        }
      }
      window.requestAnimationFrame(syncScrollable);
      window.addEventListener("resize", syncScrollable, { passive: true });
    });
  }

  function enhanceRepeatedActions() {
    document.querySelectorAll("table tbody tr").forEach(function (row) {
      const cells = Array.from(row.querySelectorAll("td"));
      if (!cells.length) return;
      const subject = cells.slice(0, 2).map(function (cell) {
        return cell.textContent.trim();
      }).filter(Boolean).join(" — ");
      row.querySelectorAll("a").forEach(function (link) {
        if (link.hasAttribute("aria-label")) return;
        const text = link.textContent.trim().toLowerCase();
        if (text === "flow" || text === "graph") {
          link.setAttribute("aria-label", "Open call graph for " + subject);
        }
      });
    });
  }

  function installMovedHash() {
    const path = (window.location.pathname || "").replace(/\/$/, "") || "/";
    if (path !== "/dashboard") return;
    const moved = {
      review: "/dashboard?window=wb-review",
      builds: "/dashboard?window=wb-corpus",
      graph: "/dashboard?window=wb-graph",
      logical: "/dashboard?window=wb-logical"
    };
    const dest = moved[(window.location.hash || "").replace(/^#/, "")];
    if (dest) window.location.replace(dest);
  }

  function installWorkspaceNav() {
    const nav = document.querySelector(".workspace-nav");
    if (!nav) return;
    function openPane(id) {
      if (!id) return;
      const pane = document.getElementById(id);
      if (pane && pane.tagName === "DETAILS") pane.open = true;
    }
    nav.querySelectorAll("a[href^='#']").forEach(function (link) {
      link.addEventListener("click", function () {
        openPane((link.getAttribute("href") || "").slice(1));
      });
    });
    const hash = (window.location.hash || "").replace(/^#/, "");
    if (hash) openPane(hash);
    const params = new URLSearchParams(window.location.search);
    if (params.get("addr") || params.get("logical_id")) openPane("graph");
    if (params.get("review_after")) openPane("review");
    if (params.get("lq") || params.get("logical_q")) openPane("logical");
  }

  function installLiveBrowse() {
    const form = document.querySelector("[data-live-search='functions']");
    if (!form) return;
    const input = form.querySelector("#function-search");
    const pageSize = form.querySelector("#page-size");
    let timer = 0;
    let controller = null;

    function publicParams() {
      const data = new FormData(form);
      data.delete("after");
      data.delete("partial");
      const params = new URLSearchParams();
      data.forEach(function (value, key) {
        if (value !== "") params.set(key, String(value));
      });
      return params;
    }

    function applyFragment(html) {
      const wrap = document.createElement("div");
      wrap.innerHTML = html;
      const next = wrap.querySelector("#function-results") || wrap.firstElementChild;
      const current = document.getElementById("function-results");
      if (current && next) {
        current.replaceWith(next);
      } else if (current) {
        current.innerHTML = html;
      }
      if (window.KotorXidUI) {
        window.KotorXidUI.enhanceTables();
        window.KotorXidUI.enhanceRepeatedActions();
      }
    }

    function fetchResults() {
      const params = publicParams();
      const hash = window.location.hash || "#functions";
      const publicUrl = "/dashboard/functions" + (params.toString() ? "?" + params.toString() : "") + hash;
      params.set("partial", "1");
      if (controller) controller.abort();
      controller = new AbortController();
      const dest = document.getElementById("function-results");
      setBusy(dest, true, "Updating functions");
      fetch("/dashboard/functions?" + params.toString(), {
        headers: { Accept: "text/html", "X-Requested-With": "fetch" },
        signal: controller.signal
      }).then(function (response) {
        if (!response.ok) throw new Error("search failed");
        return response.text();
      }).then(function (html) {
        applyFragment(html);
        history.replaceState(null, "", publicUrl);
        setBusy(document.getElementById("function-results"), false, "Functions updated");
      }).catch(function (err) {
        if (err && err.name === "AbortError") return;
        setBusy(document.getElementById("function-results"), false, "Search failed");
      });
    }

    function schedule() {
      window.clearTimeout(timer);
      timer = window.setTimeout(fetchResults, 280);
    }

    if (input) {
      input.addEventListener("input", schedule);
      input.addEventListener("search", schedule);
    }
    if (pageSize) pageSize.addEventListener("change", fetchResults);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      fetchResults();
    });
  }

  function fillFunctionList(select, results, current) {
    if (!select) return;
    const seen = new Set();
    select.innerHTML = "";
    (results || []).forEach(function (row) {
      const addr = String(row.addr || "");
      if (!addr || seen.has(addr)) return;
      seen.add(addr);
      const option = document.createElement("option");
      option.value = addr;
      option.textContent = (row.name || addr) + " — " + addr;
      if (current && addr.toLowerCase() === String(current).toLowerCase()) option.selected = true;
      select.appendChild(option);
    });
    if (!select.options.length) {
      const empty = document.createElement("option");
      empty.value = "";
      empty.disabled = true;
      empty.textContent = "No matching functions";
      select.appendChild(empty);
    }
  }

  function installFunctionCombo() {
    const form = document.querySelector("[data-fn-combo='1']");
    if (!form) return;
    const build = form.querySelector("select[name='slug']");
    const filter = form.querySelector("#fn-combo-filter");
    const list = form.querySelector("#fn-combo-list");
    if (!build || !list) return;
    let timer = 0;
    let controller = null;

    function loadChoices() {
      const params = new URLSearchParams();
      params.set("slug", build.value || "");
      if (filter && filter.value.trim()) params.set("q", filter.value.trim());
      else if (list.value) params.set("around", list.value);
      params.set("limit", "80");
      if (controller) controller.abort();
      controller = new AbortController();
      setBusy(list, true, "Loading functions");
      fetch("/dashboard/api/function-choices?" + params.toString(), {
        headers: { Accept: "application/json" },
        signal: controller.signal
      }).then(function (response) { return response.json(); }).then(function (payload) {
        fillFunctionList(list, payload.results || [], list.value);
        setBusy(list, false, (payload.results || []).length + " functions");
      }).catch(function (err) {
        if (err && err.name === "AbortError") return;
        setBusy(list, false, "Could not load functions");
      });
    }

    if (filter) {
      filter.addEventListener("input", function () {
        window.clearTimeout(timer);
        timer = window.setTimeout(loadChoices, 220);
      });
    }
    build.addEventListener("change", loadChoices);
    list.addEventListener("change", function () {
      if (!form.closest("[data-fn-workspace]") || !list.value) return;
      form.submit();
    });
  }

  function installGraphStage() {
    const stage = document.querySelector("[data-graph-stage]");
    const zoom = document.querySelector(".graph-zoom");
    if (!stage || !zoom) return;
    zoom.hidden = false;
    let scale = 1;
    let panX = 0;
    let panY = 0;
    let drag = null;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function apply() {
      const svg = stage.querySelector("svg");
      if (!svg) return;
      svg.style.transformOrigin = "0 0";
      svg.style.transform = "translate(" + panX + "px," + panY + "px) scale(" + scale + ")";
      stage.dataset.wide = stage.classList.contains("is-wide") ? "true" : "false";
    }

    function setScale(next) {
      scale = Math.min(3, Math.max(0.4, next));
      apply();
    }

    zoom.addEventListener("click", function (event) {
      const button = event.target.closest("[data-zoom]");
      if (!button) return;
      const action = button.getAttribute("data-zoom");
      if (action === "in") setScale(scale + 0.15);
      if (action === "out") setScale(scale - 0.15);
      if (action === "reset" || action === "fit") {
        scale = 1;
        panX = 0;
        panY = 0;
        apply();
      }
      if (action === "wide") {
        const grid = document.querySelector(".fn-grid");
        if (grid) grid.classList.toggle("graph-wide");
        stage.classList.toggle("is-wide");
      }
      if (action === "legend") {
        document.querySelectorAll(".graph-legend, .fn-graph .note").forEach(function (node) {
          node.hidden = !node.hidden;
        });
      }
    });

    stage.addEventListener("pointerdown", function (event) {
      if (event.button !== 0 || event.target.closest("a")) return;
      drag = { x: event.clientX - panX, y: event.clientY - panY };
      stage.classList.add("is-dragging");
      stage.setPointerCapture(event.pointerId);
    });
    stage.addEventListener("pointermove", function (event) {
      if (!drag) return;
      panX = event.clientX - drag.x;
      panY = event.clientY - drag.y;
      apply();
    });
    function endDrag() {
      drag = null;
      stage.classList.remove("is-dragging");
    }
    stage.addEventListener("pointerup", endDrag);
    stage.addEventListener("pointercancel", endDrag);
    if (!reduce) {
      stage.addEventListener("wheel", function (event) {
        if (!event.ctrlKey && !event.metaKey) return;
        event.preventDefault();
        setScale(scale + (event.deltaY < 0 ? 0.12 : -0.12));
      }, { passive: false });
    }
    stage._graphView = {
      zoomIn: function () { setScale(scale + 0.15); },
      zoomOut: function () { setScale(scale - 0.15); },
      reset: function () { scale = 1; panX = 0; panY = 0; apply(); }
    };
  }

  function installCopyAddress() {
    document.querySelectorAll("[data-copy]").forEach(function (button) {
      button.addEventListener("click", function () {
        const text = button.getAttribute("data-copy") || "";
        if (!text || !navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          announce("Copied " + text);
        }).catch(function () {});
      });
    });
    document.querySelectorAll("[data-copy-source]").forEach(function (button) {
      button.addEventListener("click", function () {
        const block = button.closest(".fn-source");
        const pre = block && block.querySelector("pre");
        const text = pre ? pre.textContent : "";
        if (!text || !navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(function () {
          announce("Copied decompiled C");
        }).catch(function () {});
      });
    });
  }

  function installFunctionKeys() {
    const workspace = document.querySelector("[data-fn-workspace]");
    if (!workspace) return;
    const help = document.querySelector("#fn-help");
    document.querySelectorAll(".fn-help-open").forEach(function (button) {
      button.addEventListener("click", function () {
        if (help && help.showModal) help.showModal();
      });
    });
    window.addEventListener("keydown", function (event) {
      if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.altKey) return;
      const tag = (event.target && event.target.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") {
        if (event.key === "Escape") event.target.blur();
        return;
      }
      if (event.key === "/") {
        const filter = document.querySelector("#fn-combo-filter");
        if (filter) {
          event.preventDefault();
          const picker = document.querySelector(".fn-picker");
          if (picker) picker.open = true;
          filter.focus();
        }
      }
      if (event.key === "[") {
        const prev = document.querySelector('.fn-step a[rel="prev"]');
        if (prev) prev.click();
      }
      if (event.key === "]") {
        const next = document.querySelector('.fn-step a[rel="next"]');
        if (next) next.click();
      }
      if (event.key === "?" && help && help.showModal) {
        event.preventDefault();
        help.showModal();
      }
      const view = document.querySelector("[data-graph-stage]");
      if (view && view._graphView) {
        if (event.key === "+" || event.key === "=") view._graphView.zoomIn();
        if (event.key === "-" || event.key === "_") view._graphView.zoomOut();
        if (event.key === "0") view._graphView.reset();
        if (event.key === "w") {
          const wide = document.querySelector("[data-zoom='wide']");
          if (wide) wide.click();
        }
      }
    });
  }

  function installLiveStatus() {
    const pulse = document.querySelector("#pulse");
    if (!pulse) return;
    pulse.setAttribute("role", "status");
    pulse.setAttribute("aria-live", "polite");
    pulse.setAttribute("aria-atomic", "false");
  }

  function init() {
    installSkipLink();
    installNavigation();
    installMovedHash();
    installWorkspaceNav();
    installLiveBrowse();
    installLiveStatus();
    enhanceTables();
    enhanceRepeatedActions();
    installBusyObserver();
    installFunctionCombo();
    installGraphStage();
    installCopyAddress();
    installFunctionKeys();
  }

  window.KotorXidUI = Object.freeze({
    announce: announce,
    setBusy: setBusy,
    enhanceTables: enhanceTables,
    enhanceRepeatedActions: enhanceRepeatedActions
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
