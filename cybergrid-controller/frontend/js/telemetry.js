(function () {
  const sessionPanel = document.getElementById("session-panel");
  const telemetryPanel = document.getElementById("telemetry-panel");
  const logoutBtn = document.getElementById("logout-btn");
  const toggleBtn = document.getElementById("toggle-telemetry");
  const statusEl = document.getElementById("telemetry-status");
  const tableBody = document.getElementById("telemetry-table-body");
  const chartCanvas = document.getElementById("telemetry-chart");
  const messageArea = document.getElementById("message-area");

  const colorPalette = ["#38bdf8", "#22c55e", "#f97316", "#a855f7", "#f43f5e", "#facc15", "#34d399", "#f472b6"];
  const state = {
    telemetryLive: true,
    pollHandle: null,
    chart: null,
    chartColors: {},
    colorIndex: 0,
  };

  let messageTimer = null;

  function setMessage(text, type = "info", duration = 5000) {
    clearTimeout(messageTimer);
    if (!messageArea) return;
    if (!text) {
      messageArea.className = "notice hidden";
      messageArea.textContent = "";
      return;
    }
    messageArea.className = `notice ${type}`;
    messageArea.textContent = text;
    messageTimer = setTimeout(() => {
      messageArea.className = "notice hidden";
      messageArea.textContent = "";
    }, duration);
  }

  async function initialize() {
    try {
      const user = await CyberGrid.auth.ensure();
      if (sessionPanel) sessionPanel.classList.remove("hidden");
      if (telemetryPanel) telemetryPanel.classList.remove("hidden");
      CyberGrid.ui.updateUserBanner(user);
      CyberGrid.ui.renderNav("telemetry");
      CyberGrid.ui.attachSignOut(logoutBtn);
      if (toggleBtn) toggleBtn.addEventListener("click", toggleTelemetry);
      updateTelemetryStatus();
      startPolling();
    } catch (error) {
      console.error("Telemetry init error", error);
    }
  }

  function startPolling() {
    stopPolling();
    refreshTelemetry(true);
    state.pollHandle = setInterval(refreshTelemetry, 6000);
  }

  function stopPolling() {
    if (state.pollHandle) {
      clearInterval(state.pollHandle);
      state.pollHandle = null;
    }
  }

  async function refreshTelemetry(force = false) {
    if (!state.telemetryLive && !force) return;
    try {
      const response = await CyberGrid.apiFetch("/telemetry?limit=60");
      if (!response.ok) return;
      const data = await response.json();
      const items = Array.isArray(data.items) ? data.items : [];
      renderTelemetryTable(items);
      updateTelemetryChart(items);
    } catch (error) {
      console.warn("Telemetry refresh failed", error);
    }
  }

  function renderTelemetryTable(items) {
    if (!tableBody) return;
    tableBody.innerHTML = "";
    const fragment = document.createDocumentFragment();
    const rows = [...items].slice(-25).reverse();
    rows.forEach((item) => {
      const row = document.createElement("tr");
      createCell(row, item.component || "—");
      createCell(row, CyberGrid.util.formatNumber(item.payload?.voltage), "column-number");
      createCell(row, CyberGrid.util.formatNumber(item.payload?.frequency, 3), "column-number");
      createCell(row, item.payload?.status || "—");
      createCell(row, CyberGrid.util.formatTime(item.created_at));
      fragment.appendChild(row);
    });
    tableBody.appendChild(fragment);
  }

  function updateTelemetryChart(items) {
    if (!chartCanvas) return;
    const sorted = [...items]
      .filter((item) => item && item.created_at)
      .sort((a, b) => new Date(a.created_at) - new Date(b.created_at))
      .slice(-40);
    const labels = sorted.map((item) => CyberGrid.util.formatTime(item.created_at));
    const components = Array.from(new Set(sorted.map((item) => item.component || "Unknown")));
    const datasets = components.map((component) => {
      const dataPoints = sorted.map((item) => {
        if ((item.component || "Unknown") !== component) return null;
        const voltage = Number(item.payload?.voltage);
        return Number.isFinite(voltage) ? Number(voltage.toFixed(2)) : null;
      });
      return {
        label: component,
        data: dataPoints,
        borderColor: colorFor(component),
        borderWidth: 2,
        tension: 0.35,
        fill: false,
        spanGaps: true,
        pointRadius: 2,
      };
    });
    if (!state.chart) {
      const ctx = chartCanvas.getContext("2d");
      state.chart = new Chart(ctx, {
        type: "line",
        data: { labels, datasets },
        options: {
          animation: false,
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: false,
              title: { display: true, text: "Voltage (V)" },
              grid: { color: "rgba(148, 163, 184, 0.15)" },
            },
            x: {
              grid: { color: "rgba(148, 163, 184, 0.12)" },
            },
          },
          plugins: {
            legend: { position: "bottom", labels: { usePointStyle: true } },
          },
        },
      });
    } else {
      state.chart.data.labels = labels;
      state.chart.data.datasets = datasets;
      state.chart.update();
    }
  }

  function colorFor(component) {
    if (!state.chartColors[component]) {
      const color = colorPalette[state.colorIndex % colorPalette.length];
      state.chartColors[component] = color;
      state.colorIndex += 1;
    }
    return state.chartColors[component];
  }

  function toggleTelemetry() {
    state.telemetryLive = !state.telemetryLive;
    updateTelemetryStatus();
    if (state.telemetryLive) {
      refreshTelemetry(true);
      setMessage("Telemetry streaming resumed.", "success");
    } else {
      setMessage("Telemetry streaming paused.", "info");
    }
  }

  function updateTelemetryStatus() {
    if (!statusEl || !toggleBtn) return;
    if (state.telemetryLive) {
      statusEl.textContent = "Live updates ON";
      statusEl.classList.remove("paused");
      toggleBtn.textContent = "Pause Live Telemetry";
    } else {
      statusEl.textContent = "Live updates paused";
      statusEl.classList.add("paused");
      toggleBtn.textContent = "Resume Live Telemetry";
    }
  }

  function createCell(row, text, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = text ?? "—";
    row.appendChild(cell);
    return cell;
  }

  window.addEventListener("beforeunload", stopPolling);
  initialize();
})();
