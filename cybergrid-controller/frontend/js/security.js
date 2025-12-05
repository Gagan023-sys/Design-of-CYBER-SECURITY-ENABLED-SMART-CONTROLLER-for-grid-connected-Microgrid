(function () {
  const sessionPanel = document.getElementById("session-panel");
  const alertsPanel = document.getElementById("alerts-panel");
  const attackPanel = document.getElementById("attack-panel");
  const alertsTableBody = document.getElementById("alerts-table-body");
  const refreshBtn = document.getElementById("refresh-alerts");
  const attackForm = document.getElementById("attack-form");
  const attackTypeInput = document.getElementById("attack-type");
  const attackComponentInput = document.getElementById("attack-component");
  const logoutBtn = document.getElementById("logout-btn");
  const messageArea = document.getElementById("message-area");

  let pollHandle = null;
  let messageTimer = null;
  let currentUser = null;

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
      currentUser = await CyberGrid.auth.ensure();
      CyberGrid.ui.updateUserBanner(currentUser);
      CyberGrid.ui.renderNav("security");
      CyberGrid.ui.attachSignOut(logoutBtn);
      if (sessionPanel) sessionPanel.classList.remove("hidden");
      if (alertsPanel) alertsPanel.classList.remove("hidden");
      configureAttackPanel();
      startPolling();
      if (refreshBtn) refreshBtn.addEventListener("click", () => refreshAlerts(true));
      if (attackForm) attackForm.addEventListener("submit", handleAttackSubmit);
    } catch (error) {
      console.error("Security page init failed", error);
    }
  }

  function configureAttackPanel() {
    const allowed = currentUser && ["admin", "analyst"].includes(currentUser.role);
    if (!attackPanel) return;
    attackPanel.classList.toggle("hidden", !allowed);
  }

  function startPolling() {
    stopPolling();
    refreshAlerts(true);
    pollHandle = setInterval(refreshAlerts, 9000);
  }

  function stopPolling() {
    if (pollHandle) {
      clearInterval(pollHandle);
      pollHandle = null;
    }
  }

  async function refreshAlerts(force = false) {
    try {
      const response = await CyberGrid.apiFetch("/alerts?limit=60");
      if (!response.ok) {
        if (force) console.warn("Alert fetch failed", response.statusText);
        return;
      }
      const data = await response.json();
      const items = Array.isArray(data.items) ? data.items : [];
      renderAlerts(items);
    } catch (error) {
      console.warn("Alerts refresh error", error);
    }
  }

  function renderAlerts(items) {
    if (!alertsTableBody) return;
    alertsTableBody.innerHTML = "";
    const fragment = document.createDocumentFragment();
    items.slice(0, 60).forEach((event) => {
      const row = document.createElement("tr");
      createCell(row, CyberGrid.util.formatTime(event.created_at), "column-time");
      const severity = (event.severity || "info").toLowerCase();
      createCell(row, severity.toUpperCase(), `severity severity-${severity}`);
      createCell(row, event.category || "—");
      createCell(row, event.context?.component || "—");
      createCell(row, event.details || "—");
      const mitigation = event.context?.mitigation || "—";
      const mitigationCell = createCell(row, mitigation);
      if (mitigation && mitigation !== "—") {
        mitigationCell.title = mitigation;
      }
      fragment.appendChild(row);
    });
    alertsTableBody.appendChild(fragment);
  }

  async function handleAttackSubmit(event) {
    event.preventDefault();
    if (!currentUser || !["admin", "analyst"].includes(currentUser.role)) {
      setMessage("Attack simulations require analyst or admin role.", "error");
      return;
    }
    try {
      const response = await CyberGrid.apiFetch("/simulations/attack", {
        method: "POST",
        body: {
          attack_type: attackTypeInput.value,
          component: attackComponentInput.value.trim(),
        },
      });
      const data = await response.json();
      if (!response.ok) {
        setMessage(data.detail || "Simulation failed.", "error");
        return;
      }
      attackForm.reset();
      setMessage(`Simulated ${data.alert?.metric || attackTypeInput.value} attack.`, "success");
      refreshAlerts(true);
    } catch (error) {
      console.error("Simulation error", error);
      setMessage("Unable to run simulation.", "error");
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
