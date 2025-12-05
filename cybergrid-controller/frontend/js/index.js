(function () {
  const loginPanel = document.getElementById("login-panel");
  const loginForm = document.getElementById("login-form");
  const loginStatus = document.getElementById("login-status");
  const sessionPanel = document.getElementById("session-panel");
  const summaryPanel = document.getElementById("summary-panel");
  const messageArea = document.getElementById("message-area");
  const logoutBtn = document.getElementById("logout-btn");
  const recentAlertsList = document.getElementById("recent-alerts");

  let summaryTimer = null;
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

  function togglePanels(isAuthenticated) {
    if (loginPanel) loginPanel.classList.toggle("hidden", isAuthenticated);
    if (sessionPanel) sessionPanel.classList.toggle("hidden", !isAuthenticated);
    if (summaryPanel) summaryPanel.classList.toggle("hidden", !isAuthenticated);
  }

  async function initialize() {
    const user = await CyberGrid.auth
      .ensure({ redirect: false })
      .catch(() => null);
    if (user) {
      onAuthenticated(user, false);
    } else {
      togglePanels(false);
      CyberGrid.ui.renderNav();
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    if (!loginForm) return;
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    loginStatus.textContent = "Authenticating...";
    setMessage("");
    try {
      const response = await fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (!response.ok) {
        const detail = data.detail || "Login failed.";
        loginStatus.textContent = detail;
        setMessage(detail, "error");
        return;
      }
      CyberGrid.auth.saveTokens({
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
      });
      const user = await CyberGrid.auth.fetchProfile();
      loginStatus.textContent = "";
      setMessage(`Welcome back, ${user.username}.`, "success");
      onAuthenticated(user, true);
    } catch (error) {
      console.error("Login error", error);
      loginStatus.textContent = "Unable to sign in right now.";
      setMessage("Unable to sign in right now.", "error");
    }
  }

  function onAuthenticated(user, renderNav = true) {
    togglePanels(true);
    CyberGrid.ui.updateUserBanner(user);
    if (renderNav) {
      CyberGrid.ui.renderNav("overview");
    } else {
      CyberGrid.ui.renderNav("overview");
    }
    if (logoutBtn) {
      logoutBtn.replaceWith(logoutBtn.cloneNode(true));
    }
    const freshLogoutBtn = document.getElementById("logout-btn");
    CyberGrid.ui.attachSignOut(freshLogoutBtn);
    startSummaryPolling();
  }

  function startSummaryPolling() {
    stopSummaryPolling();
    loadSummary();
    summaryTimer = setInterval(loadSummary, 20000);
  }

  function stopSummaryPolling() {
    if (summaryTimer) {
      clearInterval(summaryTimer);
      summaryTimer = null;
    }
  }

  async function loadSummary() {
    try {
      const response = await CyberGrid.apiFetch("/admin/activity/summary");
      if (!response.ok) {
        if (response.status === 403) {
          stopSummaryPolling();
          summaryPanel?.classList.add("hidden");
        }
        return;
      }
      const data = await response.json();
      updateSummary(data);
    } catch (error) {
      console.warn("Failed to load summary", error);
    }
  }

  function updateSummary(data) {
    const usersEl = document.getElementById("summary-users");
    const componentsEl = document.getElementById("summary-components");
    const telemetryEl = document.getElementById("summary-telemetry");
    const alertsEl = document.getElementById("summary-alerts");
    if (usersEl) usersEl.textContent = Number(data.users ?? 0).toLocaleString();
    if (componentsEl) componentsEl.textContent = Number(data.components ?? 0).toLocaleString();
    if (telemetryEl) telemetryEl.textContent = Number(data.telemetry_records ?? 0).toLocaleString();
    if (alertsEl) alertsEl.textContent = Number(data.alerts ?? 0).toLocaleString();
    if (!recentAlertsList) return;
    recentAlertsList.innerHTML = "";
    const recent = Array.isArray(data.recent_alerts) ? data.recent_alerts : [];
    recent.forEach((event) => {
      const li = document.createElement("li");
      const severity = (event.severity || "info").toUpperCase();
      li.textContent = `${CyberGrid.util.formatTime(event.created_at)} – [${severity}] ${event.details || ""}`;
      recentAlertsList.appendChild(li);
    });
  }

  if (loginForm) {
    loginForm.addEventListener("submit", handleLogin);
  }

  window.addEventListener("beforeunload", stopSummaryPolling);

  initialize();
})();
