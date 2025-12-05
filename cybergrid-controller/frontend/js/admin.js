(function () {
  const sessionPanel = document.getElementById("session-panel");
  const userPanel = document.getElementById("user-admin-panel");
  const logoutBtn = document.getElementById("logout-btn");
  const createForm = document.getElementById("user-create-form");
  const userTableBody = document.getElementById("user-table-body");
  const newRoleSelect = document.getElementById("new-role");
  const messageArea = document.getElementById("message-area");

  let pollHandle = null;
  let messageTimer = null;
  let availableRoles = [];

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
      const user = await CyberGrid.auth.ensure({ requiredRoles: ["admin"] });
      CyberGrid.ui.updateUserBanner(user);
      CyberGrid.ui.renderNav("admin");
      CyberGrid.ui.attachSignOut(logoutBtn);
      if (sessionPanel) sessionPanel.classList.remove("hidden");
      if (userPanel) userPanel.classList.remove("hidden");
      if (createForm) createForm.addEventListener("submit", handleCreateUser);
      if (userTableBody) userTableBody.addEventListener("change", handleRoleChange);
      if (userTableBody) userTableBody.addEventListener("click", handleStatusToggle);
      startPolling();
    } catch (error) {
      console.error("Admin page init failed", error);
      setMessage("Administrator privileges are required to access this page.", "error", 8000);
      setTimeout(() => CyberGrid.auth.redirectToLogin(), 2000);
    }
  }

  function startPolling() {
    stopPolling();
    refreshUsers();
    pollHandle = setInterval(refreshUsers, 25000);
  }

  function stopPolling() {
    if (pollHandle) {
      clearInterval(pollHandle);
      pollHandle = null;
    }
  }

  async function refreshUsers() {
    try {
      const response = await CyberGrid.apiFetch("/admin/users");
      if (!response.ok) {
        console.warn("Failed to fetch user list", response.statusText);
        return;
      }
      const data = await response.json();
      const users = Array.isArray(data.items) ? data.items : [];
      availableRoles = Array.isArray(data.roles) ? data.roles : [];
      renderRoleOptions(newRoleSelect, availableRoles, true);
      renderUsers(users);
    } catch (error) {
      console.warn("User refresh error", error);
    }
  }

  function renderUsers(users) {
    if (!userTableBody) return;
    userTableBody.innerHTML = "";
    const fragment = document.createDocumentFragment();
    users.forEach((user) => {
      const row = document.createElement("tr");
      createCell(row, user.username, "column-username");
      const roleCell = document.createElement("td");
      const roleSelect = document.createElement("select");
      roleSelect.className = "role-select";
      roleSelect.dataset.username = user.username;
      renderRoleOptions(roleSelect, availableRoles, false);
      roleSelect.value = user.role;
      if (CyberGrid.auth.getUser()?.username === user.username) {
        roleSelect.disabled = true;
        roleSelect.title = "You cannot modify your own role.";
      }
      roleCell.appendChild(roleSelect);
      row.appendChild(roleCell);
      const statusCell = createCell(row, user.is_active ? "Active" : "Disabled", "column-status");
      statusCell.classList.toggle("status-active", user.is_active);
      statusCell.classList.toggle("status-disabled", !user.is_active);
      const actionsCell = document.createElement("td");
      const toggleButton = document.createElement("button");
      toggleButton.type = "button";
      toggleButton.className = "secondary user-status-toggle";
      toggleButton.dataset.username = user.username;
      toggleButton.dataset.nextState = user.is_active ? "false" : "true";
      toggleButton.textContent = user.is_active ? "Deactivate" : "Activate";
      if (CyberGrid.auth.getUser()?.username === user.username) {
        toggleButton.disabled = true;
        toggleButton.title = "You cannot deactivate your own account.";
      }
      actionsCell.appendChild(toggleButton);
      row.appendChild(actionsCell);
      fragment.appendChild(row);
    });
    userTableBody.appendChild(fragment);
  }

  function renderRoleOptions(select, roles, includePlaceholder) {
    if (!select) return;
    const previousValue = select.value;
    select.innerHTML = "";
    if (includePlaceholder) {
      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = "Select role";
      placeholder.disabled = true;
      placeholder.selected = true;
      select.appendChild(placeholder);
    }
    roles.forEach((role) => {
      const option = document.createElement("option");
      option.value = role;
      option.textContent = role.charAt(0).toUpperCase() + role.slice(1);
      select.appendChild(option);
    });
    if (!includePlaceholder && roles.includes(previousValue)) {
      select.value = previousValue;
    }
  }

  async function handleCreateUser(event) {
    event.preventDefault();
    const username = document.getElementById("new-username").value.trim();
    const password = document.getElementById("new-password").value;
    const role = newRoleSelect.value;
    if (!username || !password || !role) {
      setMessage("Provide username, password, and role.", "error");
      return;
    }
    try {
      const response = await CyberGrid.apiFetch("/admin/users", {
        method: "POST",
        body: { username, password, role },
      });
      const data = await response.json();
      if (!response.ok) {
        setMessage(data.detail || "Unable to create user.", "error");
        return;
      }
      createForm.reset();
      renderRoleOptions(newRoleSelect, availableRoles, true);
      setMessage(`User ${data.username} created with role ${data.role}.`, "success");
      refreshUsers();
    } catch (error) {
      console.error("User creation failed", error);
      setMessage("Unable to create user right now.", "error");
    }
  }

  async function handleRoleChange(event) {
    const select = event.target;
    if (select.tagName !== "SELECT" || !select.dataset.username) return;
    const username = select.dataset.username;
    const newRole = select.value;
    try {
      const response = await CyberGrid.apiFetch(`/admin/users/${encodeURIComponent(username)}`, {
        method: "PATCH",
        body: { role: newRole },
      });
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        setMessage(detail.detail || "Unable to update role.", "error");
        refreshUsers();
        return;
      }
      setMessage(`Updated role for ${username} to ${newRole}.`, "success");
      refreshUsers();
    } catch (error) {
      console.error("Role update failed", error);
      setMessage("Unable to update role.", "error");
    }
  }

  async function handleStatusToggle(event) {
    const target = event.target;
    if (!target.classList.contains("user-status-toggle")) return;
    const username = target.dataset.username;
    const nextState = target.dataset.nextState === "true";
    try {
      const response = await CyberGrid.apiFetch(`/admin/users/${encodeURIComponent(username)}`, {
        method: "PATCH",
        body: { is_active: nextState },
      });
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        setMessage(detail.detail || "Unable to update status.", "error");
        refreshUsers();
        return;
      }
      setMessage(`Account ${username} ${nextState ? "activated" : "deactivated"}.`, "success");
      refreshUsers();
    } catch (error) {
      console.error("Status update failed", error);
      setMessage("Unable to update user status.", "error");
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
