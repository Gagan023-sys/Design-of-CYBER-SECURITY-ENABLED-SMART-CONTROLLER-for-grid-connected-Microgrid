(function () {
  const STORAGE_KEY = "cybergrid:auth";
  const NAV_LINKS = [
    { id: "overview", label: "Overview", href: "index.html" },
    { id: "telemetry", label: "Telemetry", href: "telemetry.html" },
    { id: "security", label: "Security Ops", href: "security.html" },
    { id: "admin", label: "User Admin", href: "admin.html", roles: ["admin"] },
  ];

  function readAuth() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (error) {
      console.warn("Failed to parse auth storage", error);
      return null;
    }
  }

  function writeAuth(auth) {
    if (!auth || (!auth.accessToken && !auth.refreshToken)) {
      localStorage.removeItem(STORAGE_KEY);
      return;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(auth));
  }

  function clearAuth() {
    localStorage.removeItem(STORAGE_KEY);
  }

  function saveTokens(tokens) {
    const auth = readAuth() || {};
    auth.accessToken = tokens.accessToken;
    auth.refreshToken = tokens.refreshToken;
    writeAuth(auth);
  }

  function setUser(user) {
    const auth = readAuth() || {};
    auth.user = user;
    writeAuth(auth);
  }

  function getUser() {
    const auth = readAuth();
    return auth && auth.user ? auth.user : null;
  }

  function redirectToLogin() {
    window.location.replace("index.html");
  }

  async function apiFetch(path, options = {}) {
    const { skipAuthRedirect = false, ...fetchOptions } = options;
    const auth = readAuth();
    fetchOptions.headers = new Headers(fetchOptions.headers || {});
    if (auth && auth.accessToken) {
      fetchOptions.headers.set("Authorization", `Bearer ${auth.accessToken}`);
    }
    if (
      fetchOptions.body &&
      typeof fetchOptions.body !== "string" &&
      !(fetchOptions.body instanceof FormData)
    ) {
      fetchOptions.headers.set("Content-Type", "application/json");
      fetchOptions.body = JSON.stringify(fetchOptions.body);
    }
    const response = await fetch(path, fetchOptions);
    if (response.status === 401) {
      clearAuth();
      if (!skipAuthRedirect) {
        redirectToLogin();
      }
      throw new Error("Unauthorized");
    }
    return response;
  }

  async function fetchProfile() {
    const response = await apiFetch("/auth/me");
    const user = await response.json();
    setUser(user);
    return user;
  }

  async function ensureAuth(options = {}) {
    const { redirect = true, requiredRoles = [] } = options;
    const auth = readAuth();
    if (!auth || !auth.accessToken) {
      if (redirect) {
        redirectToLogin();
      }
      throw new Error("Not authenticated");
    }
    let user = auth.user;
    try {
      if (!user) {
        user = await fetchProfile();
      }
    } catch (error) {
      if (redirect) {
        redirectToLogin();
      }
      throw error;
    }
    if (requiredRoles.length && (!user || !requiredRoles.includes(user.role))) {
      if (redirect) {
        redirectToLogin();
      }
      throw new Error("Insufficient role");
    }
    return user;
  }

  function renderNav(activeId) {
    const nav = document.getElementById("primary-nav");
    if (!nav) return;
    const auth = readAuth();
    const user = auth ? auth.user : null;
    if (!user) {
      nav.innerHTML = "";
      nav.classList.add("hidden");
      return;
    }
    nav.classList.remove("hidden");
    nav.innerHTML = "";
    NAV_LINKS.forEach((link) => {
      if (link.roles && (!user || !link.roles.includes(user.role))) {
        return;
      }
      const anchor = document.createElement("a");
      anchor.href = link.href;
      anchor.textContent = link.label;
      if (link.id === activeId) {
        anchor.classList.add("active");
      }
      nav.appendChild(anchor);
    });
  }

  function updateUserBanner(user) {
    const nameEl = document.getElementById("current-user-name");
    const roleEl = document.getElementById("current-user-role");
    if (nameEl) {
      nameEl.textContent = user ? user.username : "";
    }
    if (roleEl) {
      roleEl.textContent = user ? user.role : "";
      roleEl.className = "role-badge";
      if (user && user.role) {
        roleEl.classList.add(`role-${user.role}`);
      }
    }
  }

  function attachSignOut(button) {
    if (!button) return;
    button.addEventListener("click", () => {
      clearAuth();
      redirectToLogin();
    });
  }

  function formatNumber(value, digits = 1) {
    const num = Number(value);
    if (!Number.isFinite(num)) return "—";
    return num.toFixed(digits);
  }

  function formatTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return date.toLocaleTimeString();
  }

  window.CyberGrid = {
    auth: {
      read: readAuth,
      saveTokens: saveTokens,
      setUser: setUser,
      getUser: getUser,
      clear: clearAuth,
      ensure: ensureAuth,
      fetchProfile: fetchProfile,
      redirectToLogin,
    },
    apiFetch,
    ui: {
      renderNav,
      updateUserBanner,
      attachSignOut,
    },
    util: {
      formatNumber,
      formatTime,
    },
  };
})();
