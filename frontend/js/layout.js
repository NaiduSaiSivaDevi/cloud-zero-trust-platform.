const NAV_ITEMS = [
  {
    href: "dashboard.html",
    label: "Dashboard",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>`,
  },
  {
    href: "providers.html",
    label: "Cloud Providers",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17.5 19H9a5 5 0 0 1-.5-9.98A6 6 0 0 1 20 11a4 4 0 0 1-2.5 8Z"/></svg>`,
  },
  {
    href: "scanner.html",
    label: "Config Scanner",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>`,
  },
  {
    href: "findings.html",
    label: "Security Findings",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/></svg>`,
  },
  {
    href: "policies.html",
    label: "Zero Trust Engine",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/></svg>`,
  },
  {
    href: "optimization.html",
    label: "Policy Optimization",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c.26.604.852.997 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/></svg>`,
  },
  {
    href: "monitoring.html",
    label: "Monitoring",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-7 4 14 3-7h4"/></svg>`,
  },
  {
    href: "logs.html",
    label: "Log Analysis",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h6"/></svg>`,
  },
  {
    href: "reports.html",
    label: "Reports",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/></svg>`,
  },
  {
    href: "users.html",
    label: "User Management",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  },
];

function getPreferredTheme() {
  const saved = localStorage.getItem("cg_theme");
  if (saved === "light" || saved === "dark") return saved;
  const currentFile = window.location.pathname.split("/").pop() || "dashboard.html";
  return currentFile === "dashboard.html" ? "dark" : "light";
}

function applyTheme(theme) {
  const isDark = theme === "dark";
  document.body.classList.toggle("theme-dark", isDark);
  document.body.classList.toggle("theme-light", !isDark);
  const btn = document.getElementById("theme-toggle-btn");
  if (btn) {
    btn.setAttribute("aria-pressed", String(isDark));
    btn.innerHTML = isDark
      ? `<span aria-hidden="true">&#9728;</span><span>Light Mode</span>`
      : `<span aria-hidden="true">&#9790;</span><span>Dark Mode</span>`;
  }
}

function initLayout(pageTitle, breadcrumbText) {
  if (!requireAuth()) return false;

  const currentTheme = getPreferredTheme();
  applyTheme(currentTheme);

  const user = getCurrentUser() || { email: "unknown", role: "analyst" };
  const currentFile = window.location.pathname.split("/").pop() || "dashboard.html";

  const sidebar = document.getElementById("app-sidebar");
  let backdrop = document.getElementById("sidebar-backdrop");

  if (sidebar) {
    sidebar.setAttribute("aria-label", "Primary navigation");
    sidebar.innerHTML = `
      <div class="sidebar-brand">
        <div class="brand-icon">CG</div>
        <div class="brand-text">
          <span class="brand-title">CloudGuard ZT</span>
          <span class="brand-subtitle">Zero Trust Platform</span>
        </div>
      </div>
      <nav class="sidebar-nav">
        ${NAV_ITEMS.map((item) => {
          const isActive = currentFile === item.href;
          return `
          <a href="${item.href}"
             class="nav-item ${isActive ? "active" : ""}"
             ${isActive ? 'aria-current="page"' : ""}>
            <span class="nav-icon" aria-hidden="true">${item.icon}</span>
            <span class="nav-label">${escapeHtml(item.label)}</span>
          </a>
        `;
        }).join("")}
      </nav>
      <div class="sidebar-footer">
        <div class="sidebar-footer-title">CloudGuard Zero Trust</div>
        <div class="sidebar-footer-status">
          <span class="status-dot" aria-hidden="true"></span>
          <span>Policy Engine · Active</span>
        </div>
      </div>
    `;

    if (!backdrop) {
      backdrop = document.createElement("div");
      backdrop.id = "sidebar-backdrop";
      backdrop.className = "sidebar-backdrop";
      sidebar.parentNode.insertBefore(backdrop, sidebar.nextSibling);
    }

    const closeMobileSidebar = () => {
      sidebar.classList.remove("mobile-open");
      backdrop.classList.remove("visible");
    };

    backdrop.addEventListener("click", closeMobileSidebar);

    sidebar.querySelectorAll(".nav-item").forEach((link) => {
      link.addEventListener("click", () => {
        if (window.innerWidth <= 768) {
          closeMobileSidebar();
        }
      });
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && sidebar.classList.contains("mobile-open")) {
        closeMobileSidebar();
      }
    });
  }

  const topbar = document.getElementById("app-topbar");
  if (topbar) {
    topbar.innerHTML = `
      <div class="topbar-left">
        <button class="mobile-menu-btn" id="mobile-menu-toggle" type="button" aria-label="Toggle navigation menu">&#9776;</button>
        <div>
          <div class="page-heading">${escapeHtml(pageTitle)}</div>
          <div class="breadcrumb">CloudGuard / ${escapeHtml(breadcrumbText || pageTitle)}</div>
        </div>
      </div>
      <div class="topbar-right">
        <button class="btn btn-secondary btn-sm theme-toggle-btn" id="theme-toggle-btn" type="button" aria-label="Toggle color theme"></button>
        <span class="pill pill-demo">DEMO MODE</span>
        <div class="user-chip">
          <span>${escapeHtml(user.email)}</span>
          <span class="pill pill-info">${escapeHtml(user.role)}</span>
        </div>
        <button class="btn btn-secondary btn-sm" id="logout-btn" type="button">Sign out</button>
      </div>
    `;

    applyTheme(getPreferredTheme());
    const themeBtn = document.getElementById("theme-toggle-btn");
    if (themeBtn) {
      themeBtn.addEventListener("click", () => {
        const nextTheme = document.body.classList.contains("theme-dark") ? "light" : "dark";
        localStorage.setItem("cg_theme", nextTheme);
        applyTheme(nextTheme);
        window.dispatchEvent(new CustomEvent("cg-theme-change", { detail: { theme: nextTheme } }));
      });
    }

    const logoutBtn = document.getElementById("logout-btn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", () => {
        clearSession();
        window.location.replace("login.html");
      });
    }

    const toggleBtn = document.getElementById("mobile-menu-toggle");
    if (toggleBtn && sidebar) {
      toggleBtn.addEventListener("click", () => {
        const isOpen = sidebar.classList.toggle("mobile-open");
        if (backdrop) {
          backdrop.classList.toggle("visible", isOpen);
        }
      });
    }
  }
  return true;
}

function showBanner(containerId, message, type = "info") {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `<div class="banner banner-${type}">${escapeHtml(message)}</div>`;
}
