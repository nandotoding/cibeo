
/* ========================================
   CIBEO - GLOBAL JAVASCRIPT
======================================== */

document.addEventListener("DOMContentLoaded", () => {

    // 1. Confirmation before executing actions
    document.querySelectorAll("[data-confirm]").forEach((element) => {
        element.addEventListener("click", (event) => {
            const message = element.dataset.confirm || "Are you sure?";

            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });


    // 2. Dismissible alerts
    document.querySelectorAll("[data-dismiss]").forEach((element) => {
        element.addEventListener("click", () => {
            const alert = element.closest(".alert");

            if (alert) {
                alert.remove();
            }
        });
    });


    // 3. Automatically dismiss alerts
    document.querySelectorAll(".alert[data-auto-dismiss]").forEach((alert) => {
        const duration = Number(alert.dataset.autoDismiss) || 5000;

        window.setTimeout(() => {
            alert.remove();
        }, duration);
    });


    // 4. Password visibility toggle
    document.querySelectorAll("[data-toggle-password]").forEach((button) => {
        button.addEventListener("click", () => {
            const inputId = button.dataset.togglePassword;
            const input = document.getElementById(inputId);

            if (!input) return;

            const isPassword = input.type === "password";

            input.type = isPassword ? "text" : "password";
            button.textContent = isPassword ? "Hide" : "Show";
            button.setAttribute(
                "aria-label",
                isPassword ? "Hide password" : "Show password"
            );
        });
    });


    // 5. Theme toggle
    const themeToggleButtons = document.querySelectorAll("[data-theme-toggle]");

    function updateThemeToggle(theme) {
        const isDark = theme === "dark";

        themeToggleButtons.forEach((button) => {
            const icon = button.querySelector("[data-theme-icon]");
            const label = button.querySelector("[data-theme-label]");

            const nextThemeLabel = isDark ? "Light Mode" : "Dark Mode";

            if (icon) {
                icon.textContent = isDark ? "☀" : "☾";
            }

            if (label) {
                label.textContent = nextThemeLabel;
            }

            button.setAttribute(
                "aria-label",
                `Switch to ${nextThemeLabel}`
            );

            button.setAttribute(
                "title",
                `Switch to ${nextThemeLabel}`
            );
        });
    }

        // 6. Mobile sidebar toggle
    const sidebar = document.getElementById("sidebar");
    const sidebarToggle = document.querySelector("[data-sidebar-toggle]");
    const sidebarBackdrop = document.querySelector("[data-sidebar-backdrop]");

    if (sidebar && sidebarToggle && sidebarBackdrop) {
        function closeSidebar() {
            sidebar.classList.remove("is-open");
            sidebarBackdrop.classList.remove("is-visible");
            sidebarToggle.setAttribute("aria-expanded", "false");
            document.body.style.overflow = "";
        }

        function openSidebar() {
            sidebar.classList.add("is-open");
            sidebarBackdrop.classList.add("is-visible");
            sidebarToggle.setAttribute("aria-expanded", "true");
            document.body.style.overflow = "hidden";
        }

        sidebarToggle.addEventListener("click", () => {
            const isOpen = sidebar.classList.contains("is-open");

            if (isOpen) {
                closeSidebar();
            } else {
                openSidebar();
            }
        });

        sidebarBackdrop.addEventListener("click", closeSidebar);

        sidebar.querySelectorAll(".nav-link").forEach((link) => {
            link.addEventListener("click", closeSidebar);
        });

        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape") {
                closeSidebar();
            }
        });

        window.addEventListener("resize", () => {
            if (window.innerWidth > 600) {
                closeSidebar();
            }
        });
    }

    function applyTheme(theme) {
        const selectedTheme = theme === "light" ? "light" : "dark";

        document.documentElement.dataset.theme = selectedTheme;

        try {
            localStorage.setItem("cibeo-theme", selectedTheme);
        } catch (error) {
            console.warn("Unable to save theme preference.");
        }

        updateThemeToggle(selectedTheme);

        if (typeof window.CibeoUpdateChartTheme === "function") {
            window.CibeoUpdateChartTheme();
        }
    }

    updateThemeToggle(
        document.documentElement.dataset.theme || "dark"
    );

    themeToggleButtons.forEach((button) => {
        button.addEventListener("click", () => {
            const currentTheme = document.documentElement.dataset.theme;
            const nextTheme = currentTheme === "dark" ? "light" : "dark";

            applyTheme(nextTheme);
        });
    });

});


/* ========================================
   CIBEO - GLOBAL UTILITIES
======================================== */

window.Cibeo = {

    // Format number as Indonesian Rupiah
    formatRupiah(amount) {
        return new Intl.NumberFormat("id-ID", {
            style: "currency",
            currency: "IDR",
            minimumFractionDigits: 0,
            maximumFractionDigits: 0
        }).format(amount);
    },

    // General confirmation dialog
    confirmAction(message) {
        return window.confirm(message || "Are you sure?");
    }

};

