
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

