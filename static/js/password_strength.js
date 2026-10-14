/**
 * Guardly passphrase guidance & real-time strength evaluation.
 *
 * This mirrors the server policy: use a memorable long passphrase rather than
 * forcing arbitrary character substitutions. The server remains authoritative.
 */
document.addEventListener("DOMContentLoaded", () => {
    const inputs = document.querySelectorAll(".guardly-password-input, #new_password, #accNewPassword");
    if (!inputs.length) return;

    const commonPasswords = new Set([
        "password123", "password", "qwerty123", "admin123", "pass1234",
        "welcome123", "letmein123", "monkey123", "12345678", "123456789",
        "abc12345", "password1", "p@ssword1", "admin1234", "phishguard1", "guardly123"
    ]);

    const identityValues = () => [
        document.querySelector("#username, input[name='username']")?.value,
        document.querySelector("#email, input[name='email']")?.value
    ].filter(Boolean).map(value => value.trim().toLocaleLowerCase());

    inputs.forEach(input => {
        // Find parent form-group
        const formGroup = input.closest(".mb-3, .mb-4, .form-group, .card-body") || input.parentElement;
        
        // Find or create a dedicated container OUTSIDE of any .position-relative input wrapper
        let container = formGroup?.querySelector("#password-strength-container")
            || input.closest(".password-field-container")?.querySelector("#password-strength-container");

        if (!container) {
            // Find the immediate input wrapper (e.g. .position-relative)
            const inputWrapper = input.closest(".position-relative") || input;
            container = document.createElement("div");
            container.id = "password-strength-container";
            container.className = "mt-2";
            inputWrapper.insertAdjacentElement("afterend", container);
        }

        // Avoid duplicate initialization
        if (container.querySelector(".password-strength-widget")) return;

        const widget = document.createElement("section");
        widget.className = "password-strength-widget";
        widget.setAttribute("aria-live", "polite");
        widget.style.cssText = "margin-top: 0.65rem; padding: 0.75rem 0.9rem; background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 12px; backdrop-filter: blur(8px); display: block;";

        widget.innerHTML = `
            <div class="password-strength-heading" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; font-size: 0.75rem; color: #94a3b8; font-weight: 600;">
                <span style="text-transform: uppercase; letter-spacing: 0.06em; font-size: 0.7rem;">Passphrase strength</span>
                <strong class="strength-label" style="font-size: 0.75rem; font-weight: 700; padding: 0.15rem 0.55rem; border-radius: 6px; background: rgba(148, 163, 184, 0.15); color: #94a3b8; display: inline-block;">Add a passphrase</strong>
            </div>
            <div class="password-strength-track" aria-hidden="true" style="height: 6px; width: 100%; background: rgba(255, 255, 255, 0.1); border-radius: 9999px; overflow: hidden; margin-bottom: 0.65rem;">
                <span class="strength-bar" style="display: block; height: 100%; width: 0%; border-radius: 9999px; transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1), background 0.3s ease;"></span>
            </div>
            <div class="password-checklist" style="display: flex; flex-direction: column; gap: 0.35rem;">
                <span class="password-rule rule-length" style="display: inline-flex; align-items: center; gap: 0.45rem; font-size: 0.75rem; color: #64748b;"><i class="bi bi-circle" aria-hidden="true"></i><span>12 or more characters</span></span>
                <span class="password-rule rule-unique" style="display: inline-flex; align-items: center; gap: 0.45rem; font-size: 0.75rem; color: #64748b;"><i class="bi bi-circle" aria-hidden="true"></i><span>Not a common password</span></span>
                <span class="password-rule rule-safe" style="display: inline-flex; align-items: center; gap: 0.45rem; font-size: 0.75rem; color: #64748b;"><i class="bi bi-circle" aria-hidden="true"></i><span>No control characters</span></span>
            </div>`;
        container.appendChild(widget);

        const label = widget.querySelector(".strength-label");
        const bar = widget.querySelector(".strength-bar");
        const ruleLength = widget.querySelector(".rule-length");
        const ruleUnique = widget.querySelector(".rule-unique");
        const ruleSafe = widget.querySelector(".rule-safe");

        const setRule = (element, valid, text) => {
            if (!element) return;
            element.className = `password-rule ${valid ? "is-valid" : ""}`;
            element.style.color = valid ? "#86efac" : "#64748b";
            const icon = element.querySelector("i");
            if (icon) {
                icon.className = `bi ${valid ? "bi-check-circle-fill" : "bi-circle"}`;
                icon.style.color = valid ? "#22c55e" : "#64748b";
            }
            const span = element.querySelector("span");
            if (span) {
                span.textContent = text;
            }
        };

        const evaluate = password => {
            const normalized = password.trim().toLocaleLowerCase();
            const hasLength = password.length >= 12 && password.length <= 128;
            const hasNoControlCharacters = !/[\x00-\x1F\x7F]/.test(password);
            const isContextual = identityValues().includes(normalized);
            const isUnique = Boolean(password) && !commonPasswords.has(normalized) && !isContextual;

            setRule(ruleLength, hasLength, "12 or more characters");
            setRule(ruleUnique, isUnique, isContextual ? "Does not match your account details" : "Not a common password");
            setRule(ruleSafe, hasNoControlCharacters, "No control characters");

            if (!password) {
                label.textContent = "Add a passphrase";
                label.className = "strength-label";
                label.style.background = "rgba(148, 163, 184, 0.15)";
                label.style.color = "#94a3b8";
                label.style.border = "none";
                bar.style.width = "0%";
                bar.style.background = "transparent";
                bar.dataset.tone = "neutral";
                return;
            }

            const categories = [/[a-z]/, /[A-Z]/, /\d/, /[^\w\s]/, /\s/]
                .filter(pattern => pattern.test(password)).length;
            const score = Math.min(100, password.length * 3 + categories * 7 + Math.min(20, new Set(password).size));
            const valid = hasLength && hasNoControlCharacters && isUnique;
            let tone = "danger";
            let text = "Needs attention";
            let width = "28%";
            let bg = "linear-gradient(90deg, #ef4444, #f87171)";
            let lblBg = "rgba(239, 68, 68, 0.18)";
            let lblColor = "#fca5a5";
            let lblBorder = "1px solid rgba(239, 68, 68, 0.35)";

            if (valid && (password.length >= 20 || score >= 82)) {
                tone = "success"; text = "Excellent"; width = "100%";
                bg = "linear-gradient(90deg, #16a34a, #4ade80)";
                lblBg = "rgba(34, 197, 94, 0.18)";
                lblColor = "#86efac";
                lblBorder = "1px solid rgba(34, 197, 94, 0.35)";
            } else if (valid && (password.length >= 16 || score >= 65)) {
                tone = "info"; text = "Strong"; width = "75%";
                bg = "linear-gradient(90deg, #0284c7, #38bdf8)";
                lblBg = "rgba(56, 189, 248, 0.18)";
                lblColor = "#7dd3fc";
                lblBorder = "1px solid rgba(56, 189, 248, 0.35)";
            } else if (valid) {
                tone = "warning"; text = "Good"; width = "52%";
                bg = "linear-gradient(90deg, #f59e0b, #fbbf24)";
                lblBg = "rgba(245, 158, 11, 0.18)";
                lblColor = "#fde047";
                lblBorder = "1px solid rgba(245, 158, 11, 0.35)";
            }

            label.textContent = text;
            label.className = `strength-label is-${tone}`;
            label.style.background = lblBg;
            label.style.color = lblColor;
            label.style.border = lblBorder;
            bar.style.width = width;
            bar.style.background = bg;
            bar.dataset.tone = tone;
        };

        input.addEventListener("input", () => evaluate(input.value));
        if (input.value) evaluate(input.value);
    });
});
