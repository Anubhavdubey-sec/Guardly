/**
 * Guardly passphrase guidance.
 *
 * This mirrors the server policy: use a memorable long passphrase rather than
 * forcing arbitrary character substitutions. The server remains authoritative.
 */
document.addEventListener("DOMContentLoaded", () => {
    const inputs = document.querySelectorAll(".guardly-password-input, #new_password");
    if (!inputs.length) return;

    const commonPasswords = new Set([
        "password123", "password", "qwerty123", "admin123", "pass1234",
        "welcome123", "letmein123", "monkey123", "12345678", "123456789",
        "abc12345", "password1", "p@ssword1", "admin1234", "phishguard1", "guardly123"
    ]);

    const setRule = (element, valid, text) => {
        if (!element) return;
        element.className = `password-rule ${valid ? "is-valid" : ""}`;
        element.innerHTML = `<i class="bi ${valid ? "bi-check-circle-fill" : "bi-circle"}" aria-hidden="true"></i>${text}`;
    };

    const identityValues = () => [
        document.querySelector("#username, input[name='username']")?.value,
        document.querySelector("#email, input[name='email']")?.value
    ].filter(Boolean).map(value => value.trim().toLocaleLowerCase());

    inputs.forEach(input => {
        const container = input.closest(".password-field-container") || input.parentElement;
        if (container.querySelector(".password-strength-widget")) return;

        const widget = document.createElement("section");
        widget.className = "password-strength-widget";
        widget.setAttribute("aria-live", "polite");
        widget.innerHTML = `
            <div class="password-strength-heading"><span>Passphrase strength</span><strong class="strength-label">Add a passphrase</strong></div>
            <div class="password-strength-track" aria-hidden="true"><span class="strength-bar"></span></div>
            <div class="password-checklist">
                <span class="password-rule rule-length"><i class="bi bi-circle" aria-hidden="true"></i>12 or more characters</span>
                <span class="password-rule rule-unique"><i class="bi bi-circle" aria-hidden="true"></i>Not a common password</span>
                <span class="password-rule rule-safe"><i class="bi bi-circle" aria-hidden="true"></i>No control characters</span>
            </div>`;
        container.appendChild(widget);

        const label = widget.querySelector(".strength-label");
        const bar = widget.querySelector(".strength-bar");
        const ruleLength = widget.querySelector(".rule-length");
        const ruleUnique = widget.querySelector(".rule-unique");
        const ruleSafe = widget.querySelector(".rule-safe");

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
                bar.style.width = "0%";
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
            if (valid && (password.length >= 20 || score >= 82)) {
                tone = "success"; text = "Excellent"; width = "100%";
            } else if (valid && (password.length >= 16 || score >= 65)) {
                tone = "info"; text = "Strong"; width = "75%";
            } else if (valid) {
                tone = "warning"; text = "Good"; width = "52%";
            }
            label.textContent = text;
            label.className = `strength-label is-${tone}`;
            bar.style.width = width;
            bar.dataset.tone = tone;
        };

        input.addEventListener("input", () => evaluate(input.value));
        if (input.value) evaluate(input.value);
    });
});
