/**
 * Guardly Password Strength & Strict Security Checklist JS Engine
 * Real-time frontend validation, entropy estimation, and visual feedback widget.
 */
document.addEventListener("DOMContentLoaded", function () {
    const passwordInputs = document.querySelectorAll(".guardly-password-input, #password, #new_password");
    if (!passwordInputs.length) return;

    passwordInputs.forEach(input => {
        const container = input.closest(".password-field-container") || input.parentElement;
        
        // Inject Live Strength Meter & Checklist UI if not already present
        let widget = container.querySelector(".password-strength-widget");
        if (!widget) {
            widget = document.createElement("div");
            widget.className = "password-strength-widget mt-2 font-mono small";
            widget.innerHTML = `
                <div class="d-flex align-items-center justify-content-between mb-1">
                    <span class="text-muted small">PASSWORD STRENGTH:</span>
                    <strong class="strength-label text-danger small">Weak</strong>
                </div>
                <div class="progress mb-2" style="height: 6px; background-color: rgba(255,255,255,0.1);">
                    <div class="strength-bar progress-bar bg-danger transition-all" style="width: 15%;"></div>
                </div>
                <div class="password-checklist row g-1 text-muted small">
                    <div class="col-6 rule-length"><i class="bi bi-x-circle text-danger me-1"></i> 8–12 Characters</div>
                    <div class="col-6 rule-upper"><i class="bi bi-x-circle text-danger me-1"></i> Uppercase (A-Z)</div>
                    <div class="col-6 rule-lower"><i class="bi bi-x-circle text-danger me-1"></i> Lowercase (a-z)</div>
                    <div class="col-6 rule-digit"><i class="bi bi-x-circle text-danger me-1"></i> Number (0-9)</div>
                    <div class="col-6 rule-special"><i class="bi bi-x-circle text-danger me-1"></i> Special (!@#$...)</div>
                    <div class="col-6 rule-space"><i class="bi bi-check-circle text-success me-1"></i> No Spaces</div>
                </div>
            `;
            container.appendChild(widget);
        }

        const label = widget.querySelector(".strength-label");
        const bar = widget.querySelector(".strength-bar");
        const ruleLength = widget.querySelector(".rule-length");
        const ruleUpper = widget.querySelector(".rule-upper");
        const ruleLower = widget.querySelector(".rule-lower");
        const ruleDigit = widget.querySelector(".rule-digit");
        const ruleSpecial = widget.querySelector(".rule-special");
        const ruleSpace = widget.querySelector(".rule-space");

        function updateRule(elem, isValid, text) {
            if (!elem) return;
            const icon = isValid ? 'bi-check-circle text-success' : 'bi-x-circle text-danger';
            const colorClass = isValid ? 'text-success' : 'text-muted';
            elem.className = `${elem.className.split(' ')[0]} col-6 ${colorClass}`;
            elem.innerHTML = `<i class="bi ${icon} me-1"></i> ${text}`;
        }

        function evaluatePassword(pwd) {
            const usernameInput = document.querySelector("#username, input[name='username']");
            const emailInput = document.querySelector("#email, input[name='email']");
            const username = usernameInput ? usernameInput.value.trim().toLowerCase() : "";
            const email = emailInput ? emailInput.value.trim().toLowerCase() : "";

            const hasLength = pwd.length >= 8 && pwd.length <= 12;
            const hasUpper = /[A-Z]/.test(pwd);
            const hasLower = /[a-z]/.test(pwd);
            const hasDigit = /[0-9]/.test(pwd);
            const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~]/.test(pwd);
            const hasNoSpace = pwd.length > 0 && !/\s/.test(pwd);

            updateRule(ruleLength, hasLength, "8–12 Characters");
            updateRule(ruleUpper, hasUpper, "Uppercase (A-Z)");
            updateRule(ruleLower, hasLower, "Lowercase (a-z)");
            updateRule(ruleDigit, hasDigit, "Number (0-9)");
            updateRule(ruleSpecial, hasSpecial, "Special (!@#$...)");
            updateRule(ruleSpace, hasNoSpace, "No Spaces");

            if (!pwd) {
                label.textContent = "Weak";
                label.className = "strength-label text-muted small";
                bar.style.width = "0%";
                bar.className = "strength-bar progress-bar bg-secondary";
                return;
            }

            const pwdLower = pwd.lower ? pwd.lower() : pwd.toLowerCase();
            const isCommon = ["password123", "password", "qwerty123", "admin123", "pass1234", "welcome123"].includes(pwdLower);
            const isIdentity = (username && pwdLower === username) || (email && pwdLower === email);

            let pool = 0;
            if (hasLower) pool += 26;
            if (hasUpper) pool += 26;
            if (hasDigit) pool += 10;
            if (hasSpecial) pool += 32;

            const entropy = pwd.length * (pool > 0 ? Math.log2(pool) : 0);
            const validRulesCount = [hasLength, hasUpper, hasLower, hasDigit, hasSpecial, hasNoSpace].filter(Boolean).length;

            if (isCommon || isIdentity || !hasLength || validRulesCount < 4 || entropy < 38) {
                label.textContent = "Weak";
                label.className = "strength-label text-danger small";
                bar.style.width = "25%";
                bar.className = "strength-bar progress-bar bg-danger";
            } else if (validRulesCount < 5 || entropy < 48) {
                label.textContent = "Medium";
                label.className = "strength-label text-warning small";
                bar.style.width = "50%";
                bar.className = "strength-bar progress-bar bg-warning";
            } else if (entropy < 56) {
                label.textContent = "Strong";
                label.className = "strength-label text-info small";
                bar.style.width = "75%";
                bar.className = "strength-bar progress-bar bg-info";
            } else {
                label.textContent = "Excellent";
                label.className = "strength-label text-success small";
                bar.style.width = "100%";
                bar.className = "strength-bar progress-bar bg-success";
            }
        }

        input.addEventListener("input", function () {
            evaluatePassword(this.value);
        });

        if (input.value) {
            evaluatePassword(input.value);
        }
    });
});
