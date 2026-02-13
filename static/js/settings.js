const Settings = {
    form: null,
    sectionsEl: null,
    statusEl: null,
    saveBtn: null,
    settings: [],

    // Keys that require a server restart
    restartKeys: new Set(["HOST", "PORT", "DATABASE_URL"]),

    init() {
        this.form = document.getElementById("settings-form");
        this.sectionsEl = document.getElementById("settings-sections");
        this.statusEl = document.getElementById("settings-status");
        this.saveBtn = document.getElementById("settings-save");

        if (!this.form) return;

        this.form.addEventListener("submit", (e) => {
            e.preventDefault();
            this.save();
        });

        this.load();
    },

    async load() {
        try {
            const resp = await fetch("/api/settings");
            const data = await resp.json();
            this.settings = data.settings || [];
            this.render();
        } catch (e) {
            this.sectionsEl.innerHTML = '<div class="settings-loading">Failed to load settings</div>';
        }
    },

    render() {
        if (this.settings.length === 0) {
            this.sectionsEl.innerHTML = '<div class="settings-loading">No settings found</div>';
            return;
        }

        this.sectionsEl.innerHTML = this.settings.map(s => {
            const restartBadge = this.restartKeys.has(s.key)
                ? '<span class="restart-badge">Restart Required</span>'
                : '';

            let inputHtml = "";

            if (s.type === "select") {
                const options = (s.options || []).map(opt =>
                    `<option value="${this.esc(opt)}" ${opt === s.value ? "selected" : ""}>${this.esc(opt)}</option>`
                ).join("");
                inputHtml = `
                    <div class="setting-input-wrap">
                        <select class="setting-select" name="${s.key}">${options}</select>
                    </div>`;
            } else if (s.type === "password") {
                inputHtml = `
                    <div class="setting-input-wrap">
                        <input type="password" class="setting-input" name="${s.key}"
                               value="${this.esc(s.value)}"
                               placeholder="${this.esc(s.default || '')}"
                               data-real-value="${this.esc(s.value)}" />
                        <button type="button" class="toggle-visibility" data-target="${s.key}">Show</button>
                    </div>`;
            } else if (s.type === "number") {
                inputHtml = `
                    <div class="setting-input-wrap">
                        <input type="number" class="setting-input" name="${s.key}"
                               value="${this.esc(s.value)}"
                               placeholder="${this.esc(s.default || '')}" min="0" />
                    </div>`;
            } else {
                inputHtml = `
                    <div class="setting-input-wrap">
                        <input type="text" class="setting-input" name="${s.key}"
                               value="${this.esc(s.value)}"
                               placeholder="${this.esc(s.default || '')}" />
                    </div>`;
            }

            return `
                <div class="setting-group">
                    <div class="setting-group-header">
                        <span class="setting-label">${this.esc(s.label)}${restartBadge}</span>
                        <span class="setting-key">${s.key}</span>
                    </div>
                    <div class="setting-desc">${this.esc(s.desc)}</div>
                    ${inputHtml}
                </div>`;
        }).join("");

        // Bind toggle visibility buttons
        this.sectionsEl.querySelectorAll(".toggle-visibility").forEach(btn => {
            btn.addEventListener("click", () => {
                const key = btn.dataset.target;
                const input = this.sectionsEl.querySelector(`input[name="${key}"]`);
                if (!input) return;
                if (input.type === "password") {
                    input.type = "text";
                    btn.textContent = "Hide";
                } else {
                    input.type = "password";
                    btn.textContent = "Show";
                }
            });
        });
    },

    async save() {
        this.saveBtn.disabled = true;
        this.saveBtn.querySelector(".save-btn-text").style.display = "none";
        this.saveBtn.querySelector(".save-btn-loading").style.display = "inline";
        this.setStatus("");

        // Collect values
        const values = {};
        this.settings.forEach(s => {
            const el = this.sectionsEl.querySelector(`[name="${s.key}"]`);
            if (el) {
                values[s.key] = el.value;
            }
        });

        try {
            const resp = await fetch("/api/settings", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ settings: values }),
            });

            const data = await resp.json();

            if (resp.ok) {
                this.setStatus("Settings saved successfully", "success");
                // Check if restart-required keys were changed
                const needsRestart = (data.updated || []).some(k => this.restartKeys.has(k));
                if (needsRestart) {
                    this.setStatus("Saved — restart the server for some changes to take effect", "success");
                }
            } else {
                this.setStatus(data.detail || "Failed to save", "error");
            }
        } catch (e) {
            this.setStatus("Request failed: " + e.message, "error");
        } finally {
            this.saveBtn.disabled = false;
            this.saveBtn.querySelector(".save-btn-text").style.display = "inline";
            this.saveBtn.querySelector(".save-btn-loading").style.display = "none";
        }
    },

    setStatus(msg, type) {
        if (!this.statusEl) return;
        this.statusEl.textContent = msg;
        this.statusEl.className = "settings-status" + (type ? " " + type : "");
    },

    esc(text) {
        const div = document.createElement("div");
        div.textContent = text || "";
        return div.innerHTML;
    },
};

document.addEventListener("DOMContentLoaded", () => Settings.init());
