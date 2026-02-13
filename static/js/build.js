const Build = {
    form: null,
    resultEl: null,
    buildsListEl: null,
    buildBtn: null,

    init() {
        this.form = document.getElementById("build-form");
        this.resultEl = document.getElementById("build-result");
        this.buildsListEl = document.getElementById("builds-list");
        this.buildBtn = document.getElementById("build-btn");

        if (!this.form) return;

        this.form.addEventListener("submit", (e) => {
            e.preventDefault();
            this.buildImplant();
        });

        document.getElementById("refresh-builds")?.addEventListener("click", () => {
            this.loadBuilds();
        });

        // Auto-update format options based on OS selection
        document.querySelectorAll('input[name="os"]').forEach(radio => {
            radio.addEventListener("change", () => this.updateFormatOptions());
        });

        this.updateFormatOptions();
        this.loadBuilds();
    },

    updateFormatOptions() {
        const os = document.querySelector('input[name="os"]:checked')?.value;
        const formats = document.querySelectorAll('input[name="format"]');

        formats.forEach(f => {
            const card = f.closest(".format-option");
            card.style.opacity = "1";
            card.style.pointerEvents = "auto";

            // Grey out incompatible formats
            if (os === "linux" || os === "macos") {
                if (f.value === "ps1" || f.value === "exe") {
                    card.style.opacity = "0.3";
                    card.style.pointerEvents = "none";
                    if (f.checked) {
                        document.querySelector('input[name="format"][value="py"]').checked = true;
                    }
                }
            }
            if (os === "windows") {
                if (f.value === "sh" || f.value === "elf") {
                    card.style.opacity = "0.3";
                    card.style.pointerEvents = "none";
                    if (f.checked) {
                        document.querySelector('input[name="format"][value="py"]').checked = true;
                    }
                }
            }
        });
    },

    async buildImplant() {
        const formData = new FormData(this.form);
        const config = {
            server: formData.get("server"),
            secret: formData.get("secret"),
            format: formData.get("format"),
            os: formData.get("os"),
            interval: parseInt(formData.get("interval")) || 5,
            jitter: parseInt(formData.get("jitter")) || 10,
            sleep: parseInt(formData.get("sleep")) || 0,
            auto_persist: formData.get("auto_persist") === "on",
            kill_date: formData.get("kill_date") || "",
        };

        // Validate
        if (!config.server) {
            this.showError("C2 Server URL is required");
            return;
        }
        if (!config.secret) {
            this.showError("Beacon Secret is required");
            return;
        }

        // Show loading
        this.buildBtn.disabled = true;
        this.buildBtn.querySelector(".build-btn-text").style.display = "none";
        this.buildBtn.querySelector(".build-btn-loading").style.display = "inline";

        try {
            const resp = await fetch("/api/build", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(config),
            });

            const data = await resp.json();

            if (resp.ok && data.filename) {
                this.showSuccess(data);
                this.loadBuilds();
            } else {
                this.showError(data.detail || data.error || "Build failed");
            }
        } catch (e) {
            this.showError("Request failed: " + e.message);
        } finally {
            this.buildBtn.disabled = false;
            this.buildBtn.querySelector(".build-btn-text").style.display = "inline";
            this.buildBtn.querySelector(".build-btn-loading").style.display = "none";
        }
    },

    showSuccess(data) {
        this.resultEl.innerHTML = `
            <div class="build-success">
                <div class="build-success-header">Build Successful</div>
                <div class="build-info">
                    <span class="build-info-label">Filename</span>
                    <span class="build-info-value">${this.esc(data.filename)}</span>
                    <span class="build-info-label">Size</span>
                    <span class="build-info-value">${this.formatSize(data.size)}</span>
                    <span class="build-info-label">Build ID</span>
                    <span class="build-info-value">${this.esc(data.build_id)}</span>
                </div>
                <a href="/api/build/download/${encodeURIComponent(data.filename)}" class="btn download-btn" download>
                    Download ${this.esc(data.filename)}
                </a>
            </div>`;
    },

    showError(msg) {
        this.resultEl.innerHTML = `<div class="build-error">${this.esc(msg)}</div>`;
    },

    async loadBuilds() {
        try {
            const resp = await fetch("/api/builds");
            const data = await resp.json();
            const builds = data.builds || [];

            if (builds.length === 0) {
                this.buildsListEl.innerHTML = '<div class="empty-state"><div class="empty-state-text">No builds yet</div></div>';
                return;
            }

            this.buildsListEl.innerHTML = builds.map(b => `
                <div class="build-item">
                    <div>
                        <span class="build-item-name">${this.esc(b.filename)}</span>
                        <span class="build-item-size">${this.formatSize(b.size)}</span>
                    </div>
                    <a href="/api/build/download/${encodeURIComponent(b.filename)}" class="build-item-dl" download>Download</a>
                </div>
            `).join("");
        } catch (e) {
            console.error("Failed to load builds:", e);
        }
    },

    formatSize(bytes) {
        if (!bytes) return "0 B";
        const units = ["B", "KB", "MB", "GB"];
        let i = 0;
        let size = bytes;
        while (size >= 1024 && i < units.length - 1) {
            size /= 1024;
            i++;
        }
        return size.toFixed(i > 0 ? 1 : 0) + " " + units[i];
    },

    esc(text) {
        const div = document.createElement("div");
        div.textContent = text || "";
        return div.innerHTML;
    },
};

document.addEventListener("DOMContentLoaded", () => Build.init());
