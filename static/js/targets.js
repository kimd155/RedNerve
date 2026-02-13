const Targets = {
    grid: null,
    searchInput: null,
    currentFilter: "all",
    _lastHash: "",

    init() {
        this.grid = document.getElementById("targets-grid");
        this.searchInput = document.getElementById("target-search");

        if (!this.grid) return;

        // Filter buttons
        document.querySelectorAll(".filter-btn[data-filter]").forEach((btn) => {
            btn.addEventListener("click", () => {
                document.querySelectorAll(".filter-btn[data-filter]").forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                this.currentFilter = btn.dataset.filter;
                this._lastHash = "";
                this.render(true);
            });
        });

        // Search
        if (this.searchInput) {
            this.searchInput.addEventListener("input", () => {
                this._lastHash = "";
                this.render(true);
            });
        }

        // Listen for updates
        document.addEventListener("rednerve:target_update", (e) => {
            State.updateTarget(e.detail);
            this._lastHash = "";
            this.render(true);
        });

        App.socket.on("beacon_registered", (beacon) => {
            State.updateTarget(beacon);
            this._lastHash = "";
            this.render(true);
        });

        App.socket.on("targets_list", (data) => {
            State.setTargets(data.targets || []);
            this.render(false);
        });

        App.socket.on("beacon_deleted", (data) => {
            State.targets = State.targets.filter(t => t.id !== data.beacon_id);
            this._lastHash = "";
            this.render(false);
        });

        // Request targets once socket is ready
        if (App.socket.connected) {
            App.emit("request_targets", {});
        }
        App.socket.on("connect", () => {
            App.emit("request_targets", {});
        });

        // Auto-refresh every 5 seconds
        this._refreshInterval = setInterval(() => {
            App.emit("request_targets", {});
        }, 5000);
    },

    _computeHash(targets) {
        return targets.map(t => t.id + t.status + (t.last_seen || "")).join("|");
    },

    render(animate) {
        if (!this.grid) return;

        let targets = [...State.targets];

        // Filter
        if (this.currentFilter !== "all") {
            targets = targets.filter(t => t.status === this.currentFilter);
        }

        // Search
        const query = (this.searchInput?.value || "").toLowerCase();
        if (query) {
            targets = targets.filter(t =>
                (t.hostname || "").toLowerCase().includes(query) ||
                (t.ip_address || "").toLowerCase().includes(query) ||
                (t.username || "").toLowerCase().includes(query) ||
                (t.domain || "").toLowerCase().includes(query) ||
                (t.os || "").toLowerCase().includes(query)
            );
        }

        // Skip re-render if nothing changed (prevents animation flicker on auto-refresh)
        const hash = this._computeHash(targets);
        if (hash === this._lastHash) return;
        this._lastHash = hash;

        if (targets.length === 0) {
            this.grid.innerHTML = `
                <div class="empty-state" style="grid-column: 1 / -1;">
                    <div class="empty-state-icon">&#9673;</div>
                    <div class="empty-state-text">No beacons ${this.currentFilter !== "all" ? "matching filter" : "registered"}</div>
                </div>`;
            return;
        }

        this.grid.innerHTML = targets.map(t => this.renderCard(t, animate)).join("");

        // Attach delete handlers
        this.grid.querySelectorAll(".target-delete-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const beaconId = btn.dataset.deleteId;
                if (beaconId && confirm("Delete this beacon? It will be rejected on next check-in.")) {
                    App.emit("delete_beacon", { beacon_id: beaconId });
                }
            });
        });
    },

    renderCard(target, animate) {
        const statusClass = target.status === "active" ? "online" :
                           target.status === "dormant" ? "pending" : "offline";
        const lastSeen = target.last_seen ? this.timeAgo(new Date(target.last_seen)) : "never";
        const animClass = animate ? " target-card-animate" : "";

        return `
            <div class="target-card${animClass}" data-id="${target.id}">
                <div class="target-card-header">
                    <span class="target-hostname">${this.escapeHtml(target.hostname || "Unknown")}</span>
                    <span class="badge badge-${statusClass}">${target.status || "unknown"}</span>
                </div>
                <div class="target-card-body">
                    <span class="target-label">IP</span>
                    <span class="target-value">${this.escapeHtml(target.ip_address || "—")}</span>
                    <span class="target-label">OS</span>
                    <span class="target-value">${this.escapeHtml(target.os || "—")}</span>
                    <span class="target-label">User</span>
                    <span class="target-value">${this.escapeHtml(target.username || "—")}</span>
                    <span class="target-label">Domain</span>
                    <span class="target-value">${this.escapeHtml(target.domain || "—")}</span>
                    <span class="target-label">Integrity</span>
                    <span class="target-value">${this.escapeHtml(target.integrity || "—")}</span>
                    <span class="target-label">PID</span>
                    <span class="target-value">${target.pid || "—"}</span>
                </div>
                <div class="target-card-footer">
                    <span>ID: ${(target.id || "").substring(0, 8)}...</span>
                    <span>Last seen: ${lastSeen}</span>
                </div>
                <button class="target-delete-btn" data-delete-id="${target.id}" title="Delete beacon">&times;</button>
            </div>`;
    },

    escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    },

    timeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        if (seconds < 10) return "just now";
        if (seconds < 60) return seconds + "s ago";
        if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
        if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
        return Math.floor(seconds / 86400) + "d ago";
    },
};

document.addEventListener("DOMContentLoaded", () => Targets.init());
