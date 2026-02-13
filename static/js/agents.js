const Dashboard = {
    logFeed: null,
    logFilter: "all",
    logs: [],
    maxLogs: 200,
    findingsData: [],

    init() {
        this.logFeed = document.getElementById("log-feed");

        if (!document.getElementById("findings-grid")) return;

        // Log filter buttons
        document.querySelectorAll(".filter-btn[data-level]").forEach((btn) => {
            btn.addEventListener("click", () => {
                document.querySelectorAll(".filter-btn[data-level]").forEach(b => b.classList.remove("active"));
                btn.classList.add("active");
                this.logFilter = btn.dataset.level;
                this.renderLogs();
            });
        });

        // Task events → log entries
        App.socket.on("task_progress", (data) => {
            this.addLog({
                level: "info",
                source: data.agent || "agent",
                message: `Task ${data.status}: ${data.summary || data.task_id}`,
                created_at: new Date().toISOString(),
            });
        });

        App.socket.on("task_result", (data) => {
            this.addLog({
                level: "info",
                source: data.beacon_id?.substring(0, 8) || "beacon",
                message: `Result for task ${data.task_id?.substring(0, 8)}: ${data.result?.status || "done"}`,
                created_at: new Date().toISOString(),
            });
        });

        // Findings updates — now grouped by beacon
        App.socket.on("findings_summary", (data) => {
            this.findingsData = data.beacons || [];
            this.renderFindings(this.findingsData);
        });

        // Log entries from server
        App.socket.on("log_entry", (data) => {
            this.addLog(data);
        });

        // Recent logs on connect
        App.socket.on("recent_logs", (data) => {
            const logs = data.logs || [];
            logs.reverse().forEach(l => this.addLog(l));
        });

        // Reports list
        App.socket.on("reports_list", (data) => {
            this.renderReportsTable(data.reports || []);
        });

        App.socket.on("report_started", (data) => {
            this.showToast("Report is processing. Check back later for download.");
            App.emit("request_reports", {});
        });

        App.socket.on("report_status", (data) => {
            App.emit("request_reports", {});
            if (data.status === "ready") {
                this.showToast("Report is ready for download!");
            }
        });

        // Modal close
        document.getElementById("modal-close")?.addEventListener("click", () => this.closeModal());
        document.getElementById("findings-modal")?.addEventListener("click", (e) => {
            if (e.target.id === "findings-modal") this.closeModal();
        });

        // Report modal
        document.getElementById("generate-report-btn")?.addEventListener("click", () => {
            this.openReportModal();
        });
        document.getElementById("report-modal-close")?.addEventListener("click", () => {
            document.getElementById("report-modal").style.display = "none";
        });
        document.getElementById("report-modal")?.addEventListener("click", (e) => {
            if (e.target.id === "report-modal") e.target.style.display = "none";
        });
        document.getElementById("report-modal-generate")?.addEventListener("click", () => {
            this.generateReport();
        });

        // Request data when socket is ready
        const requestData = () => {
            App.emit("request_findings_summary", {});
            App.emit("request_recent_logs", {});
            App.emit("request_reports", {});
        };

        if (App.socket.connected) {
            requestData();
        }
        document.addEventListener("rednerve:socket_ready", requestData);
    },

    // ─── Beacon Findings Cards ────────────────────────────

    renderFindings(beacons) {
        const grid = document.getElementById("findings-grid");
        if (!grid) return;

        if (!beacons || beacons.length === 0) {
            grid.innerHTML = `<div class="empty-state"><div class="empty-state-text">No findings yet — run some agents first</div></div>`;
            return;
        }

        grid.innerHTML = beacons.map((b, idx) => {
            const sevCounts = b.severity_counts || {};
            const agentNames = Object.keys(b.agents || {});
            const badges = [];
            if (sevCounts.critical > 0) badges.push(`<span class="sev-badge sev-critical">${sevCounts.critical} Critical</span>`);
            if (sevCounts.high > 0) badges.push(`<span class="sev-badge sev-high">${sevCounts.high} High</span>`);
            if (sevCounts.medium > 0) badges.push(`<span class="sev-badge sev-medium">${sevCounts.medium} Medium</span>`);
            if (sevCounts.low > 0) badges.push(`<span class="sev-badge sev-low">${sevCounts.low} Low</span>`);
            if (sevCounts.info > 0) badges.push(`<span class="sev-badge sev-info">${sevCounts.info} Info</span>`);

            return `
                <div class="findings-card" data-findings-idx="${idx}">
                    <div class="findings-card-header">
                        <div class="findings-beacon-info">
                            <span class="findings-beacon-name">${this.escapeHtml(b.hostname || "Unknown")}</span>
                            <span class="findings-beacon-ip">${this.escapeHtml(b.ip_address || "N/A")}</span>
                        </div>
                        <span class="findings-count">${b.total} finding${b.total !== 1 ? "s" : ""}</span>
                    </div>
                    <div class="findings-severity-row">${badges.join("")}</div>
                    <div class="findings-categories">
                        ${agentNames.map(a => `<span class="capability-tag">${this.escapeHtml(a)}</span>`).join("")}
                    </div>
                </div>`;
        }).join("");

        grid.querySelectorAll(".findings-card").forEach(card => {
            card.addEventListener("click", () => {
                const idx = parseInt(card.dataset.findingsIdx);
                if (beacons[idx]) this.openFindingsModal(beacons[idx]);
            });
        });
    },

    openFindingsModal(beaconData) {
        const modal = document.getElementById("findings-modal");
        const title = document.getElementById("modal-agent-name");
        const body = document.getElementById("modal-body");
        if (!modal || !body) return;

        const hostname = beaconData.hostname || "Unknown";
        const ip = beaconData.ip_address || "N/A";
        const os = beaconData.os || "N/A";
        title.textContent = `${hostname} (${ip})`;

        const agents = beaconData.agents || {};
        const findings = beaconData.findings || [];

        if (findings.length === 0) {
            body.innerHTML = '<div class="empty-state"><div class="empty-state-text">No findings</div></div>';
            modal.style.display = "flex";
            return;
        }

        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const sevMap = {
            credentials: "critical", hashes: "critical", kerberoastable: "critical", domain_admins: "critical",
            vulnerabilities: "high", escalation_paths: "high", sessions: "high",
            shares: "medium", services: "medium",
            users: "info", groups: "info", hosts: "info", computers: "info", network: "info",
            ports: "low", artifacts: "low",
        };

        // Group findings by agent
        const byAgent = {};
        for (const f of findings) {
            const agent = f.source_agent || "unknown";
            if (!byAgent[agent]) byAgent[agent] = [];
            byAgent[agent].push(f);
        }

        // Sort each group by severity
        for (const agent in byAgent) {
            byAgent[agent].sort((a, b) => {
                const sa = sevOrder[sevMap[a.category] || "info"] || 4;
                const sb = sevOrder[sevMap[b.category] || "info"] || 4;
                return sa - sb;
            });
        }

        // Build HTML with agent sub-sections
        let html = `<div class="modal-beacon-meta">
            <span class="modal-meta-item"><strong>OS:</strong> ${this.escapeHtml(os)}</span>
            <span class="modal-meta-item"><strong>IP:</strong> ${this.escapeHtml(ip)}</span>
            <span class="modal-meta-item"><strong>Total:</strong> ${findings.length} findings</span>
        </div>`;

        for (const [agent, agentFindings] of Object.entries(byAgent)) {
            const agentInfo = agents[agent] || {};
            const agentCategories = Object.keys(agentInfo.categories || {});

            html += `
                <div class="modal-agent-section">
                    <div class="modal-agent-header">
                        <span class="modal-agent-name">${this.escapeHtml(agent)}</span>
                        <span class="modal-agent-count">${agentFindings.length} finding${agentFindings.length !== 1 ? "s" : ""}</span>
                        <div class="modal-agent-tags">
                            ${agentCategories.map(c => `<span class="capability-tag">${this.escapeHtml(c)}</span>`).join("")}
                        </div>
                    </div>
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Category</th>
                                <th>Key</th>
                                <th>Data</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${agentFindings.map(f => {
                                const sev = sevMap[f.category] || "info";
                                const dataStr = typeof f.data === "object" ? JSON.stringify(f.data, null, 0) : String(f.data);
                                const truncData = dataStr.length > 120 ? dataStr.substring(0, 120) + "..." : dataStr;
                                const time = f.created_at ? new Date(f.created_at).toLocaleString() : "";
                                return `
                                    <tr>
                                        <td><span class="sev-badge sev-${sev}">${sev}</span></td>
                                        <td>${this.escapeHtml(f.category)}</td>
                                        <td>${this.escapeHtml(f.key)}</td>
                                        <td class="findings-data-cell" title="${this.escapeHtml(dataStr)}">${this.escapeHtml(truncData)}</td>
                                        <td class="findings-time-cell">${time}</td>
                                    </tr>`;
                            }).join("")}
                        </tbody>
                    </table>
                </div>`;
        }

        body.innerHTML = html;
        modal.style.display = "flex";
    },

    closeModal() {
        const modal = document.getElementById("findings-modal");
        if (modal) modal.style.display = "none";
    },

    // ─── Reports ─────────────────────────────────────────

    openReportModal() {
        const select = document.getElementById("report-agent-select");
        if (select) {
            select.innerHTML = '<option value="all">All Beacons</option>';
            (this.findingsData || []).forEach(b => {
                const opt = document.createElement("option");
                opt.value = b.beacon_id;
                opt.textContent = `${b.hostname || "Unknown"} — ${b.ip_address || "N/A"} (${b.total} findings)`;
                select.appendChild(opt);
            });
        }
        document.getElementById("report-modal").style.display = "flex";
    },

    generateReport() {
        const select = document.getElementById("report-agent-select");
        const filter = select ? select.value : "all";
        App.emit("generate_report", { agent_filter: filter });
        this.showToast("Report is processing. Check back later for download.");
        document.getElementById("report-modal").style.display = "none";
    },

    renderReportsTable(reports) {
        const container = document.getElementById("reports-table-container");
        if (!container) return;

        if (!reports || reports.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No reports generated yet</div></div>';
            return;
        }

        container.innerHTML = `
            <table class="reports-table">
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Status</th>
                        <th>Findings</th>
                        <th>Created</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    ${reports.map(r => {
                        const date = r.created_at ? new Date(r.created_at).toLocaleString() : "";
                        let statusHtml = "";
                        let actionHtml = "";

                        if (r.status === "processing") {
                            statusHtml = '<span class="report-processing">Processing...</span>';
                        } else if (r.status === "ready") {
                            statusHtml = '<span class="report-ready">Ready</span>';
                            actionHtml = `<a href="/api/reports/${r.id}/download" class="btn btn-sm report-download-link" target="_blank">Download</a>`;
                        } else if (r.status === "failed") {
                            statusHtml = `<span class="report-failed">Failed</span>`;
                        }

                        return `
                            <tr>
                                <td>${this.escapeHtml(r.title || "Report")}</td>
                                <td>${statusHtml}</td>
                                <td>${r.finding_count || 0}</td>
                                <td class="findings-time-cell">${date}</td>
                                <td>${actionHtml}</td>
                            </tr>`;
                    }).join("")}
                </tbody>
            </table>`;
    },

    // ─── Toast ───────────────────────────────────────────

    showToast(message) {
        const container = document.getElementById("toast-container");
        if (!container) return;

        const toast = document.createElement("div");
        toast.className = "toast";
        toast.textContent = message;
        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add("toast-fade-out");
            setTimeout(() => toast.remove(), 400);
        }, 5000);
    },

    // ─── Logs ────────────────────────────────────────────

    addLog(entry) {
        this.logs.unshift(entry);
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(0, this.maxLogs);
        }
        this.renderLogs();
    },

    renderLogs() {
        if (!this.logFeed) return;

        let filtered = this.logs;
        if (this.logFilter !== "all") {
            filtered = this.logs.filter(l => l.level === this.logFilter);
        }

        if (filtered.length === 0) {
            this.logFeed.innerHTML = `<div class="empty-state"><div class="empty-state-text">No activity yet</div></div>`;
            return;
        }

        this.logFeed.innerHTML = filtered.slice(0, 50).map(entry => {
            const time = entry.created_at ? new Date(entry.created_at).toLocaleTimeString() : "";
            return `
                <div class="log-entry">
                    <span class="log-time">${time}</span>
                    <span class="log-level log-level-${entry.level || "info"}">${entry.level || "info"}</span>
                    <span class="log-source">${this.escapeHtml(entry.source || "system")}</span>
                    <span class="log-message">${this.escapeHtml(entry.message || "")}</span>
                </div>`;
        }).join("");
    },

    escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    },
};

document.addEventListener("DOMContentLoaded", () => Dashboard.init());
