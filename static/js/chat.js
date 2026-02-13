const Chat = {
    container: null,
    form: null,
    input: null,
    emptyState: null,
    typingIndicator: null,
    autoScroll: true,
    sidebar: null,
    sessionLabel: null,
    beaconSelect: null,

    init() {
        this.container = document.getElementById("chat-messages");
        this.form = document.getElementById("chat-form");
        this.input = document.getElementById("chat-input");
        this.emptyState = document.getElementById("chat-empty");
        this.typingIndicator = document.getElementById("typing-indicator");
        this.sidebar = document.getElementById("history-sidebar");
        this.sessionLabel = document.getElementById("chat-session-label");
        this.beaconSelect = document.getElementById("beacon-select");

        if (!this.container || !this.form) return;

        this.form.addEventListener("submit", (e) => {
            e.preventDefault();
            this.sendMessage();
        });

        this.container.addEventListener("scroll", () => {
            const { scrollTop, scrollHeight, clientHeight } = this.container;
            this.autoScroll = scrollHeight - scrollTop - clientHeight < 50;
        });

        // Listen for new messages from orchestrator
        document.addEventListener("rednerve:new_message", (e) => {
            this.renderMessage(e.detail, true);
        });

        document.addEventListener("rednerve:typing_start", (e) => {
            if (this.typingIndicator) {
                this.typingIndicator.style.display = "flex";
                const label = this.typingIndicator.querySelector(".typing-label");
                if (label && e.detail && e.detail.status) {
                    label.textContent = e.detail.status;
                }
            }
            this.scrollToBottom();
        });

        document.addEventListener("rednerve:typing_end", () => {
            if (this.typingIndicator) this.typingIndicator.style.display = "none";
        });

        // Session comes automatically on connect from server
        App.socket.on("session_info", (session) => {
            State.setSession(session);
            console.log("[Chat] Session ready:", session.id, "beacon:", session.beacon_id || "general");
            this.updateSessionLabel();
            this.loadHistory();
            this.refreshSidebar();
        });

        App.socket.on("chat_history", (data) => {
            const messages = data.messages || [];
            if (messages.length > 0) {
                this.hideEmptyState();
                messages.forEach((msg) => {
                    if (State.addMessage(msg)) {
                        this.renderMessage(msg, false);
                    }
                });
                this.scrollToBottom();
            }
        });

        App.socket.on("sessions_list", (data) => {
            this.renderSessions(data.sessions || []);
        });

        App.socket.on("session_deleted", (data) => {
            if (State.currentSession && data.session_id === State.currentSession.id) {
                this.newChat();
            }
            this.refreshSidebar();
        });

        // Sidebar controls
        document.getElementById("history-toggle")?.addEventListener("click", () => {
            this.toggleSidebar();
        });

        document.getElementById("sidebar-close")?.addEventListener("click", () => {
            this.toggleSidebar(false);
        });

        document.getElementById("new-chat-btn")?.addEventListener("click", () => {
            this.newChat();
        });

        document.getElementById("cancel-btn")?.addEventListener("click", () => {
            this.cancelOperation();
        });

        // Beacon selector
        document.getElementById("open-beacon-chat")?.addEventListener("click", () => {
            this.openBeaconChat();
        });

        document.getElementById("open-general-chat")?.addEventListener("click", () => {
            this.openGeneralChat();
        });

        // Load beacons for dropdown
        this.loadBeacons();
        // Listen for new beacon registrations
        App.socket.on("beacon_registered", () => this.loadBeacons());
        App.socket.on("beacon_deleted", () => this.loadBeacons());
    },

    // ─── Beacon Selector ─────────────────────────────────

    async loadBeacons() {
        try {
            const resp = await fetch("/api/beacons");
            const data = await resp.json();
            const beacons = data.beacons || [];
            if (!this.beaconSelect) return;

            const current = this.beaconSelect.value;
            this.beaconSelect.innerHTML = '<option value="">Select a beacon...</option>';
            beacons.forEach(b => {
                if (b.status === "active" || b.status === "dormant") {
                    const opt = document.createElement("option");
                    opt.value = b.id;
                    opt.textContent = `${b.hostname} (${b.ip_address}) — ${b.username}`;
                    this.beaconSelect.appendChild(opt);
                }
            });
            // Restore selection if still valid
            if (current) this.beaconSelect.value = current;
        } catch (e) {
            console.error("[Chat] Failed to load beacons:", e);
        }
    },

    openBeaconChat() {
        const beaconId = this.beaconSelect?.value;
        if (!beaconId) return;
        this.clearMessages();
        State.messages = [];
        State.lastSequence = 0;
        App.emit("request_beacon_session", { beacon_id: beaconId });
    },

    openGeneralChat() {
        this.clearMessages();
        State.messages = [];
        State.lastSequence = 0;
        App.emit("request_session", {});
    },

    cancelOperation() {
        if (!State.currentSession) return;
        App.emit("cancel_operation", { session_id: State.currentSession.id });
        const label = this.typingIndicator?.querySelector(".typing-label");
        if (label) label.textContent = "Cancelling...";
    },

    // ─── Sidebar ──────────────────────────────────────

    toggleSidebar(force) {
        if (!this.sidebar) return;
        const open = force !== undefined ? force : !this.sidebar.classList.contains("open");
        this.sidebar.classList.toggle("open", open);
        if (open) this.refreshSidebar();
    },

    refreshSidebar() {
        App.emit("request_sessions", {});
    },

    renderSessions(sessions) {
        const el = document.getElementById("sidebar-sessions");
        if (!el) return;

        if (sessions.length === 0) {
            el.innerHTML = '<div class="sidebar-empty">No chat sessions yet</div>';
            return;
        }

        const currentId = State.currentSession?.id;

        // Group sessions: beacon-scoped vs general
        const beaconSessions = sessions.filter(s => s.beacon_id);
        const generalSessions = sessions.filter(s => !s.beacon_id);

        let html = "";

        if (beaconSessions.length > 0) {
            html += '<div class="sidebar-group-header">Beacon Sessions</div>';
            html += beaconSessions.map(s => this._renderSessionItem(s, currentId)).join("");
        }

        if (generalSessions.length > 0) {
            html += '<div class="sidebar-group-header">General Sessions</div>';
            html += generalSessions.map(s => this._renderSessionItem(s, currentId)).join("");
        }

        el.innerHTML = html;

        // Click handlers for session items
        el.querySelectorAll(".session-item").forEach(item => {
            item.addEventListener("click", (e) => {
                if (e.target.closest(".session-item-delete")) return;
                const sid = item.dataset.sessionId;
                if (sid && sid !== currentId) {
                    this.switchSession(sid);
                }
            });
        });

        // Delete handlers
        el.querySelectorAll(".session-item-delete").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const sid = btn.dataset.deleteId;
                if (sid && confirm("Delete this chat session?")) {
                    App.emit("delete_session", { session_id: sid });
                }
            });
        });
    },

    _renderSessionItem(s, currentId) {
        const isActive = s.id === currentId;
        const preview = this.escapeHtml(s.preview || "Empty session");
        const date = s.updated_at ? this.formatDate(s.updated_at) : "";
        const count = s.message_count || 0;

        let label = preview;
        if (s.beacon_id) {
            const host = s.beacon_hostname || s.beacon_id.slice(0, 8);
            const ip = s.beacon_ip ? ` (${s.beacon_ip})` : "";
            label = `<span class="session-beacon-tag">${this.escapeHtml(host)}${this.escapeHtml(ip)}</span> ${preview}`;
        }

        return `
            <div class="session-item ${isActive ? "active" : ""}" data-session-id="${s.id}">
                <div class="session-item-body">
                    <div class="session-item-preview">${label}</div>
                    <div class="session-item-meta">
                        <span>${date}</span>
                        <span class="session-item-count">${count} msg${count !== 1 ? "s" : ""}</span>
                    </div>
                </div>
                <button class="session-item-delete" data-delete-id="${s.id}" title="Delete">&times;</button>
            </div>`;
    },

    switchSession(sessionId) {
        this.clearMessages();
        State.messages = [];
        State.lastSequence = 0;
        App.emit("switch_session", { session_id: sessionId });
    },

    newChat() {
        this.clearMessages();
        State.messages = [];
        State.lastSequence = 0;
        App.emit("switch_session", { session_id: "new" });
    },

    clearMessages() {
        if (!this.container) return;
        this.container.innerHTML = '';
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.id = "chat-empty";
        empty.innerHTML = '<div class="empty-state-icon">&gt;_</div><div class="empty-state-text">Awaiting operator commands...</div>';
        this.container.appendChild(empty);
        this.emptyState = empty;
    },

    updateSessionLabel() {
        if (!this.sessionLabel || !State.currentSession) return;
        const s = State.currentSession;
        if (s.beacon_id) {
            const host = s.beacon_hostname || s.beacon_id.slice(0, 8);
            this.sessionLabel.textContent = `Beacon: ${host}`;
            this.sessionLabel.style.color = "var(--accent-glow)";
        } else {
            this.sessionLabel.textContent = "Session: " + s.id.slice(0, 8);
            this.sessionLabel.style.color = "";
        }
    },

    formatDate(iso) {
        try {
            const d = new Date(iso);
            const now = new Date();
            const diff = now - d;
            if (diff < 60000) return "just now";
            if (diff < 3600000) return Math.floor(diff / 60000) + "m ago";
            if (diff < 86400000) return Math.floor(diff / 3600000) + "h ago";
            return d.toLocaleDateString();
        } catch {
            return "";
        }
    },

    // ─── Chat ─────────────────────────────────────────

    loadHistory() {
        if (!State.currentSession) return;
        App.emit("request_history", {
            session_id: State.currentSession.id,
            since_sequence: State.lastSequence,
        });
    },

    sendMessage() {
        const content = this.input.value.trim();
        if (!content) return;

        if (!State.currentSession) {
            console.warn("[Chat] No session yet, retrying in 500ms...");
            setTimeout(() => this.sendMessage(), 500);
            return;
        }

        this.input.value = "";
        this.hideEmptyState();

        const localMsg = {
            id: "local-" + Date.now(),
            sequence: State.lastSequence + 0.5,
            role: "user",
            content: content,
            metadata: {},
        };
        this.renderMessage(localMsg, false);

        App.emit("send_message", {
            session_id: State.currentSession.id,
            content: content,
        });
    },

    renderMessage(msg, isNew) {
        this.hideEmptyState();

        if (msg.sequence > 0 && document.querySelector(`[data-sequence="${msg.sequence}"]`)) return;

        const el = document.createElement("div");
        el.className = `message message-${msg.role}`;
        if (msg.sequence) el.dataset.sequence = msg.sequence;

        const contentEl = document.createElement("div");
        contentEl.className = "message-content";

        if (msg.role === "assistant" && isNew) {
            this.typeText(contentEl, msg.content || "");
        } else {
            contentEl.innerHTML = this.formatContent(msg.content || "", msg.role);
        }

        el.appendChild(contentEl);

        if (msg.metadata && msg.metadata.agent) {
            const meta = document.createElement("div");
            meta.className = "message-meta";
            meta.innerHTML = `<span class="message-agent-tag">${this.escapeHtml(msg.metadata.agent)}</span>`;
            el.appendChild(meta);
        }

        this.container.appendChild(el);

        if (this.autoScroll) {
            this.scrollToBottom();
        }
    },

    typeText(el, text) {
        const formatted = this.formatContent(text, "assistant");
        const temp = document.createElement("div");
        temp.innerHTML = formatted;
        const fullText = temp.textContent || temp.innerText;

        let i = 0;
        const cursor = document.createElement("span");
        cursor.className = "typing-cursor";

        el.textContent = "";
        el.appendChild(cursor);

        const speed = Math.max(5, Math.min(20, 2000 / Math.max(fullText.length, 1)));

        const typeNext = () => {
            if (i < fullText.length) {
                el.insertBefore(document.createTextNode(fullText[i]), cursor);
                i++;
                if (this.autoScroll) this.scrollToBottom();
                setTimeout(typeNext, speed);
            } else {
                cursor.remove();
                el.innerHTML = formatted;
            }
        };

        typeNext();
    },

    formatContent(content, role) {
        if (!content) return "";
        if (role === "user") return this.escapeHtml(content);

        let html = this.escapeHtml(content);
        html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/^\s*[-*]\s+(.+)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');
        html = html.replace(/\n/g, '<br>');
        return html;
    },

    escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    },

    hideEmptyState() {
        if (this.emptyState) this.emptyState.style.display = "none";
    },

    scrollToBottom() {
        if (this.container) {
            this.container.scrollTop = this.container.scrollHeight;
        }
    },
};

document.addEventListener("DOMContentLoaded", () => Chat.init());
