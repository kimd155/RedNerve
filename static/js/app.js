const App = {
    socket: null,

    init() {
        this.connectSocket();
    },

    connectSocket() {
        this.socket = io({ transports: ["websocket", "polling"] });

        this.socket.on("connect", () => {
            State.setConnected(true);
            this.updateConnectionUI(true);
            console.log("[RedNerve] WebSocket connected");
            document.dispatchEvent(new CustomEvent("rednerve:socket_ready"));
        });

        this.socket.on("connected", (data) => {
            console.log("[RedNerve] Server acknowledged:", data.sid);
        });

        this.socket.on("disconnect", () => {
            State.setConnected(false);
            this.updateConnectionUI(false);
            console.log("[RedNerve] WebSocket disconnected");
        });

        this.socket.on("connect_error", (err) => {
            console.error("[RedNerve] Connection error:", err.message);
            this.updateConnectionUI(false);
        });

        // Global event listeners
        this.socket.on("new_message", (msg) => {
            if (State.addMessage(msg)) {
                document.dispatchEvent(new CustomEvent("rednerve:new_message", { detail: msg }));
            }
        });

        this.socket.on("agent_status_update", (data) => {
            if (data.agent_name) {
                State.updateAgentStatus(data.agent_name, data);
            } else if (data.agents) {
                Object.entries(data.agents).forEach(([name, status]) => {
                    State.updateAgentStatus(name, status);
                });
            }
            document.dispatchEvent(new CustomEvent("rednerve:agent_update", { detail: data }));
        });

        this.socket.on("target_status_update", (data) => {
            State.updateTarget(data);
            document.dispatchEvent(new CustomEvent("rednerve:target_update", { detail: data }));
        });

        this.socket.on("task_progress", (data) => {
            document.dispatchEvent(new CustomEvent("rednerve:task_progress", { detail: data }));
        });

        this.socket.on("log_entry", (data) => {
            document.dispatchEvent(new CustomEvent("rednerve:log_entry", { detail: data }));
        });

        this.socket.on("typing_start", (data) => {
            document.dispatchEvent(new CustomEvent("rednerve:typing_start", { detail: data }));
        });

        this.socket.on("typing_end", () => {
            document.dispatchEvent(new CustomEvent("rednerve:typing_end"));
        });
    },

    updateConnectionUI(connected) {
        const dot = document.getElementById("ws-status");
        const text = document.getElementById("ws-status-text");
        if (!dot || !text) return;

        dot.className = "status-dot " + (connected ? "connected" : "disconnected");
        text.textContent = connected ? "Online" : "Disconnected";
    },

    emit(event, data) {
        if (this.socket && this.socket.connected) {
            this.socket.emit(event, data);
        }
    }
};

document.addEventListener("DOMContentLoaded", () => App.init());
