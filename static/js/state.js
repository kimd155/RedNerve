const State = {
    messages: [],
    lastSequence: 0,
    targets: [],
    agentStatuses: {},
    currentSession: null,
    connected: false,

    addMessage(msg) {
        if (this.messages.find(m => m.sequence === msg.sequence)) return false;
        this.messages.push(msg);
        this.messages.sort((a, b) => a.sequence - b.sequence);
        if (msg.sequence > this.lastSequence) {
            this.lastSequence = msg.sequence;
        }
        return true;
    },

    setMessages(msgs) {
        this.messages = msgs;
        if (msgs.length > 0) {
            this.lastSequence = Math.max(...msgs.map(m => m.sequence));
        }
    },

    updateTarget(target) {
        const idx = this.targets.findIndex(t => t.id === target.id);
        if (idx >= 0) {
            this.targets[idx] = { ...this.targets[idx], ...target };
        } else {
            this.targets.push(target);
        }
    },

    setTargets(targets) {
        this.targets = targets;
    },

    updateAgentStatus(name, status) {
        this.agentStatuses[name] = status;
    },

    setSession(session) {
        this.currentSession = session;
    },

    setConnected(val) {
        this.connected = val;
    },

    clear() {
        this.messages = [];
        this.lastSequence = 0;
        this.targets = [];
        this.agentStatuses = {};
    }
};
