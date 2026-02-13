const Effects = {
    codeSnippets: [
        "import socket; s = socket.socket()",
        "nmap -sV -O target_host",
        "def exploit(target): return shell",
        "SELECT * FROM credentials WHERE hash != NULL",
        "ssh -L 8080:internal:80 pivot@host",
        "for port in range(1,65535): scan(port)",
        "curl -X POST /api/exfil -d @data.enc",
        "chmod +x payload.sh && ./payload.sh",
        "grep -r 'password' /etc/ 2>/dev/null",
        "iptables -A INPUT -j DROP",
        "nc -lvp 4444 -e /bin/bash",
        "hashcat -m 1000 hashes.txt wordlist.txt",
        "mimikatz # sekurlsa::logonpasswords",
        "reg add HKLM\\...\\Run /v persist",
        "wmic process call create payload.exe",
    ],

    initCodeBackground() {
        const container = document.getElementById("bg-animation");
        if (!container) return;

        const lineCount = 25;
        for (let i = 0; i < lineCount; i++) {
            this.spawnCodeLine(container, i * (100 / lineCount));
        }
    },

    spawnCodeLine(container, initialDelay) {
        const line = document.createElement("div");
        line.className = "code-line";
        line.textContent = this.codeSnippets[Math.floor(Math.random() * this.codeSnippets.length)];
        line.style.left = Math.random() * 90 + "%";
        line.style.animationDuration = (15 + Math.random() * 20) + "s";
        line.style.animationDelay = (initialDelay / 100 * 20) + "s";
        line.style.fontSize = (10 + Math.random() * 4) + "px";
        container.appendChild(line);

        line.addEventListener("animationiteration", () => {
            line.textContent = this.codeSnippets[Math.floor(Math.random() * this.codeSnippets.length)];
            line.style.left = Math.random() * 90 + "%";
        });
    },
};

document.addEventListener("DOMContentLoaded", () => {
    Effects.initCodeBackground();
});
