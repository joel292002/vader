# Swarm Input

This safe swarm ingests evidence you place in this directory.
The AI analyst watches this directory and assesses each new or modified file.

- `recon.txt`: paste `nmap`-style lines such as `22/tcp open ssh OpenSSH 9.6`
- `services.json`: optional structured port input with `{"open_ports": [{"port": 80, "service": "http", "banner": "nginx"}]}`
- `web_urls.txt`: one URL per line, optional trailing notes
- `web_findings.txt`: URLs, credentials like `user:pass`, flags, and file names
- `hashes.txt`: one hash per line, optionally prefixed with a hash type
- `shell_access.txt`: notes indicating shell/root access and any recovered flags
- `exploit_notes.txt`: research notes, `file:`, `credential:`, and `flag:` entries
- Any other text file is also reviewed by the AI analyst and turned into advisory next-step recommendations
