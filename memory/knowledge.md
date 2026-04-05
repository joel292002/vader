# Technical Knowledge Base

## Port Patterns
- 2026-04-04 | 10.65.156.241 | Ports observed: 21, 22, 80, 3306
- Port 21: seen on 10.65.156.241
- Port 22: seen on 10.65.156.241
- Port 80: seen on 10.65.156.241
- Port 3306: seen on 10.65.156.241

## Service Patterns
- 2026-04-04 | 10.65.156.241 | Services: FTP, SSH, HTTP, MariaDB

## Tool Effectiveness
- 2026-04-04 | 10.65.156.241 | Useful tools: nmap, curl, gobuster, hydra

## CTF Patterns
### TryHackMe
(patterns noticed across THM machines)

### HackTheBox
(patterns noticed across HTB machines)

## Credentials That Have Worked
- 2026-04-04 | 10.65.156.241 | Recovered app creds: Daedalus:g2e55kh4ck5r, M!n0taur:aminotauro, Eurycliedes:greeklover, Menekrates:greeksalad, Philostratos:nickthegreek
- 2026-04-04 | 10.65.156.241 | Historical credential seen in Git: Daedalus:1989dontforgetyourpass
- No confirmed system credentials captured yet

## Rabbit Holes To Avoid
- 2026-04-04 | 10.65.156.241 | Anonymous FTP was read-only and did not allow upload
- 2026-04-04 | 10.65.156.241 | SSH/FTP credential reuse from exposed app passwords did not yield a shell
- 2026-04-04 | 10.65.156.241 | MariaDB rejected remote connections from the assessment host
- 2026-04-04 | 10.65.156.241 | Live PHP endpoints returned zero-length bodies or 500s and did not match recovered source behavior

## Winning Strategies
- 2026-04-04 | 10.65.156.241 | Best move: broad recon -> exposed .git -> reconstruct source -> pull dbCreate.sql -> mine history for creds and flags

## Latest Assessment Snapshot
- Source report: report_labyrinth.md
- Findings: Exposed Git repository; Exposed SQL initialization file
