# Web Enumeration

## Goal
Map the web attack surface quickly, then pivot into the highest-value exposed artifact.

## Tool Order
1. `whatweb`
2. `gobuster`
3. `nikto`

## Mandatory Checks
- `robots.txt`
- `/.git/`
- `/.env`
- `/backup`

## Git Exposure
- If Git is exposed, mirror it with `git-dumper`
- Reconstruct the repository locally
- Check ALL branches, not just `main`
- Mine commit history for flags, credentials, and alternate paths

## WordPress
- If WordPress is detected, run `wpscan` immediately

## Secrets Handling
- Extract all credentials from any SQL files
- Extract all credentials from any config files
- Add every recovered username and password to the findings board immediately
