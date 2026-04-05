# TryHackMe Labyrinth Assessment

## Scope

- Target: `10.65.156.241`
- Platform: `TryHackMe`
- Room: `Labyrinth`
- Authorization: Fully authorized CTF assessment

## Executive Summary

The box exposes four primary network services: anonymous FTP on `21/tcp`, SSH on `22/tcp`, Apache on `80/tcp`, and MariaDB on `3306/tcp`. The most important weakness is severe source exposure through an open `.git` repository and a directly downloadable `dbCreate.sql`. Those leaks provide application source, commit history, usernames, plaintext application passwords, historical passwords, and one confirmed flag embedded in the recovered source.

The deployed PHP application appears partially broken or overwritten: key PHP endpoints such as `index.php`, `login.php`, `session.php`, `echo.php`, and API handlers return `200` with zero-length bodies or `500` without useful output, despite the `.git` history showing working code and vulnerabilities. I was able to confirm `Flag 1`, but I was not able to turn the exposed source and credentials into a working foothold for `Flag 2`, `user.txt`, or `root.txt` from the externally reachable surface.

## Recon

### Nmap

```text
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     ProFTPD
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
3306/tcp open  mysql   MariaDB 10.3.24 or later (unauthorized)
```

Key web findings from service discovery:

- `/.git/` is exposed over HTTP.
- `dbCreate.sql` is directly accessible over HTTP.

## Findings

### 1. Exposed Git repository

- Severity: Critical
- Evidence:
  - `/.git/HEAD` returned `ref: refs/heads/main`
  - `/.git/refs/heads/main` exposed commit `920cfcd99d95912dfc2e5ff0588de24762168b55`
  - Full repository could be mirrored and reconstructed locally

Impact:

- Recovered full application source
- Recovered commit history and side branches
- Recovered plaintext application passwords from `dbCreate.sql`
- Recovered one flag from source history

### 2. Exposed SQL initialization file

- Severity: Critical
- Evidence:
  - `GET /dbCreate.sql` returned the live database bootstrap script

Recovered credentials:

- `Eurycliedes : greeklover`
- `Menekrates : greeksalad`
- `Philostratos : nickthegreek`
- `Daedalus : g2e55kh4ck5r`
- `M!n0taur : aminotauro`
- `Cerberos : soviet911210036173`
- `Pegasus : pizzaeater_1`
- `Chiron : hiphophugosoviet18`
- `Centaurus : elcentauro`

Historical credential from Git history:

- Older commits used `Daedalus : 1989dontforgetyourpass`

Additional config clue:

- SQL comments referenced a local database user:
  - `CREATE USER 'daedalus'@'localhost' IDENTIFIED BY 'password';`

### 3. Confirmed source flag

- Severity: Informational
- Location:
  - `index.php` in exposed Git history

Confirmed flag:

- `fla6{7H@Ts_tHe_Dat48as3_F149}`

Assessment:

- This is the only flag I could confirm directly from the exposed artifacts during this assessment.

### 4. Anonymous FTP present but low-value

- Severity: Medium
- Evidence:
  - Anonymous login allowed
  - Exposed file: `pub/message.txt`

FTP clue:

```text
Daedalus is a clumsy person, he forgets a lot of things arount the labyrinth, have a look around, maybe you'll find something :)
-- Minotaur
```

Notes:

- Anonymous FTP was read-only.
- Upload attempts failed with `550 ... Operation not permitted`.
- `SITE CPFR/CPTO` were not supported, so ProFTPD `mod_copy` exploitation was not available.

### 5. Deployed PHP appears broken or overwritten

- Severity: High
- Evidence:
  - `GET /index.php` returned `200` with `Content-Length: 0`
  - `GET /login.php` returned `200` with `Content-Length: 0`
  - `GET /echo.php` returned `200` with `Content-Length: 0`
  - `GET /api/people/read.php` returned `500`
  - `POST /api/people/search.php` returned `200` with `Content-Length: 0`

Assessment:

- The exposed `.git` tree contains login logic, SQLi-prone search handlers, and an `echo.php` command-injection path in history.
- The currently deployed PHP endpoints did not behave like the recovered source and did not yield a usable execution path.

## Tooling And Pivots

### Effective moves

1. Full TCP recon with `nmap`
2. Mirroring `/.git/` and reconstructing the repository
3. Mining Git history for credentials and code paths
4. Pulling the live `dbCreate.sql` directly

### Dead ends

1. SSH login attempts with current and historical app credentials did not produce a shell
2. FTP credential attempts did not reveal non-anonymous access
3. MariaDB rejected remote connections from this host with `Host ... is not allowed to connect`
4. Live PHP endpoints returned empty bodies or errors, preventing app-based exploitation
5. ProFTPD `mod_copy` was not available
6. Web artifact checks did not reveal additional flags beyond the source-exposed one

## Flags

- Flag 1: `fla6{7H@Ts_tHe_Dat48as3_F149}`
- Flag 2: Not found
- User flag: Not found
- Root flag: Not found

## Conclusion

This box is badly misconfigured from a source-protection standpoint, but the live deployment is inconsistent enough that the recovered application vulnerabilities did not translate into a working foothold during this assessment. The strongest confirmed win is the exposed Git repository and SQL bootstrap file, which leaked credentials and one flag directly.

If I continued from here, the next steps would be:

1. Deeper branch-by-branch source archaeology for hidden deployment paths or host users
2. More focused SSH username discovery tied to the commit authors and room theme
3. Manual reproduction of the broken PHP environment assumptions to infer how the current deployment diverged from the repo
