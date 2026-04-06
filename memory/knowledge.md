# Vader Knowledge Base

## Port Patterns Learned
- `21/tcp`: observed on Labyrinth
- `22/tcp`: observed on Labyrinth
- `80/tcp`: observed on Labyrinth
- `3306/tcp`: observed on Labyrinth
- `3306/tcp`: frequently blocks remote access on TryHackMe and should trigger source/config pivots.
- `53/tcp`: common on AD domain controllers for DNS
- `88/tcp`: Kerberos; useful for user validation, AS-REP roasting, and Kerberoasting
- `135/tcp`: MSRPC; supporting Windows/DC indicator
- `139/tcp`: NetBIOS session service; common Windows file-sharing support port
- `389/tcp`: LDAP; rootDSE often leaks domain/DC names even when full binds are required
- `445/tcp`: SMB; share visibility and post-credential looting surface
- `464/tcp`: Kerberos password change service
- `593/tcp`: RPC over HTTP
- `636/tcp`: LDAPS
- `3268/tcp`: Global Catalog LDAP
- `3269/tcp`: Global Catalog LDAPS
- `3389/tcp`: RDP
- `5985/tcp`: WinRM

## Service Patterns Learned
- ProFTPD
- OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
- Apache httpd 2.4.41 ((Ubuntu))
- MariaDB 10.3.24 or later (unauthorized)
- Exposed Git over HTTP is often more valuable than the rendered web app.
- Downloadable SQL/bootstrap files are high-value credential leaks.
- Broken live PHP can diverge sharply from recovered source history.
- Windows AD DCs can expose enough rootDSE metadata anonymously to reveal the exact domain and hostname.
- LSARPC SID bruteforcing can still leak a full domain user list even when anonymous LDAP subtree queries and null-session SAMR are blocked.
- SMB signing being required blocks easy relay over SMB, but does not prevent other post-credential SMB actions.
- LDAP signing not enforced is a meaningful relay signal on AD hosts.
- Kerberoastable service accounts with SPNs remain high-value once any valid domain user is obtained.
- Readable backup shares may contain machine-account NTLM hashes that are directly useful for pass-the-hash.

## Tool Effectiveness Rankings
1. `nmap`: best first-pass network map.
2. `curl`: fastest way to validate files, endpoints, and weird behavior.
3. Git mirroring/reconstruction: highest-value move when `/.git/` is exposed.
4. `gobuster`: useful for confirming hidden files and directory leaks.
5. `hydra`: useful only after strong credentials are recovered.
6. `impacket-lookupsid`: excellent when AD blocks normal anonymous enumeration but still leaks user RIDs.
7. `netexec`: strong for SMB/LDAP validation, share enumeration, Kerberoast checks, and pass-the-hash validation.
8. `impacket-GetUserSPNs`: reliable Kerberoast collection once any domain user credential is available.
9. `john`: fast enough for offline cracking of a small Kerberoast set with `rockyou`.
10. `smbclient`: simple and effective for targeted share looting after credential recovery.

## CTF Platform Patterns For TryHackMe
- Hints often redirect from a minor service to the real weakness.
- Naming themes can become usernames.
- Remote MySQL commonly looks interesting but blocks direct access.
- Flag text can reveal the flag's own location.
- Large fake AD user populations can hide a single weak credential pattern.
- AD labs often expect an initial low-priv foothold, then Kerberoast or share looting, then a credential/hash pivot to admin.
- Machine-account hashes from backups can still yield privileged SMB access on the DC.

## Credential Patterns Seen
- Eurycliedes:greeklover
- Menekrates:greeksalad
- Philostratos:nickthegreek
- Daedalus:g2e55kh4ck5r
- M!n0taur:aminotauro
- Cerberos:soviet911210036173
- Pegasus:pizzaeater_1
- Chiron:hiphophugosoviet18
- Centaurus:elcentauro
- Daedalus:1989dontforgetyourpass
- Historical Git credentials remain worth testing.
- Developer comments can reveal local-only accounts and password habits.
- `ybob317:ybob317`
- `file_svc:Password123!!`
- `FileServer$:e41da7e79a4c76dbd9cf79d1cb325559`
- Username-equals-password can be the intended spray pattern for one low-priv AD user.
- Cracked service-account passwords should be tested immediately against SMB shares tied to that service.

## Dead Ends To Avoid
- SSH login attempts with current and historical app credentials did not produce a shell
- FTP credential attempts did not reveal non-anonymous access
- MariaDB rejected remote connections from this host with `Host ... is not allowed to connect`
- Live PHP endpoints returned empty bodies or errors, preventing app-based exploitation
- ProFTPD `mod_copy` was not available
- Web artifact checks did not reveal additional flags beyond the source-exposed one
- Stopping Git analysis at `main`.
- Assuming read-only anonymous FTP means FTP is irrelevant.
- Assuming flag numbering equals discovery order.
- Assuming anonymous LDAP failure means anonymous Windows enumeration is fully dead; LSARPC may still leak users.
- Spraying only standout service accounts; the real weak credential may belong to a random low-priv user.
- Ignoring a denied share after first contact; it may become the key pivot once the right service credential is found.

## Winning Strategies Confirmed
- Full TCP recon with `nmap`
- Mirroring `/.git/` and reconstructing the repository
- Mining Git history for credentials and code paths
- Pulling the live `dbCreate.sql` directly
- Broad recon first, then pivot into the richest exposed artifact.
- Test every recovered credential across every relevant service immediately.
- Use `lookupsid` when null-session RPC and LDAP subtree reads are blocked.
- Try a username-equals-password spray when the room hint suggests spraying and the user base looks synthetic.
- Kerberoast all SPN accounts as soon as one valid domain user is recovered.
- Map cracked service credentials back to shares and host roles; `file_svc` led directly to the readable `backup` share.
- Parse raw backup material into NTLM hashes and validate them with pass-the-hash against SMB immediately.
- Machine-account hashes can be enough to read `C$` and recover the administrator flag.

## Soupedecode Snapshot
- Platform: TryHackMe
- Target: 10.65.186.22
- Domain: `SOUPEDECODE.LOCAL`
- DC: `DC01.SOUPEDECODE.LOCAL`
- Confirmed path: RID leak -> `ybob317:ybob317` spray hit -> Kerberoast -> `file_svc:Password123!!` -> backup share -> `FileServer$` hash -> pass-the-hash to admin SMB
- Confirmed flags: `28189316c25dd3c0ad56d44d000d62a8`, `27cb2be302c388d63d27c86bfdd5f56a`

## Labyrinth Snapshot
- Platform: TryHackMe
- Target: 10.65.156.241
- Confirmed flags: fla6{7H@Ts_tHe_Dat48as3_F149}
