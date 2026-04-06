# Credential Attack

## Goal
Turn every recovered credential into a cross-service test set immediately.

## Order Of Operations
1. SSH first
2. FTP second
3. Web login third
4. Database fourth

## Rules
- Try every credential on every open service
- Use `hydra` when brute force is justified
- Common CTF passwords often match the room theme
- Old Git history passwords sometimes still work on SSH
