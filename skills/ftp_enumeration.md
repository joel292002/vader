# FTP Enumeration

## Goal
Determine whether FTP is only a clue holder or a real access path.

## Core Steps
- Try anonymous first
- If a hint mentions a specific name, try that user immediately
- List recursively with `ls -la -R`
- Download everything with `mget *`
- Check hidden files and dot files
- Try all known credentials on FTP

## Notes
- Read clue text carefully
- FTP may look low value but still point to the next pivot
