# Security notes

SimpleCrypt is new, unaudited software. This document describes what it does and does not protect against, so you can decide how much to trust it.

## What is protected

- **At rest:** the entire vault file — record labels, field names, field values, and structure — is encrypted with XChaCha20-Poly1305 using a key derived from your master password via Argon2id (64 MiB, 3 passes, 4 lanes, per [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)'s memory-constrained recommendation). A fresh random nonce is used for every save, and the format header is authenticated as associated data. Nothing about the vault's contents is recoverable from the ciphertext without the master password.
- **File handling:** the vault and its lock file are created with mode `0600`; their parent directory is created `0700`. Symlinked or non-regular vault/lock paths are refused. Writes go to a private temporary file in the same directory, are `fsync`'d, atomically renamed into place, and the parent directory is then synced — the on-disk vault is never partially written or briefly plaintext.
- **Process isolation:** only one SimpleCrypt process can hold a given vault open at a time, enforced with an exclusive advisory lock held for the process's lifetime.
- **In memory:** owned plaintext (the master password, derived key, decrypted records, search queries, and editor drafts) is stored in zeroizing buffers that are cleared on drop, on lock, and on exit — including on panic and on `SIGINT`/`SIGTERM`/`SIGHUP`.

## What is not protected

Zeroization and careful storage handling are **best-effort engineering practices, not guarantees**. They do not protect against:

- **A compromised host.** Malware, a keylogger, or another process with ptrace/memory-inspection access to your user account can read your master password as you type it or your secrets as you view them. SimpleCrypt cannot defend against a compromised operating system.
- **Swap and hibernation.** If your system swaps memory to disk or hibernates while SimpleCrypt is unlocked, plaintext may be written to disk outside SimpleCrypt's control. Use full-disk encryption and disable hibernation if this matters to you.
- **Crash dumps and core files.** A crash handler or `core` dump configured at the OS level can capture process memory, including secrets. SimpleCrypt's own panic handler avoids printing secrets, but it cannot prevent OS-level memory capture.
- **Terminal and multiplexer capture.** Your terminal emulator, a terminal multiplexer (`tmux`/`screen`), and any logging or session-recording tool sitting between SimpleCrypt and your eyes can see everything it renders, including a revealed secret. Scrollback buffers may retain rendered secrets after SimpleCrypt clears its own screen.
- **Every allocator and UI copy.** Rust's standard allocator, the terminal rendering library, and the OS may retain copies of freed memory that a zeroizing wrapper never touches. Zeroization covers SimpleCrypt's own long-lived owners, not every transient copy.
- **Physical access while unlocked.** Anyone who can see your screen while a secret is revealed, or who can use your unlocked session, can read your secrets. Lock (`L`) before stepping away; the default five-minute inactivity timeout is a backstop, not a substitute.
- **Forced termination.** `kill -9`, a power loss, or a host crash can end the process before its cleanup runs. Terminal restoration and in-memory zeroization on exit are best-effort and not guaranteed under a forced kill.
- **Rollback to an old, valid backup.** SimpleCrypt authenticates that a vault file has not been tampered with, but it does not detect being pointed at an older, correctly authenticated copy of your own vault.

## Master password

There is **no password recovery**. If you forget your master password, your vault cannot be decrypted by SimpleCrypt or by its authors. Choose a passphrase you can remember, and keep independent encrypted backups (see the README) somewhere you won't lose them.

## Reporting a concern

This is a personal project without a formal disclosure program. If you find a security problem, please open an issue describing it; avoid including real secrets or vault files in any report.
