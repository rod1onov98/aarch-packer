# aarch-packer
aarch-packer — post-build ELF protector for android native libraries. encrypts .text section with chacha20, decrypts at runtime via raw syscalls (bypasses SELinux mprotect restrictions). supports arm32 and arm64, no root required.
