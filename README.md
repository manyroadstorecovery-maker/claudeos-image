# ClaudeOS image

The system image for a ClaudeOS desktop: Fedora's official
[Sway Atomic 45](https://quay.io/repository/fedora/fedora-sway-atomic) plus

- **labwc** (the window manager) and **gtk4-layer-shell** (for the ClaudeOS top bar)
- the **NVIDIA 580** driver from [RPM Fusion](https://rpmfusion.org) for Pascal cards (GT 1030, GTX 10xx),
  built for this image's exact kernel and signed for Secure Boot with the key in `certs/claudeos-mok.der`
- the **ClaudeOS system pieces**, read-only in `/usr` (see `files/`): the Claude Code guard hook and its
  managed settings, `claudeos-apply`, hourly `/home` snapshots, the append-only audit-log rotation, the
  network sentinel, stricter polkit rules, no LLMNR/mDNS/Avahi, OS updates only on request (no automatic ones), daily Flatpak
  updates (which also keep Flatpak's NVIDIA driver copy matched to the kernel driver), and the labwc
  session + GT 1030 login-screen wrappers. Signature policy for this image ships in `/etc`.

Most files in `files/` are copied from the private ClaudeOS repo by its `system/image-sync.sh`,
where their tests live; edit them there, not here.

Built weekly (and on every change) by GitHub Actions and signed with cosign (`cosign.pub`). Verify:

    cosign verify --key cosign.pub ghcr.io/<owner>/claudeos-image:latest

Hosts switch to it with `rpm-ostree rebase ostree-image-signed:docker://ghcr.io/<owner>/claudeos-image:latest`
after installing `cosign.pub` in their container signature policy, and enrolling `claudeos-mok.der` with
`mokutil --import` (one blue-screen confirmation at the next boot).
