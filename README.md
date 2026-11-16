# ClaudeOS image

The system image for a ClaudeOS desktop: Fedora's official
[Sway Atomic 45](https://quay.io/repository/fedora/fedora-sway-atomic) plus

- **labwc** (the window manager) and **gtk4-layer-shell** (for the ClaudeOS top bar)
- the **NVIDIA 580** driver from [RPM Fusion](https://rpmfusion.org) for Pascal cards (GT 1030, GTX 10xx),
  built for this image's exact kernel and signed for Secure Boot with the key in `certs/claudeos-mok.der`

Built daily by GitHub Actions and signed with cosign (`cosign.pub`). Verify:

    cosign verify --key cosign.pub ghcr.io/<owner>/claudeos-image:latest

Hosts switch to it with `rpm-ostree rebase ostree-image-signed:docker://ghcr.io/<owner>/claudeos-image:latest`
after installing `cosign.pub` in their container signature policy, and enrolling `claudeos-mok.der` with
`mokutil --import` (one blue-screen confirmation at the next boot).
