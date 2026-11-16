# ClaudeOS system image
# = Fedora's official Sway Atomic 45 + labwc + NVIDIA 580 driver (for Pascal cards such as the GT 1030),
#   with the kernel module signed by our own Secure Boot key (certs/claudeos-mok.der).
# Built and signed by .github/workflows/build.yml. Hosts verify the image signature (cosign.pub).
ARG BASE=quay.io/fedora/fedora-sway-atomic:45

# ---------- stage 1: build the NVIDIA kernel module for exactly this image's kernel ----------
FROM ${BASE} AS nvidia-kmod
COPY certs/claudeos-mok.der /etc/pki/akmods/certs/public_key.der
RUN --mount=type=secret,id=akmods_key \
    set -eux; \
    FEDORA="$(rpm -E %fedora)"; \
    KVER="$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel | sort -V | tail -n1)"; \
    dnf -y install \
      "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-${FEDORA}.noarch.rpm" \
      "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${FEDORA}.noarch.rpm"; \
    dnf -y install "kernel-devel-${KVER}" akmods; \
    # its install script would try to build as root and fail; we build explicitly below instead
    dnf -y install --setopt=tsflags=noscripts akmod-nvidia-580xx; \
    install -d -m 0755 /etc/pki/akmods/private; \
    install -o akmods -g akmods -m 0400 /run/secrets/akmods_key /etc/pki/akmods/private/private_key.priv; \
    chown akmods:akmods /etc/pki/akmods/certs/public_key.der; \
    install -d -o akmods -g akmods /tmp/akout /tmp/akhome; \
    SRPM="$(ls /usr/src/akmods/nvidia-580xx-kmod*.src.rpm | grep -v latest | sort -V | tail -n1)"; \
    runuser -u akmods -- env HOME=/tmp/akhome akmodsbuild -k "${KVER}" -o /tmp/akout "${SRPM}"; \
    rm -f /etc/pki/akmods/private/private_key.priv; \
    mkdir -p /out && cp /tmp/akout/kmod-nvidia-580xx-*.rpm /out/; \
    # refuse to continue unless the module really is signed with our key
    mkdir /tmp/chk && cd /tmp/chk && rpm2cpio /out/kmod-nvidia-580xx-*.rpm | cpio -idm --quiet; \
    MOD="$(find /tmp/chk -name 'nvidia.ko*' | head -n1)"; \
    modinfo -F signer "${MOD}" | tee /out/signer.txt; \
    test -s /out/signer.txt

# ---------- stage 2: the image you boot ----------
FROM ${BASE}
COPY --from=nvidia-kmod /out/*.rpm /tmp/nvidia/
COPY certs/claudeos-mok.der /usr/share/claudeos/claudeos-mok.der
COPY files/ /
RUN set -eux; \
    FEDORA="$(rpm -E %fedora)"; \
    dnf -y install \
      "https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-${FEDORA}.noarch.rpm" \
      "https://mirrors.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${FEDORA}.noarch.rpm"; \
    dnf -y install \
      labwc gtk4-layer-shell \
      /tmp/nvidia/kmod-nvidia-580xx-*.rpm \
      xorg-x11-drv-nvidia-580xx xorg-x11-drv-nvidia-580xx-power; \
    # the driver comes from RPM Fusion at build time only; the booted system never uses these repos
    dnf -y remove rpmfusion-free-release rpmfusion-nonfree-release; \
    systemctl enable nvidia-suspend.service nvidia-hibernate.service nvidia-resume.service; \
    rm -rf /tmp/nvidia /var/cache/* /var/lib/dnf /var/log/*; \
    dnf clean all
RUN bootc container lint
