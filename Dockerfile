# OS image based on Debian 13
FROM debian:trixie-slim AS os

# Install kernel, systemd, dracut, grub2 and required tools
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    apparmor \
    bash-completion \
    bridge-utils \
    bsdextrautils \
    btrfsmaintenance \
    btrfs-progs \
    ca-certificates \
    curl \
    dbus-daemon \
    dmsetup \
    ipxe \
    debootstrap \
    dosfstools \
    dracut-core \
    dracut-live \
    dracut-network \
    dracut-squash \
    e2fsprogs \
    eject \
    findutils \
    fdisk \
    gdisk \
    genisoimage \
    gpg \
    grub2-common \
    grub-efi-amd64-signed \
    haveged \
    htop \
    iproute2 \
    iptables \
    iputils-ping \
    kbd \
    kmod \
    less \
    linux-image-amd64 \
    linux-perf \
    lldpd \
    locales \
    lvm2 \
    mtools \
    net-tools \
    networkd-dispatcher \
    openssh-client \
    openssh-server \
    parted \
    patch \
    pciutils \
    polkitd \
    psmisc \
    rsync \
    shim-signed \
    squashfs-tools \
    systemd \
    systemd-sysv \
    systemd-timesyncd \
    tcpdump \
    tzdata \
    vim \
    wget \
    xorriso \
    xz-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /etc/ssh/*key* \
    && rm -rf /etc/mdadm \
    && rm -rf /boot/initrd.img* \
    && echo > /etc/motd
COPY /config/.vimrc /root/.vimrc

# Hack to prevent systemd-firstboot failures while setting keymap
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=790955
ARG KBD=2.6.4
RUN curl -L https://mirrors.edge.kernel.org/pub/linux/utils/kbd/kbd-${KBD}.tar.xz --output kbd-${KBD}.tar.xz \
    && tar xaf kbd-${KBD}.tar.xz \
    && mkdir -p /usr/share/keymaps \
    && cp -Rp kbd-${KBD}/data/keymaps/* /usr/share/keymaps/ \
    && rm -rf kbd-${KBD}.tar.xz kbd-${KBD}

# Disable audit message spam to console
RUN systemctl mask systemd-journald-audit.socket

# Symlink grub2-editenv
RUN ln -sf /usr/bin/grub-editenv /usr/bin/grub2-editenv

# Add elemental CLI
COPY /elemental /usr/bin/elemental

# Enable systemd-networkd for network management
RUN systemctl enable systemd-networkd.service

# Add systemd-networkd configuration for two-NIC setup
COPY config/network/ /etc/systemd/network/

# Copy iPXE boot files for PXE netboot support
RUN mkdir -p /var/lib/firewall4ai/netboot/tftp \
    && cp /usr/lib/ipxe/undionly.kpxe /var/lib/firewall4ai/netboot/tftp/ 2>/dev/null || true \
    && cp /usr/lib/ipxe/ipxe.efi /var/lib/firewall4ai/netboot/tftp/ 2>/dev/null || true \
    && cp /boot/ipxe.efi /var/lib/firewall4ai/netboot/tftp/ 2>/dev/null || true \
    && cp /usr/lib/IPXE/ipxe.efi /var/lib/firewall4ai/netboot/tftp/ 2>/dev/null || true

# Add iptables rules script
COPY scripts/firewall4ai-iptables.sh /usr/local/bin/firewall4ai-iptables.sh
RUN chmod +x /usr/local/bin/firewall4ai-iptables.sh

# Add systemd services
COPY systemd/firewall4ai.service /usr/lib/systemd/system/firewall4ai.service
COPY systemd/firewall4ai-iptables.service /usr/lib/systemd/system/firewall4ai-iptables.service

# Enable services (DHCP/DNS/TFTP are now integrated into firewall4ai binary)
RUN systemctl enable firewall4ai.service \
    && systemctl enable firewall4ai-iptables.service \
    && systemctl enable ssh.service

# Create data directory
RUN mkdir -p /var/lib/firewall4ai

# Enable IP forwarding
RUN echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-firewall4ai.conf

# Enable auto-login to console
RUN mkdir -p /etc/systemd/system/getty@tty1.service.d \
    && printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %%I $TERM\n' \
    > /etc/systemd/system/getty@tty1.service.d/override.conf

# Add snapshotter configuration
COPY config/snapshotter.yaml /etc/elemental/config.d/snapshotter.yaml

# Add elemental configuration
COPY config/config.yaml /etc/elemental/

# Generate initrd with required elemental services
COPY config/50-elemental-initrd.conf /etc/dracut.conf.d/
RUN elemental --debug init -f

# DNS resolution: use upstream DNS directly (DHCP/DNS now integrated)
COPY config/resolv.conf /etc/resolv.conf

# Include bootargs.cfg after elemental init
COPY config/bootargs.cfg /etc/elemental/

# OEM configuration (persistence, layout)
COPY config/oem/ /system/oem/

# Arrange bootloader binaries into /usr/lib/elemental/bootloader
# this way elemental installer can easily fetch them
RUN mkdir -p /usr/lib/elemental/bootloader && \
    cp /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed /usr/lib/elemental/bootloader/grubx64.efi && \
    cp /usr/lib/shim/shimx64.efi.signed /usr/lib/elemental/bootloader/shimx64.efi && \
    cp /usr/lib/shim/mmx64.efi /usr/lib/elemental/bootloader/mmx64.efi

# Ensure unique machine-id per installation
RUN rm -f /var/lib/dbus/machine-id \
    && ln -s /etc/machine-id /var/lib/dbus/machine-id \
    && rm -f /etc/machine-id

# Store version
ARG VERSION=dev
RUN echo IMAGE_TAG=\"${VERSION}\" >> /etc/os-release

# Build firewall4ai binary
FROM golang:1.26.1 AS app-builder
COPY . /src
WORKDIR /src
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /firewall4ai ./cmd/firewall4ai/

FROM os
COPY --from=app-builder /firewall4ai /usr/bin/firewall4ai

# Add firewall4ai application configuration
RUN mkdir -p /etc/firewall4ai
COPY config/firewall4ai/config.json /etc/firewall4ai/config.json

CMD ["/bin/bash"]
