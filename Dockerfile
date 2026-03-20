# Build firewall4ai binary
FROM golang:1.23 AS app-builder
COPY . /src
WORKDIR /src
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /firewall4ai ./cmd/firewall4ai/

# OS image based on Debian 13
FROM debian:13 AS os

# Install kernel, systemd, dracut, grub2 and required tools
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    btrfs-progs \
    ca-certificates \
    curl \
    dbus-daemon \
    dmsetup \
    dnsmasq \
    dosfstools \
    dracut-core \
    dracut-live \
    dracut-squash \
    e2fsprogs \
    eject \
    fdisk \
    findutils \
    gdisk \
    genisoimage \
    grub2-common \
    grub-efi-amd64-signed \
    haveged \
    iproute2 \
    iptables \
    iputils-ping \
    kbd \
    kmod \
    less \
    linux-image-amd64 \
    mtools \
    openssh-server \
    parted \
    shim-signed \
    squashfs-tools \
    systemd \
    systemd-sysv \
    systemd-timesyncd \
    vim \
    xorriso \
    xz-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /etc/ssh/*key* \
    && rm -rf /boot/initrd.img* \
    && echo > /etc/motd

# Hack to prevent systemd-firstboot failures while setting keymap
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=790955
ARG KBD=2.6.4
RUN curl -L https://mirrors.edge.kernel.org/pub/linux/utils/kbd/kbd-${KBD}.tar.xz --output kbd-${KBD}.tar.xz \
    && tar xaf kbd-${KBD}.tar.xz \
    && mkdir -p /usr/share/keymaps \
    && cp -Rp kbd-${KBD}/data/keymaps/* /usr/share/keymaps/ \
    && rm -rf kbd-${KBD}.tar.xz kbd-${KBD}

# Symlink grub2-editenv
RUN ln -sf /usr/bin/grub-editenv /usr/bin/grub2-editenv

# Add elemental CLI
COPY /elemental /usr/bin/elemental

# Add firewall4ai binary
COPY --from=app-builder /firewall4ai /usr/bin/firewall4ai

# Enable systemd-networkd for network management
RUN systemctl enable systemd-networkd.service

# Add systemd-networkd configuration for two-NIC setup
COPY config/network/ /etc/systemd/network/

# Add dnsmasq configuration
COPY config/dnsmasq/firewall4ai.conf /etc/dnsmasq.d/firewall4ai.conf

# Add firewall4ai application configuration
RUN mkdir -p /etc/firewall4ai
COPY config/firewall4ai/config.json /etc/firewall4ai/config.json

# Add iptables rules script
COPY scripts/firewall4ai-iptables.sh /usr/local/bin/firewall4ai-iptables.sh
RUN chmod +x /usr/local/bin/firewall4ai-iptables.sh

# Add systemd services
COPY systemd/firewall4ai.service /usr/lib/systemd/system/firewall4ai.service
COPY systemd/firewall4ai-iptables.service /usr/lib/systemd/system/firewall4ai-iptables.service

# Enable services
RUN systemctl enable dnsmasq.service \
    && systemctl enable firewall4ai.service \
    && systemctl enable firewall4ai-iptables.service \
    && systemctl enable ssh.service

# Set hostname
RUN echo "firewall4ai" > /etc/hostname

# Set DNS resolver (static, dnsmasq handles agent DNS separately)
RUN printf "nameserver 1.1.1.1\nnameserver 1.0.0.1\n" > /etc/resolv.conf

# Create data directory
RUN mkdir -p /var/lib/firewall4ai

# Enable IP forwarding
RUN echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-firewall4ai.conf

# Enable auto-login to console
RUN mkdir -p /etc/systemd/system/getty@tty1.service.d \
    && printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %%I $TERM\n' \
    > /etc/systemd/system/getty@tty1.service.d/override.conf

# Set root password (change on first login)
RUN echo "root:firewall4ai" | chpasswd

# Add snapshotter configuration
COPY config/snapshotter.yaml /etc/elemental/config.d/snapshotter.yaml

# Add elemental configuration
COPY config/config.yaml /etc/elemental/

# Generate initrd with required elemental services
COPY config/50-elemental-initrd.conf /etc/dracut.conf.d/
RUN elemental --debug init -f

# Include bootargs.cfg after elemental init
COPY config/bootargs.cfg /etc/elemental/

# Store version
ARG VERSION=dev
RUN echo IMAGE_TAG=\"${VERSION}\" >> /etc/os-release

# OEM configuration (persistence, layout)
COPY config/oem/ /system/oem/

# Arrange bootloader binaries for elemental installer
RUN mkdir -p /usr/lib/elemental/bootloader && \
    cp /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed /usr/lib/elemental/bootloader/grubx64.efi && \
    cp /usr/lib/shim/shimx64.efi.signed /usr/lib/elemental/bootloader/shimx64.efi && \
    cp /usr/lib/shim/mmx64.efi /usr/lib/elemental/bootloader/mmx64.efi

# Ensure unique machine-id per installation
RUN rm -f /var/lib/dbus/machine-id \
    && ln -s /etc/machine-id /var/lib/dbus/machine-id \
    && rm -f /etc/machine-id

CMD ["/bin/bash"]
