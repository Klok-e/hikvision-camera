# R2 camera network watchdog

This patch adds a connection watchdog to the official DS-2CD2420F-IW R2
V5.4.800 build 210813 image. It retains the vendor kernel, drivers, camera
applications, web interface, and the ownership and permissions of retained files.
It adds `network-watchdog.sh` and appends a background launch command to
`initrun.sh`. It removes the bundled Windows ActiveX installer
`WebComponents.exe` and its startup symlink to reduce the application image size.
The camera no longer provides that Windows plug-in download; the web interface
and camera-side programs remain unchanged.

Only source, tests, and documentation are included in this repository. Original
firmware, generated images, and build manifests are excluded from Git. The
builder does not use third-party firmware releases or connect to a camera.

## Download the original firmware

Download [IPC_R2_EN_STD_5.4.800_210813.zip from Hikvision's official European archive](https://www.hikvisioneurope.com/eu/portal/portal/Technical%20Materials/00%20%20Network%20Camera/00%20%20Product%20Firmware/R2%20platform%20%28DS-2CD1x10%2C1X02%2C1X21%2C2xx0%2C2X14%2C4xx0%2C%20mobile%20IPC%29/V5.4.800%20build210813%20%281xx2%2C1xx0%2C2xx0%29/IPC_R2_EN_STD_5.4.800_210813.zip).
Extract `digicap.dav` from that ZIP and place it at
`firmware/official/digicap.dav`, the builder's default input path. Create
`firmware/official/` if needed. Keep the firmware image itself, not the ZIP, at
that path.

Verify the extracted file before building:

```sh
printf '%s  %s\n' \
  d9dd1fbe0581aec1a931b9743299fec872c58bbb5f71cf2645f4d4ede7d246fb \
  firmware/official/digicap.dav | sha256sum --check
```

The file must be 14,255,820 bytes and the checksum check must report `OK`. The
builder also rejects any input that does not match this exact SHA-256. Firmware
for other platforms or versions is not supported.

## Recovery behavior

- Start checking as soon as the watchdog starts. Ping the local router at
  `192.168.0.1` every 30 seconds, with a three-second
  response timeout. Successful probes reset the failure timer.
- Request a software reboot after ten minutes of continuous probe failures.
  Keep retrying while the router remains unreachable, with at least ten minutes
  between requests, including when a reboot request fails or shutdown is delayed.
- Start a fresh ten-minute failure timer after each camera boot or watchdog
  process restart. This also keeps reboot requests at least ten minutes apart
  across restarts without relying on the camera's wall clock or flash storage.
- Stop requesting reboots when a probe succeeds. A subsequent outage must last
  another ten continuous minutes before it triggers a reboot.
- Keep logs in RAM at `/home/network-watchdog.log`, rotating after 64 lines
  to one `.previous` file. The watchdog does not change Wi-Fi, DHCP, or SSH settings.

The router must respond to ICMP. Change `WD_GATEWAY` in
`firmware/network-watchdog.sh` before building for a different gateway.
Connectivity through an active Ethernet connection also satisfies the probe.
The watchdog uses RAM for timing and logs; it does not write persistent state.

## Build and verify

Requirements: Python with `cryptography`, `fakeroot`, `mkfs.cramfs`, and
`fsck.cramfs`. Run from this directory:

```sh
python firmware/build_firmware.py \
  --watchdog firmware/network-watchdog.sh \
  --output outputs/r2-network-watchdog/digicap.dav

python firmware/build_firmware.py \
  --watchdog firmware/network-watchdog.sh \
  --verify outputs/r2-network-watchdog/digicap.dav

python -m unittest discover -s tests -v
```

The builder refuses to overwrite an existing output or manifest. `fakeroot`
emulates the original ownership inside a temporary build directory; root access
is not required. A syscall sandbox that interferes with ownership emulation may
prevent building, while read-only verification can still run.

The adjacent `.manifest.json` records artifact hashes, all file comparisons,
metadata checks, encrypted SHA-0 manifest verification, and native CramFS
decompression checks.

## Validation boundary

The builder rejects application images larger than the official image. Removing
the installer leaves room for the watchdog within the original image footprint.
Camera boot, behavior during an actual router outage, persistence across a real
reboot, and the recovery procedure remain untested. Software recovery cannot
address a complete operating system hang, and a reboot is not a proven cure for
the original connection fault.

No flashing or upload operation is included in the builder.
