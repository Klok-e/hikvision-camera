#!/bin/sh

WD_GATEWAY=192.168.0.1
WD_FAILURE_SECONDS=600
WD_INTERVAL=30
WD_LOG=/home/network-watchdog.log
WD_UPTIME_FILE=/proc/uptime

wd_now() {
    read -r wd_uptime wd_unused < "$WD_UPTIME_FILE" || return 1
    printf '%s\n' "${wd_uptime%%.*}"
}

wd_pause() {
    sleep "$1"
}

wd_probe() {
    ping -q -c 1 -W 3 "$WD_GATEWAY" >/dev/null 2>&1
}

wd_reboot() {
    reboot
}

wd_log() {
    wd_log_lines=0
    if [ -f "$WD_LOG" ]; then
        while IFS= read -r wd_log_line; do
            wd_log_lines=$((wd_log_lines + 1))
            [ "$wd_log_lines" -ge 64 ] && break
        done < "$WD_LOG"
        if [ "$wd_log_lines" -ge 64 ]; then
            mv -f "$WD_LOG" "$WD_LOG.previous" || return 1
        fi
    fi
    printf '[uptime %s] %s\n' "${WD_TICK_NOW:-startup}" "$*" >> "$WD_LOG"
}

wd_prepare() {
    umask 077
    WD_FAILURE_SINCE=
}

wd_tick() {
    WD_TICK_NOW=$1
    if [ "$2" = up ]; then
        if [ -n "$WD_FAILURE_SINCE" ]; then
            wd_log 'router reachable again'
        fi
        WD_FAILURE_SINCE=
        return 0
    fi

    if [ -z "$WD_FAILURE_SINCE" ]; then
        WD_FAILURE_SINCE=$WD_TICK_NOW
        wd_log 'router unreachable; waiting before recovery'
    fi
    if [ "$((WD_TICK_NOW - WD_FAILURE_SINCE))" -lt "$WD_FAILURE_SECONDS" ]; then
        return 0
    fi
    # Reset before requesting a reboot: the command may fail or return before shutdown.
    # A fresh process/boot also waits a complete failure interval before its first request.
    WD_FAILURE_SINCE=$WD_TICK_NOW
    wd_log 'sustained router failure; requesting recovery reboot'
    if ! wd_reboot; then
        wd_log 'reboot request failed; waiting before retrying'
    fi
    return 0
}

wd_main() {
    PATH=/sbin:/bin:/usr/sbin:/usr/bin
    export PATH
    wd_prepare || return 1
    while :; do
        if wd_probe; then
            WD_STATUS=up
        else
            WD_STATUS=down
        fi
        WD_TICK_NOW=$(wd_now) || return 1
        case "$WD_TICK_NOW" in
            ''|*[!0-9]*) wd_log 'disabled: invalid monotonic clock'; return 1 ;;
        esac
        wd_tick "$WD_TICK_NOW" "$WD_STATUS"
        wd_pause "$WD_INTERVAL" || return 1
    done
}

case "${1-}" in
    --library) ;;
    '') wd_main ;;
    *) exit 2 ;;
esac
