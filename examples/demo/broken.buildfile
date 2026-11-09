# Original synthetic review fixture. Not a bootable image.
[virtual=x86_64,bios] .boot = {
    startup-x86
    PATH=/proc/boot:/bin
    procnto-smp-instr
}
[search=payload]
[+include] components.buildfile
/etc/telemetry.conf = {
interval=5
}
/etc/telemetry.conf = {
interval=60
}
[type=link] /var/log = /tmp/log
/var/log/startup.txt = payload/notice.stub
[perms=04777 uid=0] /proc/boot/diagnostic = diagnostic.stub
[+script] .script = {
    display_msg Starting synthetic demo
    [uid=100] telemetry &
    on -u 0 /proc/boot/auditor &
    on -u 100:100 /proc/boot/telemetry &
    [+external] waitfor /dev/storage
    collector_missing &
}
