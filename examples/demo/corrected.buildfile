# Original synthetic review fixture after configuration corrections.
# Placeholder payloads are text, not executables. Not a bootable image.
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
[type=dir] /var/log
/var/log/startup.txt = notice.stub
[perms=0750 uid=100 gid=100] /proc/boot/diagnostic = diagnostic.stub
[+script] .script = {
    display_msg Starting synthetic demo
    on -u 100:100 /proc/boot/telemetry &
    waitfor /dev/storage 5.0
    diagnostic &
}
