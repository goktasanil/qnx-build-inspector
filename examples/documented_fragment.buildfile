# Short excerpt (23 whitespace-delimited tokens) from QNX SDP 8.0
# Minimal configuration; attribution and URL in docs/SOURCES.md.
# Fragment for parser testing, not a complete runnable image.
[virtual=x86_64,bios +compress] boot = {
    startup-x86 -v
    PATH=/proc/boot
    LD_LIBRARY_PATH=/proc/boot
    procnto-smp-instr
}
[+script] startup-script = {
    devc-ser8250 &
    reopen /dev/ser1
    [+session] sh &
}
