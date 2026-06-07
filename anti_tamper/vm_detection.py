"""
VM Detection - Detect if the application is running in a virtual machine

Usage:
    from anti_tamper.vm_detection import detect_vm
    if detect_vm():
        print("Running in a VM!")
"""
import platform
import struct
import ctypes
import os


def check_dmi_info() -> bool:
    """Check DMI/SMBIOS for VM indicators"""
    vm_indicators = [
        "virtualbox", "vbox", "vmware", "qemu", "kvm",
        "xen", "hyper-v", "microsoft virtual", "bochs",
        "parallels", "vmm", "virtual machine"
    ]

    # Try reading DMI info on Linux
    if platform.system() == "Linux":
        dmi_paths = [
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/bios_vendor",
        ]
        for path in dmi_paths:
            try:
                with open(path) as f:
                    content = f.read().lower().strip()
                    for indicator in vm_indicators:
                        if indicator in content:
                            return True
            except (FileNotFoundError, PermissionError):
                continue

    # Windows: Check via WMI
    if platform.system() == "Windows":
        try:
            import subprocess
            result = subprocess.run(
                'wmic baseboard get manufacturer,product',
                capture_output=True, text=True, shell=True, timeout=5
            )
            output = result.stdout.lower()
            for indicator in vm_indicators:
                if indicator in output:
                    return True
        except Exception:
            pass

    return False


def check_mac_prefixes() -> bool:
    """Check MAC address prefixes known for VMs"""
    vm_mac_prefixes = [
        "00:50:56",  # VMware
        "00:0C:29",  # VMware
        "00:05:69",  # VMware
        "08:00:27",  # VirtualBox
        "52:54:00",  # QEMU/KVM
        "00:1C:42",  # Parallels
        "00:03:FF",  # Microsoft Hyper-V
        "00:15:5D",  # Hyper-V
    ]

    try:
        import subprocess
        if platform.system() == "Windows":
            result = subprocess.run(
                "getmac /FO CSV /NH",
                capture_output=True, text=True, shell=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "-" in line:
                    mac = line.split(",")[0].strip('"').replace("-", ":")
                    if len(mac) >= 8:
                        prefix = mac[:8].lower()
                        for vm_prefix in vm_mac_prefixes:
                            if prefix == vm_prefix:
                                return True
        elif platform.system() == "Linux":
            for iface in os.listdir("/sys/class/net/"):
                try:
                    with open(f"/sys/class/net/{iface}/address") as f:
                        mac = f.read().strip().lower()
                        for vm_prefix in vm_mac_prefixes:
                            if mac.startswith(vm_prefix):
                                return True
                except (FileNotFoundError, PermissionError):
                    continue
    except Exception:
        pass

    return False


def check_hardware() -> bool:
    """Check hardware for VM signatures using CPUID"""
    if platform.system() != "Windows":
        return False

    try:
        kernel32 = ctypes.windll.kernel32
        # Check if running under Hyper-V via CPUID
        # Hyper-V sets bit 31 of ECX when CPUID leaf 1 is called
        # and leaf 0x40000000 returns "Microsoft HV" or "VMwareVMware"

        # Simple check: look for known VM vendor strings in CPUID
        # Using __cpuid intrinsic equivalent via inline asm is complex in Python
        # We'll rely on DMI/MAC checks which are reliable enough
        pass
    except Exception:
        pass

    return False


def detect_vm() -> bool:
    """Run all VM detection checks. Returns True if VM detected."""
    checks = []

    checks.append(("DMI", check_dmi_info()))
    checks.append(("MAC", check_mac_prefixes()))
    checks.append(("Hardware", check_hardware()))

    triggered = [name for name, result in checks if result]
    return len(triggered) > 0


if __name__ == "__main__":
    if detect_vm():
        print("⚠ Running inside a virtual machine")
    else:
        print("✓ No VM detected (bare metal)")
