#!/usr/bin/env python3
"""
SWCLI - Sidewinder Command Line Interface Toolkit
Implements human-driven attack pipelines requiring explicit confirmation.
"""
import argparse
import asyncio
import sys
import os
import shutil
import subprocess

try:
    from sidewinder.adapters import AdapterManager
    from sidewinder.core.monitor import enter_monitor_mode, exit_monitor_mode, get_interface_mode_sync
    from sidewinder.core.scanner import ScanEngine
    from sidewinder.core.services import get_service_manager
    from sidewinder.core.capture import capture_passive, capture_deauth, validate_handshake
    from sidewinder.core.cracker import crack_aircrack, crack_hashcat, find_wordlists
    from sidewinder.core.intelligence import IntelligenceEngine
    from sidewinder.core.cleanup import get_cleanup_manager
    from sidewinder.core.session import Session
    from sidewinder.core.config import SidewinderConfig
    from sidewinder.core.errors import SidewinderError
    from sidewinder.attacks.deauth import run_deauth, DeauthConfig
    from sidewinder.attacks.evil_twin import EvilTwinEngine
    from sidewinder.attacks.wps import WPSEngine
    from sidewinder.attacks.pmkid import PMKIDEngine
    from sidewinder.core.attack import AttackConfig
    SIDEWINDER_AVAILABLE = True
except ImportError:
    SIDEWINDER_AVAILABLE = False


def print_error(msg):
    print(f"\033[91m[ERROR]\033[0m {msg}", file=sys.stderr)

def print_info(msg):
    print(f"\033[94m[INFO]\033[0m {msg}")

def print_success(msg):
    print(f"\033[92m[SUCCESS]\033[0m {msg}")

def print_warning(msg):
    print(f"\033[93m[WARNING]\033[0m {msg}")

def confirm_action(prompt: str) -> bool:
    """Prompt the user for [y/N] confirmation."""
    try:
        ans = input(f"{prompt} [y/N]: ").strip().lower()
        return ans in ('y', 'yes')
    except (KeyboardInterrupt, EOFError):
        return False

def check_sidewinder():
    if not SIDEWINDER_AVAILABLE:
        print_error("Sidewinder core module is not installed or accessible.")
        sys.exit(1)


# --- 0. PREFLIGHT ---

def handle_root(args):
    if os.geteuid() == 0:
        print_success("Running as root")
    else:
        print_error("Not running as root — many commands will fail")
        print("      Run: sudo swcli ...")

def handle_deps(args):
    reqs = ["airodump-ng", "aireplay-ng", "aircrack-ng", "iw", "ip"]
    opts = ["hashcat", "hcxpcapngtool", "airbase-ng", "reaver", "dnsmasq"]
    
    print("REQUIRED:")
    req_ok = 0
    for r in reqs:
        p = shutil.which(r)
        if p:
            print(f"  [OK] {r:<15} {p}")
            req_ok += 1
        else:
            print(f"  [--] {r:<15} NOT FOUND")
            
    print("\nOPTIONAL (for specific attacks):")
    opt_ok = 0
    for o in opts:
        p = shutil.which(o)
        if p:
            print(f"  [OK] {o:<15} {p}")
            opt_ok += 1
        else:
            print(f"  [--] {o:<15} NOT FOUND")
            
    print(f"\nSUMMARY: {req_ok}/{len(reqs)} required, {opt_ok}/{len(opts)} optional")

def handle_rfkill(args):
    if getattr(args, "rfkill_cmd", None) == "unblock":
        target = args.target if args.target else "all"
        if not confirm_action(f"Unblock wifi on {target}?"):
            print_info("Aborted")
            return
        cmd = ["rfkill", "unblock", "wifi"] if target == "all" else ["rfkill", "unblock", target]
        subprocess.run(cmd)
        print_success(f"Unblocked {target}")
    else:
        subprocess.run(["rfkill", "list", "wifi"])
        print("\nTo unblock: swcli rfkill unblock <phy>")
        print("To unblock all: swcli rfkill unblock")


# --- 1. HARDWARE ---

async def handle_adapters(args):
    check_sidewinder()
    manager = AdapterManager()
    adapters = await manager.discover()
    
    if args.info == "info":
        if not args.info_iface or args.info_iface not in adapters:
            print_error(f"Adapter not found or missing interface name.")
            return
        info = adapters[args.info_iface]
        print(f"Interface:      {info.iface}")
        print(f"PHY:            {info.phy}")
        print(f"Chipset:        {info.chipset}")
        print(f"Driver:         {info.driver}")
        print(f"Bus:            {info.bus}")
        print(f"MAC:            {info.mac}")
        print(f"Bands:          {', '.join(info.bands)}")
        print(f"Current Mode:   {info.current_mode}")
        print(f"Monitor:        {'YES' if info.monitor_capable else 'NO'}")
        print(f"Injection:      {'YES' if info.injection_capable else 'NO'}")
        print(f"Status:         {info.status}")
        return

    print(f"{'#':<3} {'Interface':<15} {'Chipset':<12} {'Driver':<12} {'Bus':<5} {'Mode':<8} {'Bands':<8} {'Monitor':<7} {'Inject':<7} {'Status'}")
    for i, (iface, info) in enumerate(adapters.items(), 1):
        bands = "/".join(info.bands)
        print(f"{i:<3} {info.iface:<15} {info.chipset:<12} {info.driver:<12} {info.bus:<5} {info.current_mode:<8} {bands:<8} {'YES' if info.monitor_capable else 'NO':<7} {'YES' if info.injection_capable else 'NO':<7} {info.status}")
    print(f"\nTotal: {len(adapters)} adapters found")
    print("Use: swcli monitor <interface> to enter monitor mode")

async def handle_kill(args):
    check_sidewinder()
    manager = get_service_manager()
    print_info("Checking for conflicting services...")
    result = await manager.find_conflicting()
    if not result:
        print_info("No conflicting services found.")
        return
        
    print("Conflicting services found:")
    for svc in result:
        print(f"  PID {svc.pid} - {svc.name}")
        
    print("\nWARNING: This will disconnect you from WiFi.")
    if confirm_action("Kill these services?"):
        killed = await manager.kill_conflicting()
        for p in killed.killed:
            print_success(f"Stopped: {p.name} (pid={p.pid})")
        print("\nServices tracked for restore.")
        print("Run: swcli restore to bring them back.")
    else:
        print_info("Aborted — no services killed")

async def handle_restore(args):
    check_sidewinder()
    manager = get_service_manager()
    if not manager.killed_processes:
        print_info("No services to restore")
        return
        
    print("Services to restore:")
    for p in manager.killed_processes:
        print(f"  - {p.name}")
        
    if confirm_action("Restore these services?"):
        await manager.restore()
        print_success("Services restored.")
    else:
        print_info("Aborted — services remain stopped")


# --- 2. MONITOR ---

async def handle_monitor(args):
    check_sidewinder()
    cmd = getattr(args, "monitor_cmd", None)
    
    if cmd == "stop":
        print(f"Stop monitor mode on {args.mon}?")
        if confirm_action("This will restore managed mode."):
            try:
                await exit_monitor_mode(args.mon, args.interface or "", args.phy or "")
                print_success("Monitor mode stopped")
            except SidewinderError as e:
                print_error(f"{e.what} - {e.why}")
        else:
            print_info("Aborted")
    elif cmd == "status":
        mode = get_interface_mode_sync(args.iface)
        print(f"Interface: {args.iface}\nMode:      {mode}")
    else:
        if not args.iface:
            print_error("Missing argument <interface>")
            return
        # Start monitor mode
        print(f"Adapter:  {args.iface}")
        print(f"Channel:  {args.channel}")
        print("\nThis will bring the interface down, create a monitor VIF, and set channel/txpower.")
        if confirm_action("Continue?"):
            try:
                mon_iface = await enter_monitor_mode(args.iface, "", args.channel)
                print_success(f"Monitor mode active: {mon_iface}")
                print(f"Channel: {args.channel}")
            except SidewinderError as e:
                print_error(f"{e.what} - {e.why}")
        else:
            print_info("Aborted")


# --- 3. SCAN ---

async def handle_scan(args):
    check_sidewinder()
    cmd = getattr(args, "scan_cmd", None)
    
    if cmd == "results":
        engine = ScanEngine()
        nets = engine.get_networks()
        print(f"Scan results (saved to session):\n")
        print(f"{'#':<3} {'BSSID':<18} {'CH':<3} {'Signal':<7} {'Privacy':<8} {'ESSID':<20} {'WPS'}")
        for i, n in enumerate(nets, 1):
            print(f"{i:<3} {n.bssid:<18} {n.channel:<3} {n.signal:<7} {n.privacy:<8} {n.display_name():<20} {'Yes' if n.wps else 'No'}")
        return

    if not args.mon:
        print_error("Missing argument <mon_interface>")
        return

    # Start scan
    print(f"Scan WiFi on {args.mon}?")
    print(f"Band: {args.band}")
    if args.channels:
        print(f"Channels: {args.channels}")
        
    if not confirm_action("\nStart scan?"):
        print_info("Aborted")
        return
        
    engine = ScanEngine()
    channels = [int(c) for c in args.channels.split(",")] if args.channels else None
    
    print_info("Starting background scan... Press Ctrl+C to stop.")
    def on_network(net):
        print(f"[NET] {net.bssid} | PWR: {net.signal} | CH: {net.channel} | ESSID: {net.display_name()}")
        
    def on_client(cli):
        print(f"[CLI] {cli.mac} -> {cli.bssid} | PWR: {cli.signal} | PROBE: {cli.probe}")
        
    try:
        await engine.scan(
            mon_iface=args.mon,
            capture_prefix="/tmp/sidewinder_scan",
            band=args.band,
            channels=channels,
            on_network=on_network,
            on_client=on_client
        )
    except KeyboardInterrupt:
        print_info("\nScan stopped by user.")
        await engine.stop_and_wait()
        print_info("Run 'swcli results' to view captured data.")


# --- 4. CAPTURE ---

async def handle_capture(args):
    check_sidewinder()
    cmd = args.capture_cmd
    
    if cmd == "validate":
        print_info(f"Validating {args.cap}...")
        res = validate_handshake(args.cap)
        if res:
            print(f"\nMessage Status:")
            print(f"  M1: {'✓' if res.m1 else '✗'}")
            print(f"  M2: {'✓' if res.m2 else '✗'}")
            print(f"  M3: {'✓' if res.m3 else '✗'}")
            print(f"  M4: {'✓' if res.m4 else '✗'}")
            print(f"\nStatus:     {res.status.upper()}")
            print(f"SHA-256:    {res.sha256}")
            print(f"EAPOL frames: {res.eapol_count}")
        else:
            print_error("Validation returned no result or invalid format.")
        return

    elif cmd == "passive":
        print(f"Passive capture on:")
        print(f"  Interface:  {args.mon}")
        print(f"  Target:     {args.bssid}")
        print(f"  Channel:    {args.ch}")
        print(f"  Timeout:    {args.timeout}s")
        print("\nThis will listen for a WPA handshake without sending any packets.")
        if not confirm_action("Start capture?"):
            print_info("Aborted")
            return
            
        res = await capture_passive(
            mon_iface=args.mon,
            bssid=args.bssid,
            channel=args.ch,
            output_prefix=args.output,
            timeout=args.timeout
        )
        if res:
            print_success(f"Capture finished. Status: {res.status}")
        else:
            print_warning("No handshake captured before timeout.")

    elif cmd == "deauth":
        print(f"Deauth + Capture:")
        print(f"  Interface:  {args.mon}")
        print(f"  Target:     {args.bssid}")
        print(f"  Channel:    {args.ch}")
        print(f"  Client:     {args.client}")
        print(f"  Deauths:    {args.count} frames × {args.bursts} bursts = {args.count * args.bursts} total")
        print(f"  Timeout:    {args.timeout}s")
        print("\nWARNING: This will send deauthentication frames and disconnect clients.")
        if not confirm_action("Start deauth attack?"):
            print_info("Aborted")
            return
            
        res = await capture_deauth(
            mon_iface=args.mon,
            bssid=args.bssid,
            client=args.client,
            channel=args.ch,
            output_prefix=args.output,
            count=args.count,
            timeout=args.timeout
        )
        if res and res.handshake:
            print_success(f"Capture finished. Status: {res.handshake.status}")
        else:
            print_error("Deauth attack failed to capture handshake.")
            
    elif cmd == "pmkid":
        print(f"PMKID capture:")
        print(f"  Interface:  {args.mon}")
        print(f"  Target:     {args.bssid}")
        print(f"  Channel:    {args.ch}")
        print(f"  Timeout:    {args.timeout}s")
        print("\nThis attempts to capture the PMKID hash directly from the AP. Requires hcxdumptool.")
        if not confirm_action("Start PMKID capture?"):
            print_info("Aborted")
            return
            
        engine = PMKIDEngine()
        cfg = AttackConfig(target_bssid=args.bssid, channel=args.ch, timeout=args.timeout)
        try:
            res = await engine.start(cfg, mon_iface=args.mon)
            if res.success:
                print_success(f"PMKID captured successfully!")
                print(f"Hash file: {res.stats.get('hash_file', 'unknown')}")
            else:
                print_error("Failed to capture PMKID.")
        except Exception as e:
            print_error(f"Error during PMKID capture: {e}")


# --- 5. ATTACK ---

async def handle_attack(args):
    check_sidewinder()
    cmd = args.attack_cmd
    
    if cmd == "evil-twin":
        print("Evil Twin attack:")
        print(f"  Interface:  {args.mon}")
        print(f"  ESSID:      {args.essid}")
        print(f"  Channel:    {args.ch}")
        if args.bssid: print(f"  Clone BSSID: {args.bssid}")
        print("\nWARNING: This creates a rogue Access Point.")
        if not confirm_action("Start Evil Twin?"): return
        
        engine = EvilTwinEngine()
        cfg = AttackConfig(target_bssid=args.bssid or "00:00:00:00:00:00", channel=args.ch)
        print_info("Starting Evil Twin engine... Press Ctrl+C to stop.")
        try:
            await engine.start(cfg, mon_iface=args.mon, essid=args.essid)
        except KeyboardInterrupt:
            await engine.stop()
            print_info("Evil Twin stopped.")
            
    elif cmd == "wps":
        print("WPS Pixie-Dust attack:")
        print(f"  Interface:  {args.mon}")
        print(f"  Target:     {args.bssid}")
        print(f"  Channel:    {args.ch}")
        print("\nRequires: reaver. Target must have WPS enabled.")
        if not confirm_action("Start WPS attack?"): return
        
        engine = WPSEngine()
        cfg = AttackConfig(target_bssid=args.bssid, channel=args.ch)
        try:
            res = await engine.start(cfg, mon_iface=args.mon)
            if res.success:
                print_success("WPS Attack succeeded!")
                print(f"PIN: {res.stats.get('pin')}")
                print(f"PSK: {res.stats.get('psk')}")
            else:
                print_error("WPS attack failed or timed out.")
        except KeyboardInterrupt:
            await engine.stop()


# --- 6. CRACK ---

async def handle_crack(args):
    check_sidewinder()
    cmd = args.crack_cmd
    if cmd == "wordlists":
        wls = find_wordlists()
        print("Available wordlists:\n")
        for i, w in enumerate(wls, 1):
            size = os.path.getsize(w) if os.path.exists(w) else 0
            print(f"{i:<3} {w:<60} {size:,} bytes")
            
    elif cmd == "aircrack":
        print("Crack with aircrack-ng:")
        print(f"  Capture:   {args.cap}")
        print(f"  Target:    {args.bssid}")
        print(f"  Wordlist:  {args.wl}")
        if not confirm_action("\nStart cracking?"): return
        
        res = await crack_aircrack(args.cap, args.bssid, args.wl)
        if res.found:
            print_success(f"KEY FOUND! [ {res.password} ]")
        else:
            print_error("Password not found in wordlist.")
            
    elif cmd == "hashcat":
        print("Crack with hashcat (GPU):")
        print(f"  Capture:   {args.cap}")
        print(f"  Wordlist:  {args.wl}")
        print("\nRequires: hashcat, hcxpcapngtool")
        if not confirm_action("\nConvert and start cracking?"): return
        
        res = await crack_hashcat(args.cap, args.wl)
        if res.found:
            print_success(f"PASSWORD FOUND! [ {res.password} ]")
        else:
            print_error("Password not found in wordlist.")


# --- 7. CLEANUP ---

async def handle_cleanup(args):
    check_sidewinder()
    cmd = getattr(args, "cleanup_cmd", None)
    mgr = get_cleanup_manager()
    
    if cmd == "procs":
        print_info("Killing attack processes...")
        for p in ["airodump-ng", "aireplay-ng", "hashcat", "aircrack-ng"]:
            subprocess.run(["pkill", "-9", "-f", p], stderr=subprocess.DEVNULL)
            print(f"  [+] Sent SIGKILL to {p}")
            
    elif cmd == "files":
        if args.dry_run:
            print_info("Dry run: showing files that would be deleted")
            await mgr.cleanup_files(dry_run=True)
        else:
            if confirm_action("Delete temp files (/tmp/sidewinder_*)?"):
                await mgr.cleanup_files(dry_run=False)
                print_success("Temp files deleted.")
    else:
        # Full cleanup
        print("Full cleanup will:")
        print("  1. Kill attack processes")
        print("  2. Exit monitor mode")
        print("  3. Restore NetworkManager, wpa_supplicant")
        print("  4. Delete /tmp/sidewinder_* temp files")
        if not confirm_action("\nRun full cleanup?"): return
        
        await mgr.full_cleanup("", "", "")
        print_success("Cleanup complete.")


# --- 8 & 9. SESSION / CONFIG ---

async def handle_session(args):
    check_sidewinder()
    cmd = args.session_cmd
    if cmd == "save":
        s = Session()
        path = args.file or "~/.sidewinder/session.json"
        s.save(path)
        print_success(f"Session saved to {path}")
    elif cmd == "load":
        s = Session.load(args.file)
        print_success(f"Session loaded.")
    elif cmd == "list":
        print_info("Not fully implemented.")

async def handle_config(args):
    check_sidewinder()
    cmd = args.config_cmd
    cfg_path = "~/.sidewinder/config.json"
    cfg = SidewinderConfig.load(cfg_path)
    if cmd == "show":
        import pprint
        pprint.pprint(cfg.__dict__)
    elif cmd == "set":
        if hasattr(cfg, args.key):
            setattr(cfg, args.key, args.value)
            cfg.save(cfg_path)
            print_success(f"Set {args.key} to {args.value}")
        else:
            print_error(f"Unknown config key: {args.key}")


def main():
    parser = argparse.ArgumentParser(
        description="SWCLI - Sidewinder Command Line Interface Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # PREFLIGHT
    subparsers.add_parser("root", help="Check if running as root")
    subparsers.add_parser("deps", help="Check required/optional binaries")
    
    p_rfkill = subparsers.add_parser("rfkill", help="Show rfkill status")
    r_subs = p_rfkill.add_subparsers(dest="rfkill_cmd")
    r_unblock = r_subs.add_parser("unblock", help="Unblock wifi")
    r_unblock.add_argument("target", nargs="?", help="Specific phy to unblock (default: all)")

    # HARDWARE
    p_adapters = subparsers.add_parser("adapters", help="List all wireless interfaces")
    p_adapters.add_argument("info", nargs="?", choices=["info"], help="Get detailed adapter info")
    p_adapters.add_argument("info_iface", nargs="?", help="Interface name for details")
    
    subparsers.add_parser("kill", help="Kill conflicting services")
    subparsers.add_parser("restore", help="Restore killed services")

    # MONITOR
    p_mon = subparsers.add_parser("monitor", help="Enter monitor mode")
    p_mon.add_argument("iface", nargs="?", help="Interface to use")
    p_mon.add_argument("--channel", type=int, default=1)
    
    m_subs = p_mon.add_subparsers(dest="monitor_cmd")
    m_stop = m_subs.add_parser("stop", help="Exit monitor mode")
    m_stop.add_argument("mon")
    m_stop.add_argument("--interface")
    m_stop.add_argument("--phy")
    
    m_status = m_subs.add_parser("status", help="Check current mode")
    m_status.add_argument("iface")

    # SCAN
    p_scan = subparsers.add_parser("scan", help="Start airodump-ng scan")
    p_scan.add_argument("mon", nargs="?", help="Monitor interface")
    p_scan.add_argument("--band", default="bg")
    p_scan.add_argument("--channels", default="")
    
    s_subs = p_scan.add_subparsers(dest="scan_cmd")
    s_subs.add_parser("results", help="Show last scan results")

    # CAPTURE
    p_cap = subparsers.add_parser("capture", help="Capture operations")
    c_subs = p_cap.add_subparsers(dest="capture_cmd", required=True)
    
    c_pass = c_subs.add_parser("passive", help="Passive capture")
    c_pass.add_argument("mon")
    c_pass.add_argument("bssid")
    c_pass.add_argument("ch", type=int)
    c_pass.add_argument("--output", default="/tmp/sidewinder_cap")
    c_pass.add_argument("--timeout", type=int, default=300)
    
    c_deauth = c_subs.add_parser("deauth", help="Deauth capture")
    c_deauth.add_argument("mon")
    c_deauth.add_argument("bssid")
    c_deauth.add_argument("ch", type=int)
    c_deauth.add_argument("--client", default="FF:FF:FF:FF:FF:FF")
    c_deauth.add_argument("--output", default="/tmp/sidewinder_cap")
    c_deauth.add_argument("--count", type=int, default=10)
    c_deauth.add_argument("--bursts", type=int, default=3)
    c_deauth.add_argument("--timeout", type=int, default=300)
    
    c_pmkid = c_subs.add_parser("pmkid", help="PMKID capture")
    c_pmkid.add_argument("mon")
    c_pmkid.add_argument("bssid")
    c_pmkid.add_argument("ch", type=int)
    c_pmkid.add_argument("--timeout", type=int, default=300)

    # VALIDATE
    p_val = subparsers.add_parser("validate", help="Validate handshake")
    p_val.add_argument("cap")

    # ATTACK
    p_atk = subparsers.add_parser("attack", help="Attack modules")
    a_subs = p_atk.add_subparsers(dest="attack_cmd", required=True)
    
    a_evil = a_subs.add_parser("evil-twin", help="Evil Twin")
    a_evil.add_argument("mon")
    a_evil.add_argument("essid")
    a_evil.add_argument("ch", type=int)
    a_evil.add_argument("--bssid")
    
    a_wps = a_subs.add_parser("wps", help="WPS Pixie-Dust")
    a_wps.add_argument("mon")
    a_wps.add_argument("bssid")
    a_wps.add_argument("ch", type=int)

    # CRACK
    subparsers.add_parser("wordlists", help="List available wordlists")
    
    p_crack = subparsers.add_parser("crack", help="Crack capture")
    cr_subs = p_crack.add_subparsers(dest="crack_cmd", required=True)
    
    cr_air = cr_subs.add_parser("aircrack", help="Crack with aircrack-ng")
    cr_air.add_argument("cap")
    cr_air.add_argument("--bssid", required=True)
    cr_air.add_argument("--wordlist", dest="wl", required=True)
    
    cr_hash = cr_subs.add_parser("hashcat", help="Crack with hashcat")
    cr_hash.add_argument("cap")
    cr_hash.add_argument("--wordlist", dest="wl", required=True)

    # CLEANUP
    p_clean = subparsers.add_parser("cleanup", help="Cleanup processes and files")
    cl_subs = p_clean.add_subparsers(dest="cleanup_cmd")
    cl_subs.add_parser("procs", help="Kill attack procs only")
    cl_files = cl_subs.add_parser("files", help="Clean temp files")
    cl_files.add_argument("--dry-run", action="store_true")

    # SESSION
    p_ses = subparsers.add_parser("session", help="Session persistence")
    se_subs = p_ses.add_subparsers(dest="session_cmd", required=True)
    se_subs.add_parser("save").add_argument("--file")
    se_subs.add_parser("load").add_argument("file")
    se_subs.add_parser("list")

    # CONFIG
    p_cfg = subparsers.add_parser("config", help="Config management")
    cf_subs = p_cfg.add_subparsers(dest="config_cmd", required=True)
    cf_subs.add_parser("show")
    cf_set = cf_subs.add_parser("set")
    cf_set.add_argument("key")
    cf_set.add_argument("value")

    args = parser.parse_args()

    # Route
    try:
        if args.command == "root":
            handle_root(args)
        elif args.command == "deps":
            handle_deps(args)
        elif args.command == "rfkill":
            handle_rfkill(args)
        elif args.command == "adapters":
            asyncio.run(handle_adapters(args))
        elif args.command == "kill":
            asyncio.run(handle_kill(args))
        elif args.command == "restore":
            asyncio.run(handle_restore(args))
        elif args.command == "monitor":
            asyncio.run(handle_monitor(args))
        elif args.command == "scan":
            asyncio.run(handle_scan(args))
        elif args.command == "capture":
            asyncio.run(handle_capture(args))
        elif args.command == "validate":
            args.capture_cmd = "validate"
            asyncio.run(handle_capture(args))
        elif args.command == "attack":
            asyncio.run(handle_attack(args))
        elif args.command == "wordlists":
            args.crack_cmd = "wordlists"
            asyncio.run(handle_crack(args))
        elif args.command == "crack":
            asyncio.run(handle_crack(args))
        elif args.command == "cleanup":
            asyncio.run(handle_cleanup(args))
        elif args.command == "session":
            asyncio.run(handle_session(args))
        elif args.command == "config":
            asyncio.run(handle_config(args))
    except KeyboardInterrupt:
        print("\n\033[93m[WARNING]\033[0m Interrupted by user. Run 'swcli cleanup' if needed.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
