import sys
import os

# Ensure the root SWCLI directory is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# If running under sudo, append the invoking user's local site-packages to sys.path
sudo_user = os.environ.get("SUDO_USER")
if sudo_user:
    try:
        import pwd
        user_home = pwd.getpwnam(sudo_user).pw_dir
        py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
        local_site_packages = os.path.join(user_home, ".local", "lib", py_ver, "site-packages")
        if os.path.exists(local_site_packages) and local_site_packages not in sys.path:
            sys.path.append(local_site_packages)
    except Exception:
        pass

def main():
    if len(sys.argv) == 1:
        # Interactive REPL mode
        from swcli.repl.loop import SwcliREPL
        repl = SwcliREPL()
        repl.run()
    else:
        # Direct command mode via argparse
        from swcli import cli
        cli.main()

if __name__ == "__main__":
    main()
