import sys
import os

# Ensure the root SWCLI directory is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
