#!/usr/bin/env python3
"""
Minimal replacement for the missing `osken-manager` / `ryu-manager` CLI.

The os-ken PyPI wheel (4.2.2) ships the controller framework (os_ken.base,
os_ken.controller, os_ken.ofproto, os_ken.lib) but NOT its cmd/manager.py
entry point, console script, or the `--app`/`app_lists` CLI option
registration that entry point normally provides. AppManager itself exposes
a ready-made `run_apps(app_lists)` helper, so we use that directly instead
of re-registering oslo.config CLI options.

Usage:
    python3 osken_run.py <app_module_path> [<app_module_path> ...]

Example:
    python3 osken_run.py controller/simple_switch_13.py
"""
import sys

from os_ken import log
import os_ken.base.app_manager as app_manager


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    if not argv:
        print("Usage: python3 osken_run.py <app_module_path> [...]")
        return 1

    log.init_log()
    app_manager.AppManager.run_apps(argv)
    return 0


if __name__ == '__main__':
    sys.exit(main())
