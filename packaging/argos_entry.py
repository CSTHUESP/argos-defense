"""Frozen-executable entry point (PyInstaller). Never re-invokes sys.executable as Python."""
import multiprocessing
import sys

from argos.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
