from __future__ import annotations

import pathlib
import shutil

import pygame

from .app import App
from .config import interfaces, load_config


def choose_interface(tshark):
    items = interfaces(tshark)
    if not items:
        raise RuntimeError("TShark reports no interfaces. Check TShark permissions.")

    print("\nAvailable interfaces:")
    for num, name in items:
        print(f"  {num}: {name}")

    while True:
        choice = input("\nSelect interface (number or name): ").strip()
        for num, name in items:
            if choice == num or choice == name:
                # tshark accepts either its numeric interface id or its name.
                return num if choice == num else name
        print("Ungültige Auswahl.")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    config_path = pathlib.Path(args.config)
    cfg = load_config(config_path)

    tshark = cfg["tshark_path"]
    if not pathlib.Path(tshark).exists():
        tshark = shutil.which("tshark") or tshark
    if not shutil.which(tshark) and not pathlib.Path(tshark).exists():
        raise SystemExit("TShark not found. Set tshark_path in config.json.")

    interface = cfg.get("interface") or choose_interface(tshark)

    pygame.mixer.quit()  # Prevent ALSA errors - we don't need audio
    pygame.init()
    try:
        App(cfg, interface).run()
    finally:
        pygame.quit()
