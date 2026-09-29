#!/usr/bin/env python3
"""
Live TShark/Pygame network map for Linux.

Requirements:
  sudo apt install tshark
  python3 -m pip install pygame

Run:
  python3 netmap.py
  python3 netmap.py --config config.json
"""

from netmap.main import main

if __name__ == "__main__":
    main()
