# Netmap GUI

Real-time network map visualization using TShark and Pygame. Displays IP connections as a force-directed graph grouped by protocol.

## Views

**NodeView** (default) — Force-directed graph showing all active IPs as nodes and their connections as colored edges (one line per protocol).

![NodeView](netmap_nodeView.png)

**DetailedView** — Click two nodes to inspect all traffic between them: packet timestamps, protocols, ports, and decoded payload data.

![DetailedView](netmap_detailedView.png)

## Installation

```bash
# 1. Install system dependencies (TShark for packet capture)
sudo apt install tshark

# 2. Create virtual environment
python3 -m venv .venv

# 3. Install Python dependencies
.venv/bin/pip install pygame

# 4. Run (sudo required for packet capture)
sudo .venv/bin/python netmap.py
sudo .venv/bin/python netmap.py --config config.json
```

## Installation (requirements.txt)

```bash
pip install -r requirements.txt
```

## Controls

| Key | Function |
|-----|----------|
| SPACE | Pause/Resume |
| C | Clear view |
| H | Show help |
| F | Text filter |
| P | Protocol filter |
| O | Port filter (e.g. 443, 80) |
| I | IP version (ALL→IPv4→IPv6) |
| D | DNS resolution on/off |
| S | Statistics panel on/off |
| E | Save screenshot |
| ESC | Quit |

**Mouse:** Hover over connection to see payload data. Click two nodes to switch to DetailedView. Scroll wheel navigates history.

## Configuration

Adjust `config.json` for:
- Window size, FPS
- Layout physics (Repulsion, Spring, Damping)
- Node size and retention time
- Protocol colors

See `DEFAULT_CONFIG` in [netmap.py](netmap.py) for all options.
