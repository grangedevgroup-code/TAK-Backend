# TAK-Backend

Open source server software for TAK clients and CoT software.

| Project | Description |
| --- | --- |
| [GolangTAK](GolangTAK/) | Server written in Go: one program, no dependencies, one-command install on Linux, Windows, macOS, BSD and Raspberry Pi |

![GolangTAK dashboard](GolangTAK/docs/images/overview.png)

## Install GolangTAK

Linux, Raspberry Pi, cloud VPS, macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAK/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAK/scripts/install.ps1 | iex
```

The installer sets up a service that starts at boot, opens the firewall and prints the dashboard address, the administrator password and a QR code for devices. Commands for systems without curl, BSD, updates and uninstalling are in the [GolangTAK README](GolangTAK/README.md#install).

| | |
| --- | --- |
| ![Live map](GolangTAK/docs/images/map.png) | ![Server performance](GolangTAK/docs/images/performance.png) |

**These projects are independent and open source. They are not affiliated with, endorsed by, or associated with tak.gov, the TAK Product Center, or the makers of any TAK product.**

Licensed under the [Apache License 2.0](LICENSE).
