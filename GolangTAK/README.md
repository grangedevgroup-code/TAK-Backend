# GolangTAK

GolangTAK is a free, open source server for TAK clients such as ATAK, WinTAK, iTAK and TAK Aware, and for any other software that exchanges Cursor on Target (CoT) messages. It is a single program with no runtime dependencies, no containers and no database server. It runs on Linux, Windows, macOS, FreeBSD, OpenBSD, NetBSD, Raspberry Pi and other ARM boards, MIPS routers and cloud VPSs.

**GolangTAK is an independent open source project. It is not affiliated with, endorsed by, or associated with tak.gov, the TAK Product Center, or the makers of any TAK product.** Product names such as ATAK, WinTAK, iTAK, TAK Aware and TAK Server are used only to describe compatibility.

## Install

One command installs GolangTAK as a service that starts at boot and restarts itself if it ever stops. It also opens the firewall, creates the certificate authority and the first administrator account, and tests every port before it finishes.

Linux, Raspberry Pi, macOS, FreeBSD and other Unix systems:

```sh
curl -fsSL https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAK/scripts/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAK/scripts/install.ps1 | iex
```

When it finishes, the installer prints the dashboard address, the administrator user name and password, and a QR code that iTAK can scan. The password is also saved in `admin-password.txt` in the data directory until you change it.

Installer options are passed through to `golangtak install`:

```sh
curl -fsSL https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAK/scripts/install.sh | sh -s -- --address tak.example.org --name "Field Server"
```

| Option | Effect |
| --- | --- |
| `--address HOST` | Address or DNS name devices use to reach the server (detected automatically if omitted) |
| `--name NAME` | Server name shown in clients |
| `--admin-password PW` | Password for the first administrator instead of a generated one |
| `--no-anonymous` | Require a certificate or password for every connection, and ignore UDP and multicast input |
| `--no-firewall` | Do not change firewall rules |
| `--no-start` | Install without starting |

Environment variables for the install scripts: `GOLANGTAK_VERSION=1.2.3` installs a specific release, `GOLANGTAK_SOURCE=1` builds from source with Go instead of downloading, and `GOLANGTAK_BINARY=/path/to/golangtak` installs a binary you already have.

Without the scripts: download the binary for your system from the [releases](https://github.com/grangedevgroup-code/TAK-Backend/releases), then run `sudo ./golangtak install` (or `golangtak.exe install` from an administrator terminal on Windows). To try GolangTAK without installing anything, run `golangtak` (or double-click `golangtak.exe`) and it serves from the current window until you press Ctrl+C.

Running the installer again upgrades GolangTAK in place and keeps all data.

## Connect devices

Open the dashboard and go to **Connect a device**:

- **ATAK and WinTAK enrollment QR code**: in ATAK choose Settings, Network, Servers, Add, Scan QR. The device enrolls for its own certificate with a one-time code.
- **iTAK quick connect QR code**: in iTAK choose Settings, Network, Servers, Connect with QR, then sign in with a user name and password.
- **Download link QR code**: a single-use link to a complete connection package.
- **Connection packages**: zip files to import on any TAK client, with a certificate, an enrollment profile, or plain TCP settings.
- **Manual setup**: address, ports, truststore and CA fingerprint for entering settings by hand.

The same is available from a terminal: `golangtak qr USER` prints enrollment QR codes and `golangtak user package USER` saves a connection package.

## Works with

| Software | How it connects |
| --- | --- |
| ATAK, ATAK-CIV, ATAK-MIL | SSL on 8089 with certificate enrollment, TCP on 8087, QR codes, connection packages, Data Sync, update server |
| WinTAK | SSL, TCP, connection packages, Data Sync |
| iTAK | SSL with quick connect QR and enrollment, TCP, server packages |
| TAK Aware and other CoT apps | SSL, TCP, UDP, connection packages |
| TAK Server | Federation (version 1) in both directions, or a TCP or TLS link |
| OpenTAKServer, FreeTAKServer | TCP or TLS links in both directions; GolangTAK also serves the FreeTAKServer REST API on port 19023 |
| zyrntopo-tak-server and browser software | CoT over WebSocket on port 8090, links to WebSocket servers |
| Mesh and radio gateways | Multicast situational awareness (239.2.3.1:6969 and 224.10.10.1:17012), UDP input |
| Meshtastic | Gateway nodes connect to the built-in MQTT broker on port 1883 (when enabled), or both sides share an MQTT broker |
| Scripts and integrations | REST API with tokens, CoT over HTTP, live event stream over WebSocket |

Every link is bidirectional: traffic from devices on GolangTAK reaches the other side and traffic from the other side reaches GolangTAK devices, with loop protection so nothing echoes back.

## Features

- **Messaging**: CoT XML and TAK Protocol version 1 (protobuf) with automatic negotiation, groups (channels) with separate send and receive sets, direct messages, geospatial filters, emergency alerts with a repeater, chat store-and-forward for offline contacts, situational awareness replay for new clients.
- **Accounts**: local users with groups, or sign-in with LDAP and Active Directory accounts whose directory groups become TAK groups, with an administrator group and a callsign attribute.
- **Certificates**: built-in certificate authority, certificate enrollment (signClient v1 and v2, JSON and XML), one-time enrollment codes, revocation, server certificate that renews itself when the address changes, import of an existing CA.
- **Data**: data packages and the Data Sync API, missions with subscriptions, roles, passwords, invitations and change notifications, ExCheck checklists, CI-TRAP reports, video feeds, KML export, track history.
- **Administration**: web dashboard (map, chat, clients, devices, users, groups, files, missions, video, server links, plugins, settings, logs), command line tools, API tokens, ATAK update server for plugins, device profiles pushed at enrollment or connection.
- **Links**: outbound links over TCP, TLS, UDP and WebSocket, inbound and outbound TAK Server federation.
- **Meshtastic**: built-in MQTT broker for Meshtastic gateway nodes (or an upstream broker); mesh positions, names, battery and chat appear in TAK, and TAK positions and chat go out to the mesh, encrypted with the channel key.
- **Data feeds**: live aircraft from ADS-B exchanges (airplanes.live, adsb.lol and compatible services) and ships from AISHub, sent to everyone or to one group.
- **Operations**: one binary, service on every operating system with restart on failure, crash-safe storage, automatic housekeeping, backups, built-in self-test.

## Ports

| Port | Protocol | Use |
| --- | --- | --- |
| 8089 | TCP | TAK SSL (TLS) streaming |
| 8087 | TCP | TAK streaming, unencrypted |
| 8088 | TCP | Second unencrypted streaming port |
| 8087 | UDP | CoT datagrams |
| 8446 | TCP | Certificate enrollment and the dashboard over HTTPS (no client certificate) |
| 8443 | TCP | HTTPS API with client certificates (Marti API, Data Sync, update server) |
| 8080 | TCP | HTTP API and the dashboard |
| 8090 | TCP | CoT over WebSocket |
| 19023 | TCP | FreeTAKServer-compatible REST API |
| 9000 | TCP | Federation (off by default) |
| 1883 | TCP | MQTT broker for Meshtastic gateway nodes (off by default) |
| 6969, 17012 | UDP | Multicast situational awareness (mesh) |

Set any port to 0 to turn that service off.

## Commands

| Command | Purpose |
| --- | --- |
| `golangtak` or `golangtak run` | Run in the current window |
| `golangtak install` / `uninstall [--purge]` | Install or remove the service, firewall rules and program |
| `golangtak start` / `stop` / `restart` / `status` | Control the service and show its state |
| `golangtak connect` / `qr [USER]` | Connection details and QR codes |
| `golangtak user list` / `add NAME` / `del NAME` / `passwd NAME` / `groups NAME` / `package NAME` | Manage users |
| `golangtak group list` / `add NAME` / `del NAME` | Manage groups |
| `golangtak peer list` / `add NAME URL` / `del NAME` | Links to other servers |
| `golangtak config show` / `get KEY` / `set KEY VALUE` | Settings |
| `golangtak cert info` / `renew` / `import-ca CERT KEY` | Certificates |
| `golangtak logs [-f]` | Server log |
| `golangtak selftest` | Test every port of the running server |
| `golangtak backup [FILE]` | Save settings, users, certificates and missions |

`golangtak help COMMAND` shows every option. Commands work whether the server is running or stopped. Add `--data DIR` to use another data directory.

Examples:

```sh
sudo golangtak user add alice --groups Blue --callsign ALPHA-1
sudo golangtak qr alice
sudo golangtak peer add hq tls://tak.example.org:8089 --user golangtak --password secret --trust /root/hq-ca.pem
sudo golangtak config set address tak.example.org
```

## Settings and data

| System | Data directory |
| --- | --- |
| Linux and BSD | `/var/lib/golangtak` |
| macOS | `/Library/Application Support/GolangTAK` |
| Windows | `C:\ProgramData\GolangTAK` |

Settings live in `config.json` in the data directory and can be changed in the dashboard (Settings), with `golangtak config set`, or by editing the file and restarting. The data directory also holds the certificate authority, users, files, missions, history and logs. Keep backups somewhere safe: they contain the CA private key.

## Security

- Change the generated administrator password after the first sign-in.
- Port 8087 (TCP), UDP input and the HTTP dashboard on 8080 are unencrypted. On untrusted networks install with `--no-anonymous`, give devices certificates, and use the dashboard on port 8446.
- Groups separate traffic: users only receive from their receive groups, and history, files, missions and video follow the same rules.
- On cloud servers also allow the ports in the provider's firewall or security group.

## Building from source

Requires Go 1.24 or newer.

```sh
cd GolangTAK
go build ./cmd/golangtak
go test ./...
sh scripts/build.sh 1.0.0
```

`scripts/build.sh` (or `scripts/build.ps1` on Windows) cross-compiles release binaries for every supported system into `dist/` with a `SHA256SUMS` file.

## License

GolangTAK is open source under the [Apache License 2.0](LICENSE). The dashboard embeds the Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono fonts, which are licensed under the SIL Open Font License 1.1 (see `web/static/fonts`).
