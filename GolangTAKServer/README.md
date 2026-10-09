# GolangTAKServer

GolangTAKServer is a free, open source server for TAK clients such as ATAK, WinTAK, iTAK and TAK Aware, and for any other software that exchanges Cursor on Target (CoT) messages. It is a single program with no runtime dependencies and no database server. It needs no containers, and a Docker image is there if you want one. It runs on Linux, Windows, macOS, FreeBSD, OpenBSD, NetBSD, Raspberry Pi and other ARM boards, MIPS routers and cloud VPSs.

New to it? The [step by step documentation](https://tak-backend.pages.dev/docs) covers installing, connecting devices, linking servers, video, voice, feeds and the APIs.

**GolangTAKServer is an independent open source project. It is not affiliated with, endorsed by, or associated with tak.gov, the TAK Product Center, or the makers of any TAK product.** Product names such as ATAK, WinTAK, iTAK, TAK Aware and TAK Server are used only to describe compatibility.

![GolangTAKServer dashboard overview](docs/images/overview.png)

## Install

Paste one command for your system. It installs GolangTAKServer as a service that starts at boot and restarts itself if it ever stops, opens the firewall, creates the certificate authority and the first administrator account, and tests every port before it finishes.

**Linux, Raspberry Pi, cloud VPS, macOS**

```sh
curl -fsSL https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.sh | sh
```

**Linux without curl** (some minimal Debian and Ubuntu images)

```sh
wget -qO- https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.sh | sh
```

**FreeBSD**

```sh
fetch -qo - https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.sh | sh
```

**OpenBSD, NetBSD**

```sh
ftp -Vo - https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.sh | sh
```

**Windows** (PowerShell; it asks for administrator approval)

```powershell
irm https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.ps1 | iex
```

When it finishes, the installer prints the dashboard address, the administrator user name and password, and a QR code that iTAK can scan. Open the dashboard at `https://SERVER:8446` (or `http://SERVER:8080` on a trusted network) and sign in.

Lost the password? It stays in `admin-password.txt` until you change it:

```sh
sudo cat /var/lib/golangtakserver/admin-password.txt
```

```powershell
Get-Content C:\ProgramData\GolangTAKServer\admin-password.txt
```

### Reach the server from anywhere with ZeroTier

Behind a router you cannot change, or on a phone network? Create a free network at [my.zerotier.com](https://my.zerotier.com), then add its network ID to the install command. GolangTAKServer installs ZeroTier, joins the network and adds its ZeroTier address to the server certificate. Devices with the ZeroTier app on the same network connect to that address, with no ports opened to the internet.

```sh
curl -fsSL https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.sh | GOLANGTAKSERVER_ZEROTIER=NETWORK_ID sh
```

```powershell
$env:GOLANGTAKSERVER_ZEROTIER = 'NETWORK_ID'; irm https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.ps1 | iex
```

On a private network, authorize the server in the network's member list; `golangtakserver zerotier status` shows its node ID and address. An installed server can join later with `golangtakserver zerotier join NETWORK_ID`.

### Reach the server from anywhere with Tailscale

Create an auth key under Settings, Keys in the [Tailscale admin console](https://login.tailscale.com/admin/settings/keys) and add it to the install command. GolangTAKServer installs Tailscale, joins your tailnet and adds its Tailscale addresses and MagicDNS name to the server certificate. Devices with the Tailscale app on the same tailnet connect to that name, with no ports opened to the internet.

```sh
curl -fsSL https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.sh | GOLANGTAKSERVER_TAILSCALE=tskey-auth-XXXX sh
```

```powershell
$env:GOLANGTAKSERVER_TAILSCALE = 'tskey-auth-XXXX'; irm https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.ps1 | iex
```

Use `login` instead of a key to sign in with a link. An installed server can join later with `golangtakserver tailscale up [AUTH_KEY]`; `golangtakserver tailscale status` shows its addresses.

### Run in Docker

The native install is the simplest and fastest option. If you already run everything in containers, use the image instead (Linux on amd64, arm64, armv7, ppc64le and s390x):

```sh
docker run -d --name golangtakserver --restart unless-stopped \
  -e GOLANGTAKSERVER_ADDRESS=203.0.113.10 \
  -p 8087:8087 -p 8087:8087/udp -p 8088:8088 -p 8089:8089 -p 8080:8080 -p 8443:8443 -p 8446:8446 -p 8090:8090 -p 19023:19023 \
  -p 8554:8554 -p 1935:1935 -p 8000-8001:8000-8001/udp -p 64738:64738 -p 64738:64738/udp \
  -v golangtakserver-data:/data ghcr.io/grangedevgroup-code/golangtakserver:latest
docker logs golangtakserver
```

Set `GOLANGTAKSERVER_ADDRESS` to the IP address or name devices use to reach the host. The log shows the dashboard address, the administrator password and a QR code. Run commands inside the container with `docker exec golangtakserver golangtakserver user add NAME`.

| Setup | Compose file |
| --- | --- |
| Published ports | [docker/compose.yml](docker/compose.yml) |
| Host network: mesh SA multicast and any ports you add later work without changes (Linux) | [docker/compose.host.yml](docker/compose.host.yml) |
| Tailscale sidecar: reachable only on your tailnet, no ports opened | [docker/compose.tailscale.yml](docker/compose.tailscale.yml) |

```sh
GOLANGTAKSERVER_ADDRESS=203.0.113.10 docker compose -f docker/compose.yml up -d
TS_AUTHKEY=tskey-auth-XXXX GOLANGTAKSERVER_ADDRESS=golangtakserver.your-tailnet.ts.net docker compose -f docker/compose.tailscale.yml up -d
```

Optional variables: `GOLANGTAKSERVER_NAME` and `GOLANGTAKSERVER_ADMIN_PASSWORD` (used only when the first administrator is created). Data lives in the `golangtakserver-data` volume; to use a host folder instead, give it to user 65532 (`sudo chown -R 65532:65532 FOLDER`). Update with `docker pull` and recreate the container. Build the image yourself with `docker build -t golangtakserver .` in this folder.

### Update, uninstall, other versions

| Task | Command |
| --- | --- |
| Update to the newest release | Run the install command again. Settings, users, certificates and data are kept. |
| Upgrade from GolangTAK (1.5.0 and older) | Run the install command. It replaces the old `golangtak` service and program, moves the data to the new data directory and removes the old firewall rules. Users, certificates, settings, links and plugins carry over, and old link codes still work. |
| Install a specific release | `curl -fsSL https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.sh | GOLANGTAKSERVER_VERSION=1.6.0 sh` |
| Set the address and name while installing | `curl -fsSL https://raw.githubusercontent.com/grangedevgroup-code/TAK-Backend/main/GolangTAKServer/scripts/install.sh | sh -s -- --address tak.example.org --name "Field Server"` |
| Remove GolangTAKServer, keep its data | `sudo golangtakserver uninstall` |
| Remove GolangTAKServer and all its data | `sudo golangtakserver uninstall --purge` |
| Install with Go instead of a download | `go install github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/cmd/golangtakserver@latest` then `sudo "$(go env GOPATH)/bin/golangtakserver" install` |
| Try it without installing | Download the binary from [releases](https://github.com/grangedevgroup-code/TAK-Backend/releases) and run `./golangtakserver` (or double-click `golangtakserver.exe`). It runs in that window until you press Ctrl+C. |

On Windows, run `golangtakserver` commands from an administrator PowerShell and leave out `sudo`.

### Installer options

Options after `sh -s --` (or arguments to `golangtakserver install`):

| Option | Effect |
| --- | --- |
| `--address HOST` | Address or DNS name devices use to reach the server (detected automatically if omitted) |
| `--name NAME` | Server name shown in clients |
| `--admin-password PW` | Password for the first administrator instead of a generated one |
| `--no-anonymous` | Require a certificate or password for every connection, and ignore UDP and multicast input |
| `--no-firewall` | Do not change firewall rules |
| `--no-start` | Install without starting |

Environment variables for the install scripts: `GOLANGTAKSERVER_VERSION=1.2.3` installs a specific release, `GOLANGTAKSERVER_SOURCE=1` builds from source with Go instead of downloading, and `GOLANGTAKSERVER_BINARY=/path/to/golangtakserver` installs a binary you already have.

### Everyday commands

| Task | Command |
| --- | --- |
| Is it running? | `sudo golangtakserver status` |
| Add a user | `sudo golangtakserver user add alice --groups Blue --callsign ALPHA-1` |
| Show QR codes to connect a device | `sudo golangtakserver qr alice` |
| Save a connection package | `sudo golangtakserver user package alice` |
| Follow the log | `sudo golangtakserver logs -f` |
| Restart | `sudo golangtakserver restart` |
| Test every port | `sudo golangtakserver selftest` |
| Back up | `sudo golangtakserver backup` |

The full list is under [Commands](#commands).

## Screenshots

| | |
| --- | --- |
| ![Live map with team positions, aircraft from the ADS-B feed and an emergency](docs/images/map.png) | ![Server performance with CPU, memory, disk and message rates](docs/images/performance.png) |
| **Map**: team positions, markers, aircraft from the ADS-B feed and an active emergency | **Performance**: CPU, memory, disk and message rates over the last ten minutes |
| ![Connect a device with QR codes and connection packages](docs/images/connect.png) | ![Settings, Meshtastic section](docs/images/settings.png) |
| **Connect a device**: QR codes for ATAK, WinTAK and iTAK, packages and manual settings | **Settings**: grouped sections with a save bar that tracks unsaved changes |
| ![Overview in the light theme](docs/images/overview-light.png) | ![Sign-in screen](docs/images/sign-in.png) |
| **Light theme**: follows the system setting, or choose it under My account | **Sign in** |

<p>
<img src="docs/images/phone-overview.png" alt="Overview on a phone" width="260">
&nbsp;
<img src="docs/images/phone-map.png" alt="Map on a phone" width="260">
</p>

The dashboard works on phones and tablets as well as desktops. Press Ctrl+K (or /) anywhere to jump to any page or setting.

## Connect devices

Open the dashboard and go to **Connect a device**:

- **ATAK and WinTAK enrollment QR code**: in ATAK choose Settings, Network, Servers, Add, Scan QR. The device enrolls for its own certificate with a one-time code.
- **iTAK quick connect QR code**: in iTAK choose Settings, Network, Servers, Connect with QR, then sign in with a user name and password.
- **Download link QR code**: a single-use link to a complete connection package.
- **Connection packages**: zip files to import on any TAK client, with a certificate, an enrollment profile, or plain TCP settings.
- **Manual setup**: address, ports, truststore and CA fingerprint for entering settings by hand.

The same is available from a terminal: `golangtakserver qr USER` prints enrollment QR codes and `golangtakserver user package USER` saves a connection package.

## Works with

| Software | How it connects |
| --- | --- |
| ATAK, ATAK-CIV, ATAK-MIL | SSL on 8089 with certificate enrollment, TCP on 8087, QR codes, connection packages, Data Sync, update server |
| WinTAK | SSL, TCP, connection packages, Data Sync |
| iTAK | SSL with quick connect QR and enrollment, TCP, server packages |
| TAK Aware and other CoT apps | SSL, TCP, UDP, connection packages |
| TAK Server | Federation version 1 and version 2 (gRPC) in both directions, including mission, file and log sharing over version 2, or a TCP or TLS link |
| OpenTAKServer, FreeTAKServer | TCP or TLS links in both directions; GolangTAKServer also serves the FreeTAKServer REST API on port 19023: map objects, chat, presence, routes, emergencies, drones and sensor points, video streams, KML points, objects in a zone, repeated messages, data packages, missions, ExCheck, system users and federations |
| zyrntopo-tak-server and browser software | CoT over WebSocket on port 8090, links to WebSocket servers |
| Mesh and radio gateways | Multicast situational awareness (239.2.3.1:6969 and 224.10.10.1:17012), UDP input |
| Meshtastic | Gateway nodes connect to the built-in MQTT broker on port 1883 (when enabled), or both sides share an MQTT broker |
| Scripts and integrations | REST API with tokens, CoT over HTTP, live event stream over WebSocket |

Every link is bidirectional: traffic from devices on GolangTAKServer reaches the other side and traffic from the other side reaches GolangTAKServer devices, with loop protection so nothing echoes back.

## Features

- **Messaging**: CoT XML and TAK Protocol version 1 (protobuf) with automatic negotiation, groups (channels) with separate send and receive sets, direct messages, geospatial filters, emergency alerts with a repeater, repeated objects sent to every device that connects, chat store-and-forward for offline contacts, situational awareness replay for new clients.
- **Accounts**: two-step dashboard sign-in with an authenticator app or emailed codes (with recovery codes), password reset by email, optional self-registration with email confirmation, domain allow and block lists and administrator approval, local users with groups, or sign-in with LDAP and Active Directory accounts whose directory groups become TAK groups, with an administrator group and a callsign attribute.
- **Certificates**: free browser-trusted certificates from Let's Encrypt for the dashboard and enrollment port, renewed automatically, built-in certificate authority, certificate enrollment (signClient v1 and v2, JSON and XML), one-time enrollment codes, revocation, server certificate that renews itself when the address changes, import of an existing CA.
- **Data**: data packages and the Data Sync API, missions with subscriptions, roles, passwords, invitations and change notifications, ExCheck checklists, CI-TRAP reports, video feeds, KML export, track history.
- **Languages**: the dashboard is in English, Spanish, French, German, Portuguese and Ukrainian. It follows the browser language, and each person can choose another on the sign-in page or under My account.
- **Administration**: web dashboard (map with MIL-STD-2525 unit symbols by affiliation, dimension and function, heading lines, routes, drawings, range and bearing lines, areas in acres and hectares (for Fire Area Survey perimeters and other drawings), CasEvac 9-line reports and attached images, chat, clients, devices, users, groups, files, missions, video, server links, plugins, settings, logs, and a performance page with CPU, memory, disk, load and message rates over the last ten minutes), command line tools, API tokens, ATAK update server for plugins, device profiles pushed at enrollment or connection.
- **Links**: outbound links over TCP, TLS, UDP and WebSocket, inbound and outbound TAK Server federation, version 1 and version 2.
- **Meshtastic**: built-in MQTT broker for Meshtastic gateway nodes (or an upstream broker); mesh positions, names, battery and chat appear in TAK, and TAK positions and chat go out to the mesh, encrypted with the channel key.
- **Video server**: built in, no MediaMTX needed. Cameras, drones, ATAK, OBS and ffmpeg publish over RTSP, RTSPS or RTMP (H.264 and AAC); TAK clients and VLC play over RTSP (TCP or UDP) or HLS, and the dashboard plays live H.264 in the browser. Streams sign in with GolangTAKServer accounts, are listed automatically in every TAK client's video list, can be pulled from existing cameras (RTSP with Basic or Digest sign-in) and relayed, and are recorded on demand or automatically to standard MP4 files that play, seek and download from the dashboard.
- **Voice**: built-in Mumble server, no Murmur needed. Mumble, Mumla and the TAK voice plugins sign in with TAK user names and passwords (or LDAP), every group gets its own channel that only its members can join, and voice, whispers and text chat work over TCP or encrypted UDP.
- **TAK Server API compatibility**: CloudTAK and other web clients sign in with OAuth (`/oauth/token`) and get certificates with the token. The TAK Server user management, certificate administration, repeater, CoT injector, mission property, paged mission and locate APIs are supported, so tools written for TAK Server work unchanged.
- **Locate**: an optional web page anyone you send the link to can use to put their position on the map, for search and rescue or people without a TAK client.
- **Telegram**: a Telegram group joins TAK chat in both directions, emergencies are posted to it, and locations people share in Telegram appear on the map. Only the configured chat is accepted.
- **Background jobs**: data cleanup, certificate renewal, repeated objects, feeds and Let's Encrypt renewal are listed under Settings, Maintenance with their last run, and each can be run now or paused.
- **Your own receivers and trackers**: aircraft from an RTL-SDR running dump1090, readsb or dump1090-fa (the BaseStation port 30003, or aircraft.json from tar1090 and SkyAware), ships from rtl_ais or AIS-catcher (NMEA over UDP or TCP, with multi-part messages and static vessel data), phones running Traccar Client (OsmAnd protocol, port 5055, optional key), and every device on a Traccar server (user name and password, or an API token). Each is a data feed with its own groups, archive and sync settings.
- **Data feeds**: live aircraft from ADS-B exchanges (adsb.lol by default, or any service with the same API) and ships from AISHub, sent to everyone or to one group.
- **TAK data feeds and map layers**: TCP, TLS, UDP and multicast inputs for sensors and other systems, each on its own port with its own groups, listed with the built-in feeds in the TAK Server data feed API (statistics, latest objects, bounds). Missions can include a feed with polygon, CoT type and callsign filters, and its data goes to the mission subscribers. Map layers (tiles, WMS, WMTS) are published to TAK clients and missions, and appear as base maps on the dashboard map. Missions, feeds and map layers are also shared over federation version 2.
- **Operations**: one binary, service on every operating system with restart on failure, crash-safe storage, automatic housekeeping, backups, built-in self-test.

## Link servers together

Linking lets devices on different servers see each other: an HQ server and field servers, two teams on their own servers, or a server in the cloud and one on a Raspberry Pi in a vehicle. Every link carries traffic both ways, and loop protection stops messages from echoing back.

**Two GolangTAKServer instances.** On the server the other one will connect to:

```sh
sudo golangtakserver peer invite field-team
```

It prints a link code. On the other server:

```sh
sudo golangtakserver peer join golangtakserver-link:...
```

The code carries the address, a client certificate and the certificate authority, so the link is encrypted and trusted in both directions with nothing else to set up. In the dashboard the same thing is under **Server links**, **Create a link code** and **Use a link code**. Add `--groups Blue` to either command to share only some groups. To cut the link, delete the `link-field-team` user on the first server. Send codes privately: anyone with a code can link to your server.

**Other servers and software.** Use **Server links**, **Add link** (or `golangtakserver peer add`) and choose what is on the other side:

| Other side | Link |
| --- | --- |
| TAK Server | Federation: turn it on under Server links and exchange CA certificates, or connect out with `fed2://HOST:9001` (version 2) or `fed://HOST:9000` (version 1). Or a TLS link to its port 8089 with a client certificate it issued. |
| OpenTAKServer | `tls://HOST:8089` with a certificate from OpenTAKServer, or `tcp://HOST:8088` on a trusted network |
| FreeTAKServer | `tcp://HOST:8087`, or `tls://HOST:8089` with a certificate |
| zyrntopo-tak-server and WebSocket software | `wss://HOST/` or `ws://HOST:PORT/` |
| Anything else that speaks CoT | `tcp://`, `tls://`, `udp://` or `ws://` |
| PyTAK scripts | `COT_URL=tcp://SERVER:8087`, or `tls://SERVER:8089` with `PYTAK_TLS_CLIENT_CERT` and `PYTAK_TLS_CLIENT_KEY` from a certificate package. For UDP on the same machine as GolangTAKServer use `udp+wo://SERVER:8087`, because PyTAK's two-way UDP mode takes over the port. |

**TAK Server federation.** To accept federates on both protocol versions:

```sh
golangtakserver config set federation.enabled true ports.federation 9000 ports.federationV2 9001
```

Give the other server this server's CA (`/api/ca.pem`) and add its CA under **Server links**, **Federation**. Version 2 also shares public missions, their files, logs, parent missions and expiration with TAK Server, both ways and including missions that existed before the link. Federated deletes are off unless you allow them (`federation.allowFederatedDelete`), and `federation.disableMissionFederation` turns mission sharing off.

## Video server

Publish a stream with a user name and password from this server:

```sh
ffmpeg -re -i video.mp4 -c copy -f rtsp rtsp://USER:PASSWORD@SERVER:8554/live/uas1
```

Drone apps, OBS and other encoders that only send RTMP use `rtmp://SERVER:1935/live/uas1?user=USER&pass=PASSWORD`. The stream appears in every TAK client's video list as `rtsp://SERVER:8554/live/uas1`, on the dashboard under **Video**, and as HLS at `/api/video/live/live/uas1/index.m3u8`. Cameras that already serve RTSP can be added under **Video**, **Add pull source** and are relayed from the server. Ports, RTSPS and anonymous viewing or publishing are under **Settings**, **Video server**.

**Drones and encoders that send MPEG-TS.** Add a pull source with `udp://0.0.0.0:5600` (or a multicast address such as `udp://239.1.1.1:5600`) and point the ground station or encoder at the server. The video is republished like any other stream. When the stream carries MISB 0601 KLV telemetry, the drone appears on every TAK map with its heading, camera field of view, the point the camera looks at and the ground footprint, linked to the video. RTSP sources and publishers that include a KLV track work the same way. Turn this off under **Settings**, **Video server**, **Drone telemetry**.

## Server plugins

A server plugin is any program you want running next to GolangTAKServer: a bot that answers in chat, a bridge to a dispatch or alerting system, a logger, a sensor feed. GolangTAKServer starts it with the server, restarts it if it stops (waiting a little longer each time, up to a minute), stops it on shutdown, and keeps its recent output for the dashboard.

```sh
sudo golangtakserver plugin add welcome /opt/plugins/welcome
sudo golangtakserver plugin list
sudo golangtakserver plugin logs welcome
```

Put `--` before plugin arguments that start with a dash: `golangtakserver plugin add notify /usr/bin/python3 -- /opt/notify.py --verbose`. Plugins can be written in any language. Each one gets its own user account (`plugin-NAME`) and these environment variables:

| Variable | Contents |
| --- | --- |
| `GOLANGTAKSERVER_URL` | Base URL of the REST API on this machine |
| `GOLANGTAKSERVER_STREAM_URL` | WebSocket URL of the live event stream (JSON, one event per message) |
| `GOLANGTAKSERVER_TOKEN` | API token: send it as `Authorization: Bearer TOKEN` |
| `GOLANGTAKSERVER_CA` | The server's CA certificate, for HTTPS |
| `GOLANGTAKSERVER_COT_TCP` | Address of the plain CoT TCP port, when it is on |
| `GOLANGTAKSERVER_PLUGIN`, `GOLANGTAKSERVER_PLUGIN_DATA` | The plugin's name, and a folder it can keep files in (also its working folder) |
| `GOLANGTAKSERVER_SERVER_NAME`, `GOLANGTAKSERVER_VERSION` | Server name and version |

The plugin account is a normal user, not an administrator. Add `--admin` to give it full access, and `--groups` to choose what it sees. With its token a plugin can read the event stream, send chat (`POST /api/chat`), place markers (`POST /api/markers`), and use everything else the dashboard uses.

**Packaged plugins.** A plugin folder or zip with a `plugin.json` installs in one step, from a folder, a zip file or an https link:

```sh
sudo golangtakserver plugin install ./statusboard
sudo golangtakserver plugin settings statusboard title="Team status"
sudo golangtakserver plugin uninstall statusboard
```

`plugin.json` names the program (per operating system if needed), describes the plugin, declares a settings form and says whether the plugin has web pages:

```json
{
  "name": "statusboard",
  "version": "1.0.0",
  "description": "Device status board",
  "command": "statusboard",
  "commands": { "windows": "statusboard.exe" },
  "http": true,
  "page": "Status board",
  "settings": [
    { "key": "title", "label": "Board title", "type": "text", "default": "Status board" },
    { "key": "staleMinutes", "label": "Stale after (minutes)", "type": "number", "default": "5" }
  ]
}
```

Setting types are `text`, `number`, `bool`, `secret`, `select` (with `options`) and `textarea`. Administrators change settings in the dashboard, which restarts the plugin with them; the plugin reads them as JSON from `GOLANGTAKSERVER_PLUGIN_SETTINGS`, and secrets are never shown again. A plugin with `"http": true` gets a private address in `GOLANGTAKSERVER_PLUGIN_HTTP`; its pages and API appear on the dashboard at `/plugins/NAME/` and in the menu, behind dashboard sign-in (`"adminOnly": true` limits them to administrators, and `"public": true` serves `/plugins/NAME/public/` without signing in). GolangTAKServer passes the signed-in user in the `X-GolangTAKServer-User`, `X-GolangTAKServer-Admin` and `X-GolangTAKServer-Groups` headers and never forwards session cookies or tokens to the plugin.

**Writing plugins in Go.** The [`pkg/plugin`](pkg/plugin/plugin.go) package handles the connection: `plugin.Load()`, `Events` for the live stream with reconnects, `Chat`, `SendCoT`, `PlaceMarker`, `Do` for any API call, `Setting` for the settings form, `Serve` for web pages and `UserOf` for who is signed in. [`examples/plugins/welcome`](examples/plugins/welcome/main.go) greets new devices, and [`examples/plugins/statusboard`](examples/plugins/statusboard/main.go) adds a status board page to the dashboard. Plugins in other languages use the same environment variables and HTTP endpoints.

The dashboard (**Plugins and profiles**) shows each plugin's version, state, process and output, edits its settings, and can restart, enable or disable it. Plugins can only be installed, added or removed on the server itself, with the `golangtakserver plugin` command or in `config.json`, so a stolen dashboard password cannot be used to run programs on the server.

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
| 9000 | TCP | Federation version 1 (off by default) |
| 9001 | TCP | Federation version 2, gRPC (off by default) |
| 64738 | TCP and UDP | Voice server (Mumble) |
| 8554 | TCP | Video server, RTSP |
| 1935 | TCP | Video server, RTMP ingest |
| 8000, 8001 | UDP | Video server, RTP and RTCP |
| 5055 | TCP | Traccar Client phones, when an OsmAnd data feed is added |
| 10110 | UDP | AIS receivers sending NMEA, when an AIS data feed is added |
| 1883 | TCP | MQTT broker for Meshtastic gateway nodes (off by default) |
| 6969, 17012 | UDP | Multicast situational awareness (mesh) |

Set any port to 0 to turn that service off.

## Commands

| Command | Purpose |
| --- | --- |
| `golangtakserver` or `golangtakserver run` | Run in the current window |
| `golangtakserver install` / `uninstall [--purge]` | Install or remove the service, firewall rules and program |
| `golangtakserver start` / `stop` / `restart` / `status` | Control the service and show its state |
| `golangtakserver connect` / `qr [USER]` | Connection details and QR codes |
| `golangtakserver user list` / `add NAME` / `del NAME` / `passwd NAME` / `groups NAME` / `package NAME` | Manage users |
| `golangtakserver group list` / `add NAME` / `del NAME` | Manage groups |
| `golangtakserver peer list` / `invite NAME` / `join CODE` / `add NAME URL` / `del NAME` | Links to other servers |
| `golangtakserver plugin list` / `add NAME COMMAND` / `del NAME` / `restart NAME` / `logs NAME` | Server plugins |
| `golangtakserver config show` / `get KEY` / `set KEY VALUE` | Settings |
| `golangtakserver cert info` / `renew` / `import-ca CERT KEY` | Certificates |
| `golangtakserver logs [-f]` | Server log |
| `golangtakserver selftest` | Test every port of the running server |
| `golangtakserver backup [FILE]` | Save settings, users, certificates and missions |
| `golangtakserver zerotier status` / `join NETWORK_ID` / `leave NETWORK_ID` | Install ZeroTier and join a virtual network |
| `golangtakserver tailscale status` / `up [AUTH_KEY]` / `down` | Install Tailscale and join your tailnet |
| `golangtakserver bench [--clients N] [--every S] [--duration S]` | Load test this or any TAK server with simulated clients: throughput, delivery and latency |

`golangtakserver help COMMAND` shows every option. Commands work whether the server is running or stopped. Add `--data DIR` to use another data directory.

Examples:

```sh
sudo golangtakserver user add alice --groups Blue --callsign ALPHA-1
sudo golangtakserver qr alice
sudo golangtakserver peer add hq tls://tak.example.org:8089 --user golangtakserver --password secret --trust /root/hq-ca.pem
sudo golangtakserver config set address tak.example.org
golangtakserver bench --host tak.example.org --clients 500 --duration 60
golangtakserver bench --tls --cert alice.p12 --trust truststore.p12 --clients 200
```

## Settings and data

| System | Data directory |
| --- | --- |
| Linux and BSD | `/var/lib/golangtakserver` |
| macOS | `/Library/Application Support/GolangTAKServer` |
| Windows | `C:\ProgramData\GolangTAKServer` |

Settings live in `config.json` in the data directory and can be changed in the dashboard (Settings), with `golangtakserver config set`, or by editing the file and restarting. The data directory also holds the certificate authority, users, files, missions, history and logs. Keep backups somewhere safe: they contain the CA private key.

## Security

- Change the generated administrator password after the first sign-in.
- Port 8087 (TCP), UDP input and the HTTP dashboard on 8080 are unencrypted. On untrusted networks install with `--no-anonymous`, give devices certificates, and use the dashboard on port 8446.
- Groups separate traffic: users only receive from their receive groups, and history, files, missions and video follow the same rules.
- On cloud servers also allow the ports in the provider's firewall or security group.
- Rate limits under **Settings**, **Storage and limits** cap how many messages each device can send and receive per second and how many new connections an address can open per minute. Chat, alerts, deletions, direct messages and server links are never limited.

## Translations

Dashboard translations are JSON files in `web/static/i18n`, one per language, mapping the English text to the translation. Text with `{n}` (a number) or `{x}` (a name) matches sentences built around those values. To add a language, add its file and an entry in the `LANGS` list at the top of `web/static/app.js`; `go test ./web` checks every file.

## Building from source

Requires Go 1.24 or newer.

```sh
cd GolangTAKServer
go build ./cmd/golangtakserver
go test ./...
sh scripts/build.sh 1.0.0
```

`scripts/build.sh` (or `scripts/build.ps1` on Windows) cross-compiles release binaries for every supported system into `dist/` with a `SHA256SUMS` file.

## License

GolangTAKServer is open source under the [Apache License 2.0](LICENSE). The dashboard embeds the Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono fonts, which are licensed under the SIL Open Font License 1.1 (see `web/static/fonts`).
