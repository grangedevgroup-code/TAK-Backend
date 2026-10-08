# Dashboard design rules

The dashboard is a tool for people running a TAK server, often on a laptop in the field, a tablet, or a phone, with divided attention and sometimes no internet. Every rule below serves that.

## What we learned from other TAK dashboards

- FreeTAKServer shipped its web UI as a separate program with its own install, port and database. Users could sign in and then see red status dots with no explanation of what was wrong or how to fix it, and changing IP or port settings from the UI could crash the server.
- OpenTAKServer's UI is a separate React application. Its live updates broke behind proxies and from remote browsers, devices that did not send a `takv` element never appeared on the map, data package uploads failed, and plugin pages showed stale data from a previously viewed plugin.
- Control-room research (SKA telescope operations, network operations centres) finds the same failures in operator dashboards: too much low-signal data, critical state buried among detail, and destructive actions without confirmation.

## Rules

1. One program. The dashboard is embedded in the server binary and served from the same origin as the API and the live stream. No separate install, no build step, no external requests except map tiles.
2. State in words. Every status is written out ("connected", "problem: connection refused"), never a bare colored dot. Problems say what is wrong and where to fix it.
3. Most important first. The overview answers, in order: is anything on fire (emergencies), what still needs setting up, who is online, are the links healthy. Details such as ports, certificates and host information are collapsed below.
4. One primary action per page, top right, in the page header.
5. Lists can be filtered. Any list that can grow has a filter box.
6. Destructive actions ask first and say what will happen.
7. Settings are grouped into sections, saved together, and the save bar always shows whether there are unsaved changes.
8. Everything is reachable from the keyboard: Ctrl+K or / opens "go to", every control has a visible focus outline.
9. Works at phone width.
10. Live means live. The header shows whether live updates are flowing; when they are not, it says "Reconnecting".

## Visual language

- Black and white only. Gray is used for secondary text and rules. Inversion (white on black or black on white) marks the active item, the primary action and alarms. There is no accent color, so nothing competes with an emergency.
- Type: Atkinson Hyperlegible Next and Atkinson Hyperlegible Mono, embedded in the binary. They were drawn by the Braille Institute for low-vision readers, so similar characters such as 0/O and 1/l/I stay distinct in callsigns, UIDs, coordinates and passwords. Base size 15px.
- Square corners, 1px rules, no shadows, no gradients, no rounded cards, no decorative background.
- Icons are one hand-drawn set of 24px outline icons with square ends, in `static/icons.js`. They appear in navigation, primary buttons, status tiles and alarms only, always next to a text label. No emoji.
- Motion only where it carries information: the reconnecting indicator blinks. Nothing else animates, and reduced motion turns that off too.

## Writing

- Sentence case everywhere. No all-caps labels.
- Name things by what the user does: "Connect a device", "Online now", not internal terms.
- Buttons say exactly what happens ("Download backup", "Revoke certificates").
- Empty states say what to do next and link to it.
- No filler, no exclamation marks, no apologies.

## Avoid

- The generic generated-dashboard look: purple or blue gradients, identical rounded cards with soft shadows, big-number-plus-gradient hero tiles, glass effects.
- Status shown only by color.
- Decorative numbering, eyebrow labels above every heading, arrows appended to links.
- Features that only work with an internet connection.
