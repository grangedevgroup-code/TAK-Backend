# Dashboard design rules

The dashboard is a console for people running a TAK server, often on a laptop in the field, a tablet or a phone, with divided attention and sometimes no internet. It should feel like a calm, expensive instrument: quiet chrome, loud data, nothing decorative.

## What we learned from other TAK dashboards

- FreeTAKServer shipped its web UI as a separate program with its own install, port and database. Users could sign in and then see red status dots with no explanation, and changing IP or port settings from the UI could crash the server.
- OpenTAKServer's UI is a separate React application. Its live updates broke behind proxies and from remote browsers, devices without a `takv` element never appeared on the map, data package uploads failed, and plugin pages showed stale data.
- Control-room research (SKA telescope operations, network operations centres) finds the same failures: too much low-signal data, critical state buried among detail, destructive actions without confirmation.

## What we took from well-regarded product design

- Linear's 2024 and 2026 redesigns: navigation recedes so content leads ("not every element should carry equal visual weight"), dividers are softened so structure is "felt, not seen", the gray is a warm neutral rather than blue-tinted, and surfaces step up in lightness with elevation.
- Enterprise typography guidance: a fixed type scale, one family with several weights, tabular figures for numbers in columns.
- Command-and-control software (Anduril Lattice is described as map-centric and closer to a consumer app than a military terminal): the map and live state are the product.

## Rules

1. One program. The dashboard is embedded in the server binary and served from the same origin as the API and live stream. No build step, no external requests except map tiles.
2. State in words. Every status is a labelled pill ("connected", "problem"), never a bare colored dot. Problems say what is wrong and where to fix it.
3. Most important first. An active emergency becomes a full-width banner on every page. The overview then shows setup progress, who is online, emergencies, links and server load. Ports, certificates and host details are folded away.
4. One primary action per page, top right.
5. Every growing list has a filter box.
6. Destructive actions ask first and say what will happen.
7. Settings are grouped into sections and saved together; the save bar always shows whether there are unsaved changes.
8. Keyboard first: Ctrl+K or / opens "go to"; every control has a visible focus ring.
9. Works at phone width.
10. Live means live: the strip shows "Live" or "Reconnecting".
11. Performance is visible: CPU, memory, disk, load and message rates are sampled every two seconds and shown with ten minutes of history.

## Visual language

- Charcoal, not black. Dark theme surfaces: sidebar `#161618`, page `#1c1c1f`, panels `#232326`, dialogs `#2b2b2f`. Borders are white at 7.5% to 14% opacity. Text `#ececec`, secondary `#a3a3a9`, tertiary `#6f6f76`. The light theme mirrors this on `#f4f4f3` with white panels.
- Square corners everywhere. No border radius.
- Color carries meaning only. Green is healthy or online, amber is a warning, red is an emergency or failure, and muted cyan (ATAK's default team color) marks selection, focus and chart lines. Primary buttons are off-white on charcoal, not colored.
- Map markers use the standard affiliation colors TAK users already know: friendly cyan, hostile red, neutral green, unknown yellow. The basemap is darkened in the dark theme so markers stand out.
- Type: Atkinson Hyperlegible Next and Mono, embedded in the binary, drawn by the Braille Institute so 0/O and 1/l/I stay distinct in callsigns, UIDs, coordinates and passwords. 14px base, headings tightened to -0.02em, numbers in tables tabular.
- Panels with a header row group related content. Stats are one segmented strip, not separate cards. Elevation comes from surface lightness; shadows are used only for overlays (dialogs, menus, toasts).
- The only decorative element is a faint coordinate grid, used on the sign-in screen and in empty states.
- Icons: one hand-drawn 24px outline set with square ends (`static/icons.js`), always beside a text label. No emoji.
- Motion: 120 ms hover and focus transitions, a short fade for dialogs, and the blinking reconnect indicator. Reduced motion turns all of it off.

## Charts

- One metric per chart, never two axes. A single series needs no legend; the panel title names it.
- 2px line, area wash at 10% opacity, hairline gridlines, the latest value labelled at the end of the line.
- Hover or keyboard focus shows a crosshair and a tooltip with the value first and the time second.
- Capacity meters turn amber at 75% and red at 90%, and say "High" or "Critical" in text.

## Writing

- Sentence case everywhere. No all-caps labels.
- Name things by what the user does: "Connect a device", "Online now".
- Buttons say exactly what happens ("Download backup", "Revoke certificates").
- Empty states say what to do next and link to it.
- No filler, no exclamation marks, no apologies.

## Avoid

- Purple or blue gradients, glass effects, rounded cards with soft shadows, a big-number hero with a gradient.
- Status shown only by color.
- Decorative numbering, eyebrow labels above headings, arrows appended to links.
- Anything that needs an internet connection.
