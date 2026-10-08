"use strict";

window.ICONS = {
  overview: "M4 4h7v7H4z M13 4h7v7h-7z M4 13h7v7H4z M13 13h7v7h-7z",
  map: "M3 6l6-2 6 2 6-2v14l-6 2-6-2-6 2z M9 4v14 M15 6v14",
  chat: "M4 5h16v11H10l-6 4z M8 9h8 M8 12h5",
  connect: "M4 4h6v6H4z M14 4h6v6h-6z M4 14h6v6H4z M14 14h2v2h-2z M18 18h2v2h-2z M14 18v2 M18 14h2",
  online: "M12 13.5a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3z M8.5 8.5a5 5 0 0 0 0 7 M15.5 8.5a5 5 0 0 1 0 7 M5.6 5.6a9 9 0 0 0 0 12.8 M18.4 5.6a9 9 0 0 1 0 12.8",
  devices: "M7 3h10v18H7z M11 18h2",
  files: "M6 3h8l4 4v14H6z M14 3v4h4 M9 12h6 M9 16h6",
  missions: "M5 21V4 M5 4h13l-3 4 3 4H5",
  layers: "M12 3l9 5-9 5-9-5z M3 13l9 5 9-5 M3 17.5l9 5 9-5",
  video: "M3 6h12v12H3z M15 10l6-3v10l-6-3",
  users: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M4 21c0-4 3.5-6.5 8-6.5s8 2.5 8 6.5",
  groups: "M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z M2 20c0-3.5 3-5.5 7-5.5s7 2 7 5.5 M15.5 4.3a3.5 3.5 0 0 1 0 6.4 M18 14.8c2.4.7 4 2.5 4 5.2",
  links: "M10 14l4-4 M9 11l-2.5 2.5a3.5 3.5 0 0 0 5 5L14 16 M15 13l2.5-2.5a3.5 3.5 0 0 0-5-5L10 8",
  plugins: "M3 7l9-4 9 4v10l-9 4-9-4z M3 7l9 4 9-4 M12 11v10",
  settings: "M4 6h9 M17 6h3 M13 4v4 M17 4v4 M4 12h3 M11 12h9 M7 10v4 M11 10v4 M4 18h11 M19 18h1 M15 16v4 M19 16v4",
  logs: "M4 5h16 M4 10h16 M4 15h11 M4 20h7",
  tokens: "M8 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M12 12h9 M18 12v3 M21 12v4",
  account: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M12 12.5a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M6.3 18.6c1.3-2 3.3-3.1 5.7-3.1s4.4 1.1 5.7 3.1",
  search: "M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13z M15.5 15.5L21 21",
  alert: "M12 3l10 18H2z M12 10v5 M12 17v2",
  plus: "M12 5v14 M5 12h14",
  menu: "M4 6h16 M4 12h16 M4 18h16",
  signout: "M14 4h6v16h-6 M10 8l-4 4 4 4 M6 12h10",
  download: "M12 4v11 M7 10l5 5 5-5 M4 20h16",
  upload: "M12 16V5 M7 10l5-5 5 5 M4 20h16",
  check: "M5 12.5l4.5 4.5L19 7.5",
  close: "M6 6l12 12 M18 6L6 18",
  trash: "M4 7h16 M9 7V4h6v3 M6 7l1 14h10l1-14",
  edit: "M4 20h4L19 9l-4-4L4 16z M13 7l4 4",
  restart: "M20 12a8 8 0 1 1-2.4-5.7 M20 4v5h-5",
  copy: "M8 8h12v12H8z M4 16V4h12",
  send: "M4 12l16-8-6 16-3-7z M11 13l9-9",
  key: "M8 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M12 12h9 M18 12v3 M21 12v4",
  certificate: "M4 4h16v12H4z M8 8h8 M8 11h5 M15 17.5a2 2 0 1 0 0-4 2 2 0 0 0 0 4z M14 17v4l1-1 1 1v-4",
  shield: "M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z",
  radio: "M6 9h12v11H6z M9 9l7-5 M12 13.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z",
  plane: "M12 3v18 M3 13l9-4 9 4 M8 21l4-2 4 2",
  pulse: "M3 12h4l3-7 4 14 3-7h4",
  cpu: "M7 7h10v10H7z M10 10h4v4h-4z M10 3v4 M14 3v4 M10 17v4 M14 17v4 M3 10h4 M3 14h4 M17 10h4 M17 14h4",
  memory: "M3 7h18v10H3z M7 11v2 M11 11v2 M15 11v2 M6 17v3 M18 17v3",
  disk: "M4 5h16v14H4z M4 14h16 M16.5 16.5h.5",
  external: "M14 4h6v6 M20 4l-9 9 M18 14v6H4V6h6",
};

window.icon = function (name, size) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  const s = String(size || 18);
  svg.setAttribute("width", s);
  svg.setAttribute("height", s);
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.75");
  svg.setAttribute("stroke-linecap", "square");
  svg.setAttribute("stroke-linejoin", "miter");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("class", "icon");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", window.ICONS[name] || window.ICONS.overview);
  svg.append(path);
  return svg;
};
