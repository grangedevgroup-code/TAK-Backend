# Security

## Reporting a vulnerability

Report security problems privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Please do not open a public issue for a security problem.

Include what you found, how to reproduce it, and which version you tested (`golangtak version`). You will get an answer, and a fix will be released as soon as it is ready. Reporters are credited in the release notes unless they prefer not to be.

## Supported versions

Only the newest GolangTAK release receives security fixes. Running the install command again upgrades in place and keeps all data.

## What GolangTAK protects, and what it does not

- Connections on the SSL port (8089), the HTTPS ports (8443, 8446) and federation are encrypted and authenticated with certificates or passwords.
- The plain TCP port (8087), UDP input, multicast and the HTTP dashboard on 8080 are not encrypted. Anyone on the network can read that traffic, and when anonymous access is on, anyone who can reach those ports can send and receive CoT and use the Marti API as an anonymous device. On untrusted networks install with `--no-anonymous` and use certificates.
- Anonymous devices share one identity. They can change or delete what other anonymous devices uploaded, but not what signed-in users uploaded.
- Groups separate traffic, history, files, missions and video between users. Administrators see everything.
- Server plugins run with the operating system rights of the GolangTAK service. They can only be added on the server itself, not from the dashboard.
- Link codes and connection packages contain private keys. Send them privately.
- Backups contain the certificate authority's private key. Store them safely.
