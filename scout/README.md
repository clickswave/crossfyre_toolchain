# scout

Service enumeration and web fingerprinting. Once you know a host has something
listening, scout works out what it is: the web server, frameworks, libraries, and
their versions where it can pin them down. When it can tie a version to a known CVE,
it flags that as a lead worth checking.

Part of the [Crossfyre toolchain](../).

## How it runs

scout is a daemon. Start it, then send it targets:

```sh
# start the daemon (default port 4444)
scout --daemon

# fingerprint a target through the running daemon
scout fingerprint --target https://example.com
```

`exec` sends a raw JSON op to the daemon and streams the events back, which is what
the node uses under the hood:

```sh
scout exec '{"operation":"fingerprint","target":"https://example.com"}'
```

## What you get

Detected technologies and versions for the target, plus any version-based CVE leads.
A lead is not a confirmed vulnerability; it is a "this version is known to have had X,
go look." For actually confirming a bug, hand the target to [`cortex`](../cortex/).

## Notes

Fingerprinting is mostly passive (it reads what the server volunteers) but it still
sends requests, so keep to targets you are allowed to touch.
