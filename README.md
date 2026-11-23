# rdcli

A console RustDesk client in Go: a remote shell, port forwarding and file
copy over the RustDesk protocol, through your own RustDesk server (hbbs/hbbr,
RD Panel). One static binary for Linux, macOS and Windows; no GUI, no
RustDesk install needed on your side.

```sh
rdcli shell 123456789                     # a shell on the device (~. disconnects)
rdcli forward 123456789 -L 2222:22        # localhost:2222 -> port 22 of the device
ssh -o ProxyCommand="rdcli pipe 123456789 %h:%p" user@localhost
rdcli cp -r ./site 123456789:/srv/        # copy files both ways
```

The device runs the ordinary RustDesk client (1.4.1+ for the terminal, 1.5+
for multiplexed forwarding). Nothing is installed or changed on it; it decides
who gets in with its password, 2FA, or a click on "Accept", exactly as for the
desktop client.

## Install

Download a binary from the releases, or build it (Go 1.27+):

```sh
go install github.com/bropines/rdcli/cmd/rdcli@latest
```

## Set up a server

If a RustDesk client on this machine is already configured for your server,
take its settings:

```sh
rdcli server import            # reads RustDesk2.toml: ID server, relay, key, API server
```

Otherwise:

```sh
rdcli server add home --id-server rd.example.com --key 'OeVuKk5...=' --api https://panel.example.com
```

- `--id-server`: hbbs as `host[:21116]` (TCP), or `wss://host/ws/id` behind a
  reverse proxy.
- `--relay`: hbbr as `host[:21117]` or a `wss://` URL. Default: the relay hbbs
  announces (TCP), or `/ws/relay` next to a WebSocket ID server.
- `--key`: the server's public key (`id_ed25519.pub`). **Required**: rdcli
  verifies the device's identity with it and refuses to connect without it.
- `--api`: the API server (RD Panel), for `rdcli login` and the address book.

Profiles live in `~/.config/rdcli/config.json` (Windows:
`%APPDATA%\rdcli\config.json`; `RDCLI_CONFIG` overrides), mode 0600. Every
connection flag can also be given per command (`--server`, `--id-server`,
`--relay`, `--key`, `--token`) or by environment (`RDCLI_ID_SERVER`,
`RDCLI_RELAY`, `RDCLI_KEY`, `RDCLI_TOKEN`).

## Sign in to the API server

Servers that run hbbs with `MUST_LOGIN=Y` let only signed-in clients connect.
Signing in also gives rdcli your address book:

```sh
rdcli login                    # asks for user, password and, if enabled, the 2FA code
rdcli peers                    # devices in your address books
rdcli peers office             # filter
rdcli logout
```

## Remote shell

```sh
rdcli shell 123456789
rdcli shell office-pc          # an alias from the config
rdcli shell 123456789 -c 'uptime'          # type a command, then exit
echo 'df -h; exit' | rdcli shell 123456789 # non-interactive
```

- The device runs the user's shell (PowerShell/cmd on Windows). The terminal
  size follows yours; Ctrl+C and full-screen programs work.
- Escapes at the start of a line, as in ssh: `~.` disconnects, `~~` types a
  `~`, `~?` lists them (`-e none` turns them off).
- `--persistent` keeps the shell running when you disconnect; reattach with
  `rdcli shell <id> --service <id printed on exit>`.
- `--os-user Administrator` (Windows devices): run the shell under the
  device's own account by proving an administrator account of that device.
- The exit code of the remote shell is rdcli's exit code.

The device needs the terminal permission (RustDesk: Settings > Security >
Permissions > "Enable terminal").

## Port forwarding

```sh
rdcli forward 123456789 -L 2222:22                       # localhost:2222 -> device:22
rdcli forward 123456789 -L 8080:10.0.0.5:80 -L 13389:localhost:3389
rdcli forward 123456789 -L 0.0.0.0:8080:intranet:80      # listen on all interfaces
```

`-L [bind_address:]port:host:hostport`, where `host` is resolved **on the
device** (`localhost` is the device itself). Each `-L` is one mapping; a
mapping only reaches the one target it was logged in for.

`rdcli pipe` connects stdin/stdout to one target, for tools that take a proxy
command:

```sh
ssh -o ProxyCommand="rdcli pipe 123456789 %h:%p" user@localhost
# ~/.ssh/config
Host office
    HostName localhost
    User me
    ProxyCommand rdcli pipe 123456789 %h:%p
```

Two modes, picked automatically:

- **Multiplexed** (RustDesk 1.5+ devices): one login, one encrypted link; every
  local connection is a channel on it, with per-channel flow control.
- **Legacy** (older devices): one login per local connection, and — this is how
  RustDesk itself forwards for such devices — **the data is not encrypted after
  the login** between you and the device (the relay sees it in the clear).
  rdcli warns when a mapping runs in this mode. Tunnel only protocols that
  encrypt themselves (SSH, RDP with TLS, HTTPS) through such devices, or use
  `--mux` to refuse it. This mode needs a TCP relay (hbbr pipes raw bytes only
  between TCP legs); through a WebSocket relay rdcli refuses it.

The device needs the tunnel permission ("Enable TCP tunneling").

## Files

```sh
rdcli ls 123456789:              # the remote home directory
rdcli ls 123456789:/var/log
rdcli cp report.pdf 123456789:Desktop/
rdcli cp 123456789:/etc/hosts .
rdcli cp -r 123456789:projects/site ./backup
```

Remote paths use the device's own syntax (`C:\Users\me` on Windows); a
relative path starts at the remote user's home. The device needs the file
transfer permission.

## Passwords

rdcli looks for the device password in this order:

1. `--password-stdin` (first line of stdin; not for `shell` and `pipe`) or
   `RDCLI_PASSWORD`;
2. a password remembered with `--remember` (stored as the device's salted hash,
   `SHA256(password + salt)`, like the RustDesk client: it is not the password,
   but it logs in to that device, so treat the config file as a secret;
   `rdcli forget <id>` drops it);
3. the address book entry, when you are signed in (its saved password hash or
   shared password);
4. otherwise it asks on the terminal (also when stdin is a pipe).

`--approval` sends no password at all and waits up to two minutes for the
person at the device to click "Accept". Devices set to accept by click only
always work this way.

## Security notes

- The device's identity is verified end to end: hbbs signs the device's
  long-term key with the server key you configured, and the device signs its
  session key with that long-term key. A relay or a fake hbbs cannot read or
  change a session (except legacy forwarding, above).
- Key exchange version 1 (separate keys per direction, bound to the handshake)
  is used when the device and hbbs offer it; version 0 otherwise.
- The access token goes only to the server of the profile it came from (not to
  an ID server named with `--id-server`, unless `--token` is given), never to
  the relay, and never over an unencrypted `ws://` link.
- With TCP to hbbs, rdcli runs hbbs' key exchange and never sends the access
  token over an unencrypted connection.
- The access token from `rdcli login` and remembered hashes are stored in the
  config file (0600).

## Exit codes

`0` success; the remote shell's exit code for `shell`; `1` error; `2` bad
command line; `130` interrupted.

## Development

```sh
go test ./...                       # unit tests and end-to-end tests against an in-process
                                    # fake hbbs/hbbr/device (internal/testpeer)
go build ./cmd/rdcli
```

The protocol definitions in `proto/` are shared with rdweb (written for these
projects, byte-compatible with RustDesk); regenerate with
`go run github.com/bufbuild/buf/cmd/buf@v1.59.0 generate`.

## License

MIT, see [LICENSE](LICENSE) and [NOTICE](NOTICE).

RustDesk is a trademark of its respective owners (Purslane Ltd.). rdcli is an
independent client that speaks the RustDesk network protocol; it is not
affiliated with or endorsed by RustDesk or Purslane Ltd. No RustDesk source
code is included.
