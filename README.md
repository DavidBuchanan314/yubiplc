# yubiplc
A bare-bones CLI tool for signing did:plc operations with a yubikey

(It works, but it is not useful on its own - writeup/docs coming soon)

```
NAME:
   yubiplc - yubikey did:plc stuff

USAGE:
   yubiplc [global options] [command [command options]]

COMMANDS:
   init     generate a new NIST-P256 private key on the yubikey, overwriting slot 9C
   pubkey   print the corresponding public key to stdout, in did:key format
   sign     sign a did:plc operation (reads and writes JSON on stdio)
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```
