# DNS Ghoib

DNS Poisoning tool, to manipulate ARP (Address Resolution Protocol)

## Usage

```shell
Usage: main.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  scanip
  spoof
```

## Spoofing DNS

**Short usage**
```shell
$ python main.py spoof --target-ip <target-ip?> --gateway-ip <gateway-ip?>
```
Option are optional, if you not provide you will get asked

## Scanning Local IP

```shell
$ python main.py scanip --ip-range start:end
```
IP range option are optional, default is 0:20