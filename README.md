# Description

**Utility for sniffing SSL/TLS encrypted traffic on a darwin-based platforms.**

`CFNetwork.framework` contains a debug/verbosity global, enforcing a dump of every packet transferred through it, to be
logged into device syslog in plaintext form. In order to have a nicer view with clean control flow of this traffic, we
attach each such packet appropriate TCP flags and write it back into a PCAP file.

This allows us to later dissect this traffic using popular and convenient tools (e.g. Wireshark 🦈).

On iOS, this will require a jailbroken iOS device.

# Installation

```shell
python3 -m pip install -U darwin-ssl-sniffer
```

# Usage

## Local macOS machine

Simply execute:

```shell
# output file can be given using the -o option (traffic.pcapng by default)
python3 -m darwin_ssl_sniffer sniff
```

## Jailbroken iOS device

- Download and install [`rpcserver`](https://rpc-project.readthedocs.io/en/latest/getting_started/installation.html) on
  a jailbroken device.
- Execute:
  ```shell
  python3 -m darwin_ssl_sniffer mobile setup -p 5910
  ```
  This step should be performed only once on the device. The first time will require a device reboot (you will be
  prompted to if this is indeed the first time).
- Execute:
  ```shell
  # output file can be given using the -o option (traffic.pcapng by default)
  python3 -m darwin_ssl_sniffer mobile sniff
  ```





