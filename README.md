# Description

**Utility for sniffing SSL/TLS encrypted traffic on a jailbroken iOS device.**

`CFNetwork.framework` contains a debug/verbosity global, enforcing a dump of every packet transferred through it, to be
logged into device syslog in plaintext form. In order to have a nicer view with clean control flow of this traffic, we
attach each such packet appropriate TCP flags and write it back into a PCAP file.

This allows us to later dissect this traffic using popular and convenient tools (e.g. Wireshark 🦈).
Assuming you have a jailbroken iOS device, this Python3 tool can automate this process.

# Installation

```shell
python3 -m pip install -U iosslsniffer
```

# Prerequisites

## Enable logging global

This package relies on the ability to modify Apples logging global, Thus requires a jailbroken device.
In addition, a global preference key is need to set `AppleCFNetworkDiagnosticLogging`.

### Howto

- Download and install [`rpc_server`](https://rpc-project.readthedocs.io/en/latest/getting_started/installation.html) on
  a jailbroken device.
- Setting logging global, this can be done manually or using the integrated `rpc_client` in the sniffer.
  - To use integrated `rpc_client` just provide the `rpc_server` port:
      ```shell
      python3 -m iosslsniffer setup -p 5910
      python3 -m iosslsniffer sniff
      ```
  - Manually connect to `rpc_server`:
    - Set `AppleCFNetworkDiagnosticLogging` to 3 (restart required)
    - Execute `p.syslog.set_harlogger_for_all(True)`
      ```shell
      user@Users-Mac-mini-7 ~/ @ rpcclient 127.0.0.1
      Welcome to the rpcclient interactive shell! You interactive shell for controlling the remote rpcserver.
      Feel free to use the following globals:
  
      🌍 p - the injected process
      🌍 symbols - process global symbols
  
      Have a nice flight ✈️!
      Starting an IPython shell... 🐍
  
      In [1]: pref = p.preferences.sc.open('/private/var/Managed Preferences/mobile/.GlobalPreferences.plist')
      In [2]: pref.set('AppleCFNetworkDiagnosticLogging',3)
      
      restart.........
      
      In [1]: p.syslog.set_harlogger_for_all(True)
      ```

## CFNetworkDiagnostics

In order to enable `CFNetworkDiagnostics` the key `AppleCFNetworkDiagnosticLogging` needs to be set, this is done as
part of `iosslsniffer setup` command.
A restart is required incase the key was not set.

# Usage

```shell
Usage: python -m iosslsniffer [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  setup  Setup all prerequisites required inorder to sniff the SSL traffic
  sniff  Sniff the traffic
```

