# vscan-port-knocking-detector

Tests a TCP port knocking sequence: it makes TCP connection attempts to a sequence of knock ports in order, waits, and then checks whether a chosen hidden port is open. It can be used to audit a custom TCP port knocking scheme you control.

## Install

`git clone https://github.com/ShadowGuard-AI/vscan-port-knocking-detector`

No third-party packages are required (Python standard library only, see requirements.txt).

## Usage

`python3 main.py <target_host> <knock_port> [more knock ports] --hidden_port <port> [--timeout SECONDS] [--delay SECONDS] [--wait_for_response SECONDS] [--verbose]`

Example: `python3 main.py 127.0.0.1 7000 8000 9000 --hidden_port 22`

## Parameters

- `target_host`: Target host IP address or hostname (positional, required)
- `knock_ports`: Sequence of ports to knock on, in order (positional, at least one)
- `--hidden_port`: Port to check for a response after knocking (required)
- `--timeout`: Timeout in seconds for socket operations (default: 5)
- `--delay`: Delay between knocking attempts in seconds (default: 0.1)
- `--wait_for_response`: Wait time after the knock sequence before checking the hidden port (default: 5)
- `--verbose`: Enable verbose output

Ports must be between 1 and 65535, the timeout must be positive, the delay and wait must be non-negative, and the target host must resolve, otherwise the tool exits non-zero.

## Behaviour notes

Knocks are full TCP connection attempts; there is no UDP mode. The hidden port is checked once before the knock sequence as well as once after the wait. If the hidden port was already open before knocking, the run reports that port knocking is not demonstrated, instead of claiming success. If it was closed before and open after, the run reports port knocking successful. Only one post-knock check is made, after the single fixed wait, so a port that opens and closes inside that window, or opens more slowly than the wait, is reported as closed.

## License

MIT (see LICENSE)
