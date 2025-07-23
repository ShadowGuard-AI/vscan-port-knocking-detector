# vscan-port-knocking-detector
Attempts to detect port knocking implementations by sending a sequence of packets to specified ports and monitoring for a response on a 'hidden' port. Can also be used to audit custom port knocking schemes. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-port-knocking-detector`

## Usage
`./vscan-port-knocking-detector [params]`

## Parameters
- `--hidden_port`: Port to check for a response after knocking
- `--timeout`: Timeout in seconds for socket operations
- `--delay`: Delay between knocking attempts
- `--wait_for_response`: Wait time for response after knocking sequence is complete
- `--verbose`: Enable verbose output

## License
Copyright (c) ShadowGuardAI
