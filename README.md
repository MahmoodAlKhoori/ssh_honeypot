# Simple SSH Honeypot
A lightweight SSH honeypot designed to simulate an SSH server, log connection attempts, and capture credentials.

## Overview

This project sets up a fake SSH server using Python's asyncio and asyncssh libraries. It listens on a specified port (default is 2222), simulates an SSH handshake, and logs details of every connection attempt. While the honeypot denies access, it gathers valuable data such as IP addresses, ports, and attempted credentials

## Features

- **Asynchronous Operation**: Utilizes Python's asyncio framework to handle multiple simultaneous connections efficiently.

- **Detailed Logging**: Captures and logs every connection attempt along with the client's IP, port, and any credentials they try, all stored in honeypot.log.

- **Fake SSH Simulation**: Sends a realistic SSH banner and simulates a login prompt to engage and capture attacker inputs.

- **Temporary Server Keys**: Automatically generates temporary host keys on startup for ease of use during testing. (For longer-term deployments, consider generating persistent keys.)


## Getting Started

### Prerequisites

- Python 3.7+
- asyncssh Library

Install dependencies with:

```bash
pip3 install asyncssh
```

### Running the Honeypot

1. Clone the Repository:

```bash
git clone https://github.com/MahmoodAlKhoori/ssh_honeypot.git
cd ssh-honeypot
```

2. Run the Honeypot:

```bash
python3 honeypot.py
```

3. Monitor Activity: The honeypot will start listening on 0.0.0.0:2222. All connection attempts and credential submissions are logged in honeypot.log.

## Disclaimer

This honeypot is intended for educational and research purposes only. Run it in a controlled and secure environment. Unauthorized use on production systems or networks is strictly prohibited.
