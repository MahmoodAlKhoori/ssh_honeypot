import asyncio
import asyncssh
import logging
import sys


logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s') 

HOST = '0.0.0.0'
PORT = 2222

class SimpleHoneypotServer(asyncssh.SSHServer):
    def __init__(self):
        self._conn = None
    def connection_made(self, conn):
        """Called when a client connects."""
        self._conn = conn
        peer = conn.get_extra_info('peername')
        log_message = f"Connection attempt from: {peer[0]}:{peer[1]}"
        print(log_message)
        logging.info(log_message)
    def connection_lost(self, exc):
        """Called when a client disconnects."""
        peer = self._conn.get_extra_info('peername') if self._conn else ('unknown', 0)
        if exc:
            error_message = f"Connection error from {peer[0]}:{peer[1]}: {exc}"
            print(error_message)
            logging.error(error_message)
        else:
            close_message = f"Connection closed for {peer[0]}:{peer[1]}"
            print(close_message)
            logging.info(close_message)

    def password_auth_supported(self):
        """Signal that password authentication is supported."""
        return True

    def validate_password(self, username, password):
        """Validate the password (always fail but log)."""
        try:
            peer = self._conn.get_extra_info('peername')
            peer_str = f"{peer[0]}:{peer[1]}"
            creds_message = f"Credentials attempt - Username: {username}, Password: {password}"
            print(f"[{peer_str}] {creds_message}")
            logging.info(f"Credentials attempt from {peer_str} - Username: {username}, Password: {password}")
        except Exception as e:
            logging.warning(f"Failed to log credentials attempt (User: {username}): {e}")
        raise asyncssh.AuthFailure('Permission denied.')


async def start_server():
    """Starts the asyncssh honeypot server."""
    print("[*] Generating temporary server keys...")
    server_keys = [asyncssh.generate_private_key('ssh-ed25519')]
    print("[*] Server keys generated.")
    print(f"[*] Honeypot listening on {HOST}:{PORT}")
    logging.info(f"Honeypot started listening on {HOST}:{PORT}")

    try:
        await asyncssh.create_server(
            SimpleHoneypotServer, HOST, PORT,
            server_host_keys=server_keys,
            # Provide lists of supported algorithms as strings
            kex_algs=[
                'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256',
                'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
                'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group14-sha256',
                'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512'
            ],
            encryption_algs=[
                'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
                'aes256-ctr', 'aes192-ctr', 'aes128-ctr',
                'chacha20-poly1305@openssh.com'
            ],
            mac_algs=[
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
                'hmac-sha1-etm@openssh.com',
                'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'
            ],
            signature_algs=[
                'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                'ecdsa-sha2-nistp521', 'ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512',
                'ssh-dss' 
            ]
        )
    except OSError as e:
        error_message = f"Could not bind to port {PORT}. Is it already in use? Error: {e}"
        print(error_message, file=sys.stderr)
        logging.error(error_message)
        sys.exit(1)
    except Exception as e:
        error_message = f"Failed to start server: {e}"
        print(error_message, file=sys.stderr)
        logging.error(error_message)
        sys.exit(1)

    await asyncio.get_event_loop().create_future()


async def main():
    """Main entry point."""
    try:
        await start_server()
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot server.")
        logging.info("Honeypot server shutting down.")
    except OSError as e:
        if "address already in use" in str(e):
             error_message = f"Could not bind to port {PORT}. Is it already in use? Error: {e}"
             print(error_message, file=sys.stderr)
             logging.error(error_message)
        else:
             print(f"An unexpected OS error occurred: {e}", file=sys.stderr)
             logging.error(f"An unexpected OS error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        logging.exception("An unexpected error occurred:")
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass 