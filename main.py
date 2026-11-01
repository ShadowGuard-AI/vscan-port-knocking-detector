import argparse
import logging
import socket
import sys
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the port knocking detector.
    """
    parser = argparse.ArgumentParser(description="Detects port knocking implementations.")
    parser.add_argument("target_host", help="Target host IP address or hostname")
    parser.add_argument("knock_ports", nargs="+", type=int, help="Sequence of ports to knock on")
    parser.add_argument("--hidden_port", type=int, required=True, help="Port to check for a response after knocking")
    parser.add_argument("--timeout", type=float, default=5, help="Timeout in seconds for socket operations")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between knocking attempts")
    parser.add_argument("--wait_for_response", type=float, default=5, help="Wait time for response after knocking sequence is complete")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    return parser

def knock_ports(target_host, knock_ports, timeout, delay):
    """
    Sends packets to the specified ports in the sequence to simulate port knocking.

    Args:
        target_host (str): The target host IP address or hostname.
        knock_ports (list): A list of integers representing the ports to knock on.
        timeout (float): Timeout in seconds for socket operations.
        delay (float): Delay in seconds between knocking attempts.
    """
    try:
        for port in knock_ports:
            # Knocks are full TCP connection attempts. There is no UDP
            # mode anywhere, so a sequence defined over UDP ports
            # cannot be tested by this tool at all, and a filtered TCP
            # port costs a whole timeout per knock before the sequence
            # moves on.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:  # Using TCP for knocking
                sock.settimeout(timeout)
                logging.info(f"Knock attempt on port {port} on {target_host}")
                try:
                    sock.connect((target_host, port))
                    logging.info(f"Knocking on port {port} on {target_host}")
                except socket.timeout:
                    logging.info(f"Knock attempt on port {port} on {target_host} completed: no reply (closed or filtered port, the normal case).")
                except socket.error:
                    logging.info(f"Knock attempt on port {port} on {target_host} completed: connection refused or unreachable (closed or filtered port, the normal case).")
                time.sleep(delay)
    except Exception as e:
        logging.error(f"An unexpected error occurred during port knocking: {e}")
        sys.exit(1)


def check_hidden_port(target_host, hidden_port, timeout):
    """
    Checks if the hidden port is open after the port knocking sequence.

    Args:
        target_host (str): The target host IP address or hostname.
        hidden_port (int): The port to check for a response.
        timeout (float): Timeout in seconds for the socket operation.

    Returns:
        bool: True if the hidden port is open, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:  # Using TCP to check hidden port
            sock.settimeout(timeout)
            try:
                sock.connect((target_host, hidden_port))
                logging.info(f"Hidden port {hidden_port} on {target_host} is open!")
                return True
            except socket.timeout:
                logging.info(f"Connection to hidden port {hidden_port} on {target_host} timed out. Port likely closed.")
                return False
            except socket.error as e:
                logging.info(f"Error connecting to hidden port {hidden_port} on {target_host}: {e}. Port likely closed.")
                return False
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking the hidden port: {e}")
        return False

def validate_arguments(args):
    """
    Validates the command-line arguments.

    Args:
        args (argparse.Namespace): The parsed arguments.

    Returns:
        bool: True if arguments are valid, False otherwise.  Prints error messages to stderr.
    """
    try:
        if not args.knock_ports:
            print("Error: At least one knock port must be specified.", file=sys.stderr)
            return False

        if any(not isinstance(port, int) or port <= 0 or port > 65535 for port in args.knock_ports):
            print("Error: Knock ports must be integers between 1 and 65535.", file=sys.stderr)
            return False

        if not isinstance(args.hidden_port, int) or args.hidden_port <= 0 or args.hidden_port > 65535:
            print("Error: Hidden port must be an integer between 1 and 65535.", file=sys.stderr)
            return False

        if args.timeout <= 0:
            print("Error: Timeout must be a positive number.", file=sys.stderr)
            return False

        if args.delay < 0:
            print("Error: Delay must be a non-negative number.", file=sys.stderr)
            return False

        if args.wait_for_response < 0:
            print("Error: wait_for_response must be a non-negative number.", file=sys.stderr)
            return False

        #Attempt to resolve hostname immediately for error checking.
        try:
            socket.gethostbyname(args.target_host)
        except socket.gaierror:
            print(f"Error: Could not resolve hostname '{args.target_host}'.", file=sys.stderr)
            return False


    except Exception as e:
        print(f"Error during argument validation: {e}", file=sys.stderr)
        return False

    return True  # Arguments are valid.


def main():
    """
    Main function to execute the port knocking detection.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not validate_arguments(args):
        sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose output enabled.")

    target_host = args.target_host
    knock_port_list = args.knock_ports
    hidden_port = args.hidden_port
    timeout = args.timeout
    delay = args.delay
    wait_for_response = args.wait_for_response

    logging.info(f"Starting port knocking detection on {target_host}")

    try:
        # Nobody checks the hidden port before the sequence runs. If
        # it was already open, the check below passes and the run
        # reports port knocking where there may be none at all. A
        # detector needs the before state to claim the knock changed
        # anything, and this one never takes it.
        knock_ports(target_host, knock_port_list, timeout, delay)
        logging.info(f"Waiting {wait_for_response} seconds for a response on the hidden port {hidden_port}...")
        time.sleep(wait_for_response)
        # Exactly one check, after one fixed wait. A daemon that opens
        # the port briefly and closes it again inside that window, or
        # one slower than the wait, is reported as no knocking found.
        if check_hidden_port(target_host, hidden_port, timeout):
            logging.info("Port knocking successful! Hidden port is open.")
        else:
            logging.info("Port knocking unsuccessful. Hidden port is closed.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    logging.info("Port knocking detection completed.")


if __name__ == "__main__":
    # Usage Examples:
    # python vscan-port-knocking-detector.py 127.0.0.1 1000 2000 3000 --hidden_port 4000
    # python vscan-port-knocking-detector.py example.com 7777 8888 --hidden_port 9999 --timeout 2 --delay 0.5
    # python vscan-port-knocking-detector.py example.com 22 23 24 --hidden_port 25 --verbose
    # python vscan-port-knocking-detector.py 192.168.1.100 5000 5001 5002 --hidden_port 5003 --wait_for_response 10
    main()