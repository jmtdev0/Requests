import argparse
import socket
import ssl
import sys


SERVER_TIMEOUT = 15


def create_context(certificate, key):
    protocol = getattr(ssl, "PROTOCOL_TLS_SERVER", ssl.PROTOCOL_TLS)
    context = ssl.SSLContext(protocol)
    context.load_cert_chain(certificate, key)
    return context


def create_listener(port):
    if socket.has_ipv6:
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            v6_only = getattr(socket, "IPV6_V6ONLY", None)
            if v6_only is not None:
                listener.setsockopt(socket.IPPROTO_IPV6, v6_only, 0)
            listener.bind(("::", port))
            return listener
        except OSError:
            if "listener" in locals():
                listener.close()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    return listener


def serve(arguments):
    correct_context = create_context(arguments.correct_cert, arguments.correct_key)
    wrong_context = create_context(arguments.wrong_cert, arguments.wrong_key)

    def select_certificate(ssl_socket, server_name, _context):
        if server_name == arguments.expected_name:
            ssl_socket.context = correct_context

    wrong_context.set_servername_callback(select_certificate)

    listener = create_listener(arguments.port)
    listener.listen(1)
    listener.settimeout(SERVER_TIMEOUT)

    try:
        print("PORT={}".format(listener.getsockname()[1]), flush=True)
        connection, _address = listener.accept()
        try:
            secure_connection = wrong_context.wrap_socket(connection, server_side=True)
            with secure_connection:
                request = b""
                while b"\r\n\r\n" not in request and len(request) < 65536:
                    chunk = secure_connection.recv(4096)
                    if not chunk:
                        break
                    request += chunk

                if request:
                    secure_connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
        except (OSError, ssl.SSLError) as error:
            print("{}: {}".format(type(error).__name__, error), file=sys.stderr)
            return 1
    except socket.timeout:
        print("Timed out waiting for the SNI test request.", file=sys.stderr)
        return 1
    finally:
        listener.close()

    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--correct-cert", required=True)
    parser.add_argument("--correct-key", required=True)
    parser.add_argument("--wrong-cert", required=True)
    parser.add_argument("--wrong-key", required=True)
    parser.add_argument("--expected-name", required=True)
    parser.add_argument("--port", type=int, default=0)
    arguments = parser.parse_args()
    return serve(arguments)


if __name__ == "__main__":
    sys.exit(main())
