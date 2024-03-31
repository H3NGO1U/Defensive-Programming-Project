DEFAULT_PORT = 1256

def read_port():
    try:
        with open('port.info', 'r') as port_info:
            port = int(port_info.read())
            print(f'Port read from file: {port}')
    except (FileNotFoundError, ValueError):
        port = DEFAULT_PORT

    return port
    