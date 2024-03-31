from server import Server
from port import read_port

HOST = 'localhost'

def main():
    server = Server(HOST, read_port())
    server.run()

if __name__=='__main__':
    main()    