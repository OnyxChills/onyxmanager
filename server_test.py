from onyxmanager import Master

if __name__ == '__main__':
    master = Master.Master()

    master.server.serve_forever()
