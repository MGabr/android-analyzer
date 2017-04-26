import argparse


def start():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", type=str)
    args = parser.parse_args()
    return Logger(args.logfile)


class Logger:
    def __init__(self, logfile):
        self.logfile = logfile
        file_to_create = open(self.logfile, "a")
        file_to_create.close()

    def request(self, flow):
        if flow.client_conn.tls_established:
            with open(self.logfile, "a") as logfile:
                logfile.write("host: " + flow.request.pretty_host + "\n")
                logfile.write("url: " + flow.request.pretty_url + "\n")
