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
                logfile.write("server_conn address: " + flow.server_conn.address.host + "\n")
                if flow.server_conn.ip_address:
                    logfile.write("host: " + flow.request.pretty_host + ",ip: " + flow.server_conn.ip_address.host + "\n")
                elif flow.server_conn.address:
                    logfile.write("host: " + flow.request.pretty_host + ",ip: " + flow.server_conn.address.host + "\n")
                else:
                    logfile.write("host: " + flow.request.pretty_host + ",NO IP ADDRESS" + "\n")

                logfile.write("url: " + flow.request.pretty_url + "\n")
        elif flow.server_conn.protocol == "http":
            with open(self.logfile, "a") as logfile:
                logfile.write("http host: " + "http://" + flow.request.pretty_host +
                              ",ip: " + flow.server_conn.ip_address.host + "\n")
                logfile.write("http url: " + "http://" + flow.request.pretty_url + "\n")
