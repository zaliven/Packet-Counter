import argparse


def get_cli_args():
    parser = argparse.ArgumentParser(description="Algorithm Visualizer")
    parser.add_argument("-protocol", default='tcp', dest="protocol", help="Enter protocol to use (tcp)",
                        choices=["tcp"])
    parser.add_argument("-port", default='445', dest="port", help="Enter port number",
                        choices=['443', '445', '80'])
    return parser.parse_args()
