import argparse


def get_cli_args():
    parser = argparse.ArgumentParser(description="Algorithm Visualizer")
    parser.add_argument("-protocol", default='tcp', dest="protocol", help="Enter protocol to use (tcp)",
                        choices=["tcp"])
    parser.add_argument("-port", default='443', dest="port", help="Enter port number",
                        choices=[443])
    return parser.parse_args()