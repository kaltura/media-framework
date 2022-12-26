import sys
import os

status = 0

def report_err(msg):
    global status

    sys.stderr.write(msg + '\n')
    status = 1

def exit():
    sys.exit(status)

def get_base_dir():
    base_dir = os.path.join(os.path.dirname(__file__), '../..')
    base_dir = os.path.normpath(base_dir)
    print('Info: scanning %s...' % base_dir)
    return base_dir
