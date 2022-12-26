import sys

status = 0

def printErr(msg):
    global status

    sys.stderr.write(msg + '\n')
    status = 1

def exit():
    sys.exit(status)
