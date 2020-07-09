from optparse import OptionParser
from nginx_live_client import *
from test_base import *
import nginxparser
import http_utils
import subprocess
import requests
import signal
import time
import sys
import os

NGINX_CONF = 'nginx.conf'
TEMP_NGINX_CONF = 'temp.conf'

NGINX_BIN = '/usr/local/nginx/sbin/nginx'
NGINX_PID = '/usr/local/nginx/logs/nginx.pid'
VALGRIND_BIN = 'valgrind'

def downloadTestVideos():
    for filePath, url in TEST_VIDEO_URLS.items():
        if os.path.isfile(filePath):
            continue
        print 'Info: downloading %s' % filePath
        http_utils.downloadUrl(url, filePath)

def cleanupNginx():
    os.system('killall -9 nginx 2> /dev/null')
    os.system('killall -9 memcheck-amd64- 2> /dev/null')    # valgrind
    os.system('rm -rf /tmp/dvr/channel')
    for f in ['/var/log/nginx/error.log', '/var/log/nginx/access.log']:
        try:
            os.remove(f)
        except OSError:
            pass

def waitForNginxStart():
    while True:
        try:
            res = requests.get(NGINX_LIVE_API_URL + '/')
            if res.status_code == 200:
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.1)

def startNginx(confFile, fileName, mode='w'):
    cmdLine = [NGINX_BIN, '-c', os.path.abspath(confFile)]
    stdout = None
    if options.valgrind:
        cmdLine = [VALGRIND_BIN, '-v', '--tool=memcheck', '--leak-check=yes', '--num-callers=128'] + cmdLine
        stdout = file('%s-valgrind.log' % fileName, mode)
    nginxProc = subprocess.Popen(cmdLine, stdout=stdout, stderr=subprocess.STDOUT)
    waitForNginxStart()
    return nginxProc

def stopNginx(nginxProc):
    if options.valgrind:
        nginxPid = nginxProc.pid    # daemon off
    else:
        nginxPid = int(file(NGINX_PID).read().strip())
    os.kill(nginxPid, signal.SIGTERM)
    nginxProc.wait()

def restartNginx(nginxProc, confFile, fileName, cleanupFunc):
    cleanupFunc()
    stopNginx(nginxProc)
    return startNginx(confFile, fileName, 'a')


def valgrindUpdateConf(conf):
    conf.append(['daemon', 'off'])
    conf.append(['master_process', 'off'])

def getTests(testsDir, start, end, only):
    if only is not None:
        return only.split(',')

    result = []
    for cur in sorted(os.listdir(testsDir)):
        fileName, ext = os.path.splitext(cur)
        if ext != '.py':
            continue

        if start is not None:
            if fileName != start:
                continue
            start = None

        result.append(fileName)

        if end is not None and fileName == end:
            break

    result.sort()
    return result

def defaultTestCleanup():
    nl = nginxLiveClient()
    try:
        nl.channel.delete(CHANNEL_ID)
    except requests.exceptions.HTTPError, e:
        if e.response.status_code != 404:
            raise
    cleanupStack.reset()
    logTracker.assertNoCriticalErrors()

def run(tests):
    for fileName in tests:
        curMod = __import__(fileName)
        if options.only is None:
            longTest = getattr(curMod, 'LONG_TEST', False)
            if longTest:
                print '>>> %s - skipped' % fileName
                continue

        testFunc = getattr(curMod, 'test', None)
        if not callable(testFunc):
            continue

        if options.setup:
            updateConfFuncs = []
            updateConfFunc = getattr(curMod, 'updateConf', None)
            if updateConfFunc is not None:
                updateConfFuncs.append(updateConfFunc)
            if options.valgrind:
                updateConfFuncs.append(valgrindUpdateConf)

            if len(updateConfFuncs) > 0:
                conf = nginxparser.load(file(NGINX_CONF, 'r'))
                for updateConfFunc in updateConfFuncs:
                    updateConfFunc(conf)
                nginxparser.dump(conf, file(TEMP_NGINX_CONF, 'w'))
                confFile = TEMP_NGINX_CONF
            else:
                confFile = NGINX_CONF

            cleanupNginx()
            nginxProc = startNginx(confFile, fileName)

        setupFunc = getattr(curMod, 'setup', None)
        cleanupFunc = getattr(curMod, 'cleanup', defaultTestCleanup)

        if setupFunc is not None:
            logTracker.init()
            setupFunc()
            time.sleep(2)
            nginxProc = restartNginx(nginxProc, confFile, fileName, cleanupFunc)

        if options.pause_before:
            raw_input('--Next--')

        logTracker.init()
        print '>>> %s' % fileName
        testFunc()

        if options.pause_after:
            raw_input('--Next--')

        cleanupFunc()

        if options.setup:
            stopNginx(nginxProc)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-s', '--start', dest='start',
                      help='start from TEST', metavar='TEST')
    parser.add_option('-e', '--end', dest='end',
                      help='end at TEST', metavar='TEST')
    parser.add_option('-o', '--only', dest='only',
                      help='run only at TEST', metavar='TEST')
    parser.add_option('-P', '--pause-before',
                      action='store_true', dest='pause_before', default=False,
                      help='wait for input before each test')
    parser.add_option('-p', '--pause-after',
                      action='store_true', dest='pause_after', default=False,
                      help='wait for input after each test')
    parser.add_option('-n', '--no-setup',
                      action='store_false', dest='setup', default=True,
                      help='skip setting up nginx')
    parser.add_option('-v', '--valgrind',
                      action='store_true', dest='valgrind', default=False,
                      help='run with valgrind')

    (options, args) = parser.parse_args()

    if not options.setup:
        options.valgrind = False

    thisDir = os.path.split(os.path.abspath(__file__))[0]
    testsDir = os.path.join(thisDir, 'tests')
    sys.path.append(testsDir)

    downloadTestVideos()

    tests = getTests(testsDir, options.start, options.end, options.only)
    run(tests)
