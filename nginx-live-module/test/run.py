from optparse import OptionParser
import nginxparser
import http_utils
import test_base
import sys
import os

NGINX_CONF = 'nginx.conf'
TEMP_NGINX_CONF = 'temp.conf'


def downloadTestVideos():
    for filePath, url in test_base.TEST_VIDEO_URLS.items():
        if os.path.isfile(filePath):
            continue
        print 'Info: downloading %s' % filePath
        http_utils.downloadUrl(url, filePath)

def setupNginx(confFile):
    os.system('killall -9 nginx > /dev/null')
    os.system('rm -rf /tmp/dvr/channel')
    for f in ['/var/log/nginx/error.log', '/var/log/nginx/access.log']:
        try:
            os.remove(f)
        except OSError:
            pass
    os.system('/usr/local/nginx/sbin/nginx -c %s' % os.path.abspath(confFile))

def getTests(testsDir, start, end, only):
    if only is not None:
        return [only]

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

def run(tests, setup):
    firstTime = True
    for fileName in tests:
        curMod = __import__(fileName)
        testFunc = getattr(curMod, 'test', None)
        if not callable(testFunc):
            continue

        if firstTime:
            firstTime = False
        elif options.pause:
            raw_input('--Next--')

        updateConfFunc = getattr(curMod, 'updateConf', None)
        if callable(updateConfFunc):
            conf = nginxparser.load(file(NGINX_CONF, 'r'))
            updateConfFunc(conf)
            nginxparser.dump(conf, file(TEMP_NGINX_CONF, 'w'))
            confFile = TEMP_NGINX_CONF
        else:
            confFile = NGINX_CONF

        if options.setup:
            setupNginx(confFile)

        if options.pause_before:
            raw_input('--Next--')

        print '>>> %s' % fileName
        testFunc()

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-s', '--start', dest='start',
                      help='start from TEST', metavar='TEST')
    parser.add_option('-e', '--end', dest='end',
                      help='end at TEST', metavar='TEST')
    parser.add_option('-o', '--only', dest='only',
                      help='run only at TEST', metavar='TEST')
    parser.add_option('-p', '--pause',
                      action='store_true', dest='pause', default=False,
                      help='wait for input between tests')
    parser.add_option('-P', '--pause-before',
                      action='store_true', dest='pause_before', default=False,
                      help='wait for input before each test')
    parser.add_option('-n', '--no-setup',
                      action='store_false', dest='setup', default=True,
                      help='skip setting up nginx')

    (options, args) = parser.parse_args()

    thisDir = os.path.split(os.path.abspath(__file__))[0]
    testsDir = os.path.join(thisDir, 'tests')
    sys.path.append(testsDir)

    downloadTestVideos()

    tests = getTests(testsDir, options.start, options.end, options.only)
    run(tests, options.setup)
