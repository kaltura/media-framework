import requests
import hashlib
import base64
import shutil
import hmac
import time
import zlib

try:
    import urllib.parse as urlparse # python 3
except ImportError:
    import urlparse # python 2


try:
    from g2o_params import *
except ImportError:
    G2O_KEY = ''

def parseHttpHeaders(headers):
    result = {}
    for headerName, headerValue in headers.items():
        headerName = headerName.lower()
        result.setdefault(headerName, [])
        result[headerName].append(headerValue)
    return result

def getUrl(url, extraHeaders={}, timeout=None):
    headers = getG2OHeaderFullUrl(url)
    headers.update(extraHeaders)

    try:
        res = requests.get(url, headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return 0, {}, ('Error: request failed %s %s' % (url, str(e))).encode('utf8')

    body = res.content

    # validate content length
    contentLength = res.headers.get('content-length')
    if contentLength != None and contentLength != '%s' % len(body):
        return 0, {}, ('Error: %s content-length %s is different than the response size %s' % (url, contentLength, len(body))).encode('utf8')

    return res.status_code, parseHttpHeaders(res.headers), body

def downloadUrl(url, fileName):
    with requests.get(url, stream=True) as r:
        with open(fileName, 'wb') as w:
            shutil.copyfileobj(r.raw, w)

def getG2OHeaders(uri):
    if len(G2O_KEY) == 0:
        return {}

    expiry = '%s' % (int(time.time()) + G2O_WINDOW)
    dataFields = [G2O_VERSION, G2O_GHOST_IP, G2O_CLIENT_IP, expiry, G2O_UNIQUE_ID, G2O_NONCE]
    data = ', '.join(dataFields)
    dig = hmac.new(G2O_KEY, msg=data + uri, digestmod=hashlib.sha256).digest()
    sign = base64.b64encode(dig)
    return {
        G2O_DATA_HEADER_NAME: data,
        G2O_SIGN_HEADER_NAME: sign,
        }

def getG2OHeaderFullUrl(url):
    parsedUrl = urlparse.urlsplit(url)
    uri = urlparse.urlunsplit(urlparse.SplitResult('', '', parsedUrl.path, parsedUrl.query, parsedUrl.fragment))
    return getG2OHeaders(uri)
