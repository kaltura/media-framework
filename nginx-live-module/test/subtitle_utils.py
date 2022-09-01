import re

def parseSRTTimestamp(ts):
    vals = re.split('[:,]', ts.strip())     # 00:00:00,000
    if len(vals) < 3 or len(vals) > 4:
        return None
    try:
        vals = map(int, vals)
    except ValueError:
        return None
    mult = [3600000, 60000, 1000, 1]
    return sum(map(lambda x, y: x * y, vals, mult[:len(vals)]))

def parseSRTCues(data):
    if data.startswith('\xef\xbb\xbf'):
        data = data[3:]     # strip BOM

    res = []

    start = None
    for curLine in data.split('\n'):
        curLine = curLine.strip()
        if curLine.count('-->') == 1:
            ts = map(parseSRTTimestamp, curLine.split('-->'))
            if None in ts:
                continue

            start, end = ts
            lines = []
            continue

        if start is None:
            continue

        if curLine != '':
            lines.append(curLine)
            continue

        if len(lines) > 0:
            body = '\n'.join(lines).strip()
            if body != '':
                res.append((start, end, body))
            start = None

    return res
