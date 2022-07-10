import re

def findBreakPos(line, minPos, width):
    # prefer space
    pos = line[:width].rfind(' ')
    if pos > minPos:
        return pos

    # try other delims
    delims = re.findall('[^\w]', line[minPos:width])
    if len(delims) > 0:
        return line[:width].rfind(delims[-1])

    # can't find, take first one
    delims = re.findall('[^\w]', line[width:])
    if len(delims) > 0:
        return width + line[width:].find(delims[0])

    return -1

def formatText(text, width):
    lines = []
    for line in text.split('\n'):
        curLine = line
        indent = ' ' * (len(line) - len(line.lstrip()) + 4)

        trailingLines = []
        if len(curLine) > width and curLine.endswith('{'):
            curLine = curLine[:-1].rstrip()
            trailingLines = [indent[4:] + '{']

        while len(curLine) > width:
            breakPos = findBreakPos(curLine, len(indent), width)
            if breakPos < 0:
                break
            lines.append(curLine[:breakPos + 1].rstrip())
            curLine = indent + curLine[(breakPos + 1):]
        lines.append(curLine.rstrip())
        lines += trailingLines
    return '\n'.join(lines)

def writeText(text, width=79):
    print(formatText(text, width))
