
def formatText(text, width):
    lines = []
    for line in text.split('\n'):
        curLine = line
        indent = ' ' * (len(line) - len(line.lstrip()) + 4)
        while len(curLine) > width:
            breakPos = curLine[:width].rfind(' ')
            if breakPos <= len(indent):
                breakPos = curLine[width:].find(' ')
                if breakPos < 0:
                    break
                breakPos += width
            lines.append(curLine[:breakPos].rstrip())
            curLine = indent + curLine[(breakPos + 1):]
        lines.append(curLine.rstrip())
    return '\n'.join(lines)

def writeText(text, width=79):
    print formatText(text, width)
