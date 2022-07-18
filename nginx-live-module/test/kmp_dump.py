from kmp_utils import *
import sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage:\n\t%s <raw kmp file>' % os.path.basename(__file__))
        sys.exit(1)

    reader = KmpReader(open(sys.argv[1], 'rb'))
    while reader.packetData is not None:
        data = reader.next()
        print(kmpPacketToStr(data))
