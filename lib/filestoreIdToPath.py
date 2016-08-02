from base64 import b64encode, b64decode
from struct import Struct
import os

def hashFileStoreID(fileStoreID):
    chunks = []
    try:
        idnumber = int(fileStoreID)
        chunks.append(str(idnumber / 100000))
        chunks.append(str(idnumber % 100000 / 1000))
    except:
        chunks = []
        idnumber = long(fileStoreID, 16)
        chunks.append(str(idnumber % 100000 / 100))

    chunks.append(str(fileStoreID))
    return os.path.join(*chunks)


if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print 'Usage: ' + sys.argv[0] + ' filestoreId'
        sys.exit(1)
    fileStoreId = sys.argv[1]
    path = hashFileStoreID(fileStoreId)
    print path
