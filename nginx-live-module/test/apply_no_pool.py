import glob
import sys
import os

if len(sys.argv) < 3:
    print 'Usage:\n\t%s <nginx source path> <no-pool-nginx path>' % os.path.basename(__file__)
    sys.exit(1)

_, nginxPath, noPoolPath = sys.argv
nginxPath = os.path.abspath(nginxPath)
noPoolPath = os.path.abspath(noPoolPath)

patches = glob.glob(os.path.join(noPoolPath, 'nginx-*-no_pool.patch'))

# get the nginx version
nginxH = os.path.join(nginxPath, 'src/core/nginx.h')
for curLine in file(nginxH):
    if curLine.startswith('#define NGINX_VERSION'):
        nginxVerStr = curLine.split('"')[1]
        break
else:
    print 'failed to get nginx version'
    sys.exit(1)

print 'nginx version: %s' % nginxVerStr
if '(no pool)' in nginxVerStr:
    print 'already patched'
    sys.exit(0)

nginxVer = map(int, nginxVerStr.split('.'))

# get available patch versions
patchVers = []
for patch in patches:
    patchVer = os.path.basename(patch).split('-')[1]
    patchVers.append(map(int, patchVer.split('.')))
patchVers.sort()

# find the closest patch version
if nginxVer in patchVers:
    patchVer = nginxVer
else:
    patchVers.append(nginxVer)
    patchVers.sort()
    patchVer = patchVers[patchVers.index(nginxVer) - 1]

patchVerStr = '.'.join(map(str, patchVer))
print 'patch version: %s' % patchVerStr

patchFile = os.path.join(noPoolPath, 'nginx-%s-no_pool.patch' % nginxVerStr)
if patchVerStr != nginxVerStr:
    srcPatchFile = os.path.join(noPoolPath, 'nginx-%s-no_pool.patch' % patchVerStr)
    patchData = file(srcPatchFile).read()
    patchData = patchData.replace(patchVerStr, nginxVerStr)
    patchData = patchData.replace('%d%03d%03d' % tuple(patchVer), '%d%03d%03d' % tuple(nginxVer))

    file(patchFile, 'w').write(patchData)

os.system('cd %s ; patch -p1 < %s' % (nginxPath, patchFile))
