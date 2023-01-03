# Nginx Live Module Tests

## Unit Tests

### Overview

The unit tests of Nginx Live Module are implemented in python, each test case is represented by a python script under the `tests` folder.
The test cases should be executed using the provided `run.py` script.
Execute `python run.py --help` for more details on the available command line arguments.

Some of the tests compare the resulting video stream to a previously created reference file.
The reference files are saved in the `tests/ref` folder, each file contains the body of the playlists, and the MD5 hash of the media segments.
All the streams represented by the reference files were validated by playing back the stream on an iPhone.

After running a test case, if the resulting video stream does not match the existing reference file, a new reference file is created.
The name of the new reference file is the name of the existing file with a `.new` suffix added to it.
The two reference files can then be compared, and if the change is expected and the new stream plays fine, the new reference file can be committed.

### Prerequisites

The following steps are required in order to run the tests on a server for the first time:
- Compile file-to-kmp - use [build.sh](file-to-kmp/build.sh) (note that ffmpeg has to be installed on the server).
- Install nginxparser - clone [nginxparser-1](https://github.com/shenjinian/nginxparser-1) and run `python setup.py install`.

### Test Files Reference

- *cleanup_stack.py* - used for automatic cleanup between test cases, for example, terminating a listening HTTP server created for the test.
- *file-to-kmp* - libavformat-based utility for converting media files (e.g. MP4) to KMP format.
- *http_utils.py* - helper functions for issuing HTTP requests.
- *kmp_utils.py* - helper classes for reading / sending KMP.
- *manifest_utils.py* - functions for parsing HLS / DASH manifests.
- *nginx.conf* - base nginx configuration used for unit tests.
- *nginx_live_client.py* - a client library for working with the nginx-live-module API.
- *subtitle_utils.py* - functions for parsing SRT files.
- *test_base.py* - misc helper functions for test cases - tracking log writes, editing nginx conf, assertions etc.

## Additional Scripts

- *replay.conf* / *replay.lua* - conf / code for replaying a live stream from S3 storage.
- *apply_no_pool.py* - helper script for applying [no-pool-nginx](https://github.com/openresty/no-pool-nginx) patches.
- *kmp_dump.py* - utility for dumping KMP files.
