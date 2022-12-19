import subprocess
import random
import json
import sys
import re

VALGRIND = True
VALGRIND_LOG = 'valgrind.log'

def get_random_string():
    res = ''.join([chr(random.randint(32,126)) for x in range(random.randint(0,30))])
    if not COMPACT:
        res = res.replace('[]', 'x').replace('{}', 'x')
    return res

def get_random_element(depth):
    res = random.choice([None, True, False, 0, '', [], {}])
    if res == 0:
        return random.random()*(10**random.randint(-100,100))
    elif res == '':
        return get_random_string()
    elif res == []:
        count = random.randint(0,10) if depth < 10 else 0
        return [get_random_element(depth + 1) for x in range(count)]
    elif res == {}:
        count = random.randint(0,10) if depth < 10 else 0
        return {get_random_string(): get_random_element(depth + 1) for x in range(count)}

def get_pretty_json(input_json):
    cmd_line = ['./json_pretty']
    if VALGRIND:
        cmd_line = ['valgrind', '-v', '--tool=memcheck', '--num-callers=128'] + cmd_line

    output = subprocess.check_output(cmd_line + [input_json], stderr=file(VALGRIND_LOG, 'w'))

    if VALGRIND:
        res = file(VALGRIND_LOG).read()
        if not 'ERROR SUMMARY: 0 errors from 0 contexts' in res:
            print(res)

    return output

def get_random_test():
    cur = get_random_element(0)

    if COMPACT:
        input_json = json.dumps(cur, separators=(',', ':'))
    else:
        input_json = json.dumps(cur, separators=(' , ', ' : '), indent=1)
        input_json = input_json.replace('[]', '[ ]').replace('{}', '{ }')

    expected = json.dumps(cur, indent=4)
    expected = re.sub(' $', '', expected, flags=re.MULTILINE)

    return input_json, expected

def get_nesting_test():
    count = random.randint(0,50)
    charset = random.choice(['[]{}', '[[[[[[[]', '[]]]]]]]'])  # balanced/opening/closing
    input_json = ''.join(random.choice(charset) for x in range(count))
    return input_json, None

i = 0
while True:

    # select test params
    TRUNCATE = bool(random.getrandbits(1))
    COMPACT = bool(random.getrandbits(1))
    TEST_GEN = random.choice([get_random_test, get_nesting_test])

    # get input + expected output
    input_json, expected = TEST_GEN()
    if len(input_json) > 128000:    # limit is 128k, taking a small safety margin here
        continue

    # run the test
    if TRUNCATE:
        input_json = input_json[:random.randint(0, len(input_json))]
        output = get_pretty_json(input_json)
        if expected is not None and not expected.startswith(output):
            print(output)
            print(expected)
    else:
        output = get_pretty_json(input_json)
        if expected is not None and output != expected:
            print(output)
            print(expected)

    # progress
    i += 1
    if i >= 20:
        sys.stdout.write('.')
        sys.stdout.flush()
        i = 0
