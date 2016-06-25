#! /usr/bin/env python2.7

'''
Generate commit hashes with a prefix you like.
'''

import os
import re
import sys
import zlib
import time
import argparse
from hashlib import sha1
from textwrap import fill
from subprocess import Popen, PIPE
from multiprocessing import Process, Queue, cpu_count


# Debug flag.
DEBUG_FLAG = False

# Debug messages.
GIT_COMMIT = '[{method}] Executing git-commit:\n'.format
INVALID_HEX = ('[fork #{fork}, {method}] {hash} has an invalid '
               'hexadecimal prefix.\n').format
COMPUTED_HASH = '[fork #{fork}, {method}] Computed SHA1: {hash}.\n'.format
RANDOM_STRING = '[fork #{fork}, {method}] Random string: {random}.\n'.format
TIMESTAMP_PARSE = '[{method}] Parsing \'{string}\' for timestamps.'.format
REPEATED_PREFIX = ('[fork #{fork}, {method}] The supplied prefix '
                   '({specified}) and the current prefix ({current}) '
                   'is the same.\n').format
REV_PARSE_MESSAGE = '[{method}] SHA1 of {revision}: {hash}.\n'.format
REV_PARSE_MESSAGE_WITH_ID = ('[fork #{fork}, {method}] SHA1 of {revision}: '
                             '{hash}.\n').format
DELIMITER = '{symbol}'.format(symbol=''.join(['-' * 70]))


def parse(commit):
    '''
    Parse the commit object into a JSON.
    '''
    payload, author, committer, messages = {}, None, None, []
    cat_file = ['git', 'cat-file', 'commit', commit]
    execute = Popen(cat_file, stdout=PIPE, stdin=PIPE)
    stdout, _ = execute.communicate()

    for line in stdout.split('\n'):
        if re.search(r'author', line):
            author = line
        if re.search(r'committer', line):
            committer = line

        if not re.search(r'^(author|committer|tree|parent|commit)', line):
            messages.append(line)

    if execute.returncode == 0:
        payload.update({'length': len(stdout)})
        payload.update({
            'raw': stdout,
            'length': len(stdout),
            'commit': commit,
            'author': get_timestamp(author),
            'message': '\n'.join(messages),
            'committer': get_timestamp(committer)
        })

    if DEBUG_FLAG:
        print fill('[parse] Contents of {commit}:\n'.format(commit=commit))
        print payload['raw']
        print DELIMITER

    return payload


def get_timestamp(string):
    '''
    Get the timestamp from the commit object.
    '''
    if DEBUG_FLAG:
        print fill(TIMESTAMP_PARSE(method='get_timestamp', string=string))
        print DELIMITER

    timestamp = re.search(r'\>.*\d{10}\s', string).group()
    timestamp = re.sub('>', '', timestamp).strip()
    return timestamp


def get_hash(commit, _id=None):
    '''
    Get the SHA1 of the commit (if refspecs are used).
    '''
    commit_hash = None
    rev_parse = ['git', 'rev-parse', commit]
    execute = Popen(rev_parse, stdout=PIPE, stdin=PIPE)
    stdout, _ = execute.communicate()

    if execute.returncode == 0:
        commit_hash = stdout.strip()

    if DEBUG_FLAG:
        if _id is None:
            print fill(REV_PARSE_MESSAGE(method='get_hash', revision=commit,
                                         hash=commit_hash))
            print DELIMITER
        else:
            print fill(REV_PARSE_MESSAGE_WITH_ID(fork=_id, method='get_hash',
                                                 revision=commit,
                                                 hash=commit_hash))
            print DELIMITER
    return commit_hash


def reconstruct(commit):
    '''
    Print the raw content of the commit object from the repository.
    '''
    commit_hash = get_hash(commit)
    current = os.getcwd()
    path = current + '/.git/objects/' + commit_hash[:2] + '/' + commit_hash[2:]

    if DEBUG_FLAG:
        print fill('[reconstruct] Reading from: {0}'.format(path))

    with open(path) as _file:
        print fill(zlib.decompress(_file.read()))
        print DELIMITER


def generate_hash(payload, prefix, commits, bits, _id):
    '''
    Generate SHA1 hash of the commit object.
    '''
    solution, random, flag = get_hash(payload['commit'], _id), '', False

    try:
        int(prefix, 16)
    except ValueError:
        if DEBUG_FLAG:
            print fill(INVALID_HEX(fork=_id, method='generate_hash',
                                   hash=prefix))
            print DELIMITER
        commits.put((solution, random, flag))
        return

    while not solution.startswith(prefix) and commits.empty():
        flag = True
        random = '{0}'.format(sha1(str(os.urandom(bits))).hexdigest())
        length = str(payload['length'] + len(random) + 2)
        to_be_hashed = ''.join(['commit ', length, '\0', payload['raw'],
                                '\n', random, '\n'])
        solution = sha1(to_be_hashed).hexdigest()

    if DEBUG_FLAG:
        if not flag:
            print fill(REPEATED_PREFIX(fork=_id, method='generate_hash',
                                       specified=prefix, current=solution))
            print DELIMITER
        else:
            if commits.empty():
                print fill(COMPUTED_HASH(fork=_id, method='generate_hash',
                                         hash=solution))
                print fill(RANDOM_STRING(fork=_id, method='generate_hash',
                                         random=random))
                print DELIMITER

    if commits.empty():
        commits.put((solution, random, flag))
        return
    else:
        return


def post(expected, revision):
    '''
    Post-validation check.
    '''
    current = get_hash(revision)
    return True if expected == current else False


def make_commit(commit, prefix):
    '''
    Make a commit with the prefix.
    '''
    payload = parse(commit)
    processes, commits, expected, string, flag = [], Queue(), None, None, False

    init_bit = 2
    for _ in xrange(cpu_count()):
        process = Process(target=generate_hash,
                          args=(payload, prefix, commits, init_bit, _))
        process.start()
        processes.append(process)
        init_bit *= init_bit

    expected, string, flag = commits.get()

    for process in processes:
        process.join()

    if flag:
        git_commit = ['git', 'commit', '--amend']
        os.environ['GIT_AUTHOR_DATE'] = payload['author']
        os.environ['GIT_COMMITTER_DATE'] = payload['committer']

        messages = payload['message'].split('\n') + [string]
        messages = map(lambda x: x if x != '' else '-m', messages)

        commit_it = git_commit + messages

        if DEBUG_FLAG:
            print fill(GIT_COMMIT(method='make_commit'))
            print fill(' '.join(commit_it))
            print DELIMITER

        execute = Popen(commit_it, stdout=PIPE, stderr=PIPE)

        stdout, _ = execute.communicate()
        print stdout

        del os.environ['GIT_AUTHOR_DATE']
        del os.environ['GIT_COMMITTER_DATE']

    return True if post(expected, commit) else False


def main():
    '''
    This is the main method.
    '''
    global DEBUG_FLAG
    description = 'Create vanity commits with a prefix you want.'
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument('-p', '--prefix', help='a valid hexadecimal prefix',
                        required=True)
    parser.add_argument('-d', '--debug', help='enable debugging',
                        action='store_true', default=False)

    args = vars(parser.parse_args())

    if args['debug']:
        DEBUG_FLAG = True

    start = time.time()
    validated = make_commit('HEAD', args['prefix'].strip().lower())
    end = time.time()
    if DEBUG_FLAG:
        if validated:
            print 'Done.'
        else:
            print 'Fail.'
        print 'Runtime: {seconds}s.'.format(seconds=(end - start))

    return_code = 0 if validated else 1
    sys.exit(return_code)

if __name__ == '__main__':
    main()
