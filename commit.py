#! /usr/bin/env python2.7

'''
Generate commit hashes with a prefix you like.
'''

import os
import re
import sys
import zlib
import json
import argparse
from hashlib import sha1
from subprocess import Popen, PIPE

# Debug flag.
DEBUG_FLAG = False


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
        print 'Parsed commit object:'
        print json.dumps(payload, indent=4, sort_keys=True)
    return payload


def get_timestamp(string):
    '''
    Get the timestamp from the commit object.
    '''
    if DEBUG_FLAG:
        print 'Received: {0}.'.format(string)

    timestamp = re.search(r'\>.*\d{10}\s', string).group()
    timestamp = re.sub('>', '', timestamp).strip()
    return timestamp


def get_hash(commit):
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
        print 'SHA1 of {0}: {1}.'.format(commit, commit_hash)
    return commit_hash


def reconstruct(commit):
    '''
    Print the raw content of the commit object from the repository.
    '''
    commit_hash = get_hash(commit)
    path = '.git/objects/' + commit_hash[:2] + '/' + commit_hash[2:]
    with open(path) as _file:
        print zlib.decompress(_file.read())


def generate_hash(payload, prefix):
    '''
    Generate SHA1 hash of the commit object.
    '''
    solution, random, flag = get_hash(payload['commit']), '', False

    try:
        int(prefix, 16)
    except ValueError:
        if DEBUG_FLAG:
            print '{0} is not a valid hexadecimal prefix.'.format(prefix)
        return solution, random, False

    while not solution.startswith(prefix):
        flag = True

        random = 'foo: {0}'.format(sha1(str(os.urandom(64))).hexdigest())
        length = str(payload['length'] + len(random) + 2)
        to_be_hashed = ''.join(['commit ', length, '\0', payload['raw'],
                                '\n', random, '\n'])
        solution = sha1(to_be_hashed).hexdigest()

    if DEBUG_FLAG:
        if not flag:
            print ('Existing prefix and the specified prefix '
                   'are the same; nothing to do here.')
        else:
            print 'Calculated SHA1: {0}.'.format(solution)
            print 'Random string to be appended: {0}.'.format(random)
    return solution, random, flag


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
    expected, string, flag = generate_hash(payload, prefix)

    if flag:
        os.environ['GIT_AUTHOR_DATE'] = payload['author']
        os.environ['GIT_COMMITTER_DATE'] = payload['committer']

        messages = payload['message'].split('\n') + [string]
        messages = map(lambda x: x if x != '' else '-m', messages)

        commit_it = ['git', 'commit', '--amend'] + messages

        if DEBUG_FLAG:
            print 'Commit command:\n{0}'.format(commit_it)

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

    validated = make_commit('HEAD', args['prefix'])

    if DEBUG_FLAG:
        if validated:
            print 'Done.'
        else:
            print 'Fail.'

    return_code = 0 if validated else 1
    sys.exit(return_code)

if __name__ == '__main__':
    main()
