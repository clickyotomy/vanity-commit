#! /usr/bin/env python2.7

'''
Generate commit hashes with a prefix you like.
'''

from subprocess import Popen, PIPE

NULL = '\x00'


def parse(commit):
    '''
    Parse the commit object into a JSON.
    '''
    cat_file = ['git', 'cat-file', 'commit', commit]
    execute = Popen(cat_file, stdout=PIPE, stdin=PIPE)
    stdout, stderr = execute.communicate()

    print stdout
    print stderr


parse('HEAD')
