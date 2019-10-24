#!/usr/bin/env python
#
#===- run-refactor.py - Parallel refactoring runner ----------*- python -*--===#
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#

"""
Parallel refactoring runner
==========================

Runs the given refactoring tool over all files in a compilation database.
Requires the tool and clang-apply-replacements in $PATH.

Example invocations.
- Run cpp2covert on all files in the current working directory with a default
  set of checks and show warnings in the cpp files and all project headers.
    run-refactor.py cpp2covert $PWD

Compilation database setup:
http://clang.llvm.org/docs/HowToSetupToolingForLLVM.html
"""

import argparse
import json
import multiprocessing
import os
import Queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading

parser = argparse.ArgumentParser(description='Runs TOOL over all files '
                               'in a compilation database. Requires '
                               'TOOL and clang-apply-replacements in '
                               '$PATH.')

def find_compilation_database(path):
  """Adjusts the directory until a compilation database is found."""
  result = './'
  while not os.path.isfile(os.path.join(result, path)):
    if os.path.realpath(result) == '/':
      print 'Error: could not find compilation database. Specify with -p'
      parser.print_help()
      sys.exit(1)
    result += '../'
  return os.path.realpath(result)

def get_tool_invocation(f, clang_tool_binary, extra_args, tmpdir, build_path,
                        header_filter):
  """Gets a command line for TOOL."""
  start = [clang_tool_binary]
  if header_filter is not None:
    start.append('-header-filter=' + header_filter)
  else:
    # Show warnings in all in-project headers by default.
    start.append('-header-filter=^' + build_path + '/.*')
  if extra_args:
    for a in extra_args:
      start.append(a)
  if tmpdir is not None:
    start.append('-export-fixes')
    # Get a temporary file. We immediately close the handle so TOOL can
    # overwrite it.
    (handle, name) = tempfile.mkstemp(suffix='.yaml', dir=tmpdir)
    os.close(handle)
    start.append(name)
  start.append('-p=' + build_path)
  start.append(f)
  return start

def apply_fixes(args, tmpdir):
  """Calls clang-apply-fixes on a given directory. Deletes the dir when done."""
  invocation = [args.clang_apply_replacements_binary]
  if args.format:
    invocation.append('-format')
  invocation.append(tmpdir)
  subprocess.call(invocation)
  shutil.rmtree(tmpdir)

class ToolRunner:
  def __init__(self):
    self.failed = False

  def __call__(self, args, tmpdir, build_path, queue):
    """Takes filenames out of queue and runs TOOL on them."""
    while True:
      name = queue.get()
      invocation = get_tool_invocation(name, args.clang_tool_binary, args.extra_args,
                                       tmpdir, build_path, args.header_filter)
      sys.stdout.write(' '.join(invocation) + '\n')
      ret = subprocess.call(invocation)
      if ret != 0:
          self.failed = True
      queue.task_done()

def main():
  parser.add_argument('-tool', metavar='TOOL', dest='clang_tool_binary',
                      help='The refactoring tool to run')
  parser.add_argument('-clang-apply-replacements-binary', metavar='PATH',
                      default='clang-apply-replacements',
                      help='path to clang-apply-replacements binary')
  parser.add_argument('-header-filter', default=None,
                      help='regular expression matching the names of the '
                      'headers to output diagnostics from. Diagnostics from '
                      'the main file of each translation unit are always '
                      'displayed.')
  parser.add_argument('-j', type=int, default=1, metavar='JOBS',
                      help='number of TOOL instances to be run in parallel.')
  parser.add_argument('-fix', action='store_true', help='apply fix-its')
  parser.add_argument('-format', action='store_true', help='Reformat code '
                      'after applying fixes')
  parser.add_argument('-p', dest='build_path',
                      help='Path used to read a compile command database.')
  parser.add_argument('-sources', nargs='+', default=['.*'], metavar='FILE',
                      dest='files',
                      help='source files to be processed (regex on path)')
  parser.add_argument('-arg', default=[], dest='extra_args', action="append",
                      metavar='ARG', help='Pass additional arguments to TOOL')
  args = parser.parse_args()
  usage = parser.print_help

  db_path = 'compile_commands.json'

  if args.build_path is not None:
    build_path = args.build_path
  else:
    # Find our database
    build_path = find_compilation_database(db_path)

  try:
    invocation = [args.clang_tool_binary, "-list-checks"]
    invocation.append('-p=' + build_path)
    subprocess.check_output(invocation)
  except:
    print >>sys.stderr, "Unable to run TOOL."
    sys.exit(1)

  # Load the database and extract all files.
  database = json.load(open(os.path.join(build_path, db_path)))
  files = [entry['file'] for entry in database]

  max_task = args.j
  if max_task == 0:
    max_task = multiprocessing.cpu_count()

  tmpdir = None
  if args.fix:
    tmpdir = tempfile.mkdtemp()

  # Build up a big regexy filter from all command line arguments.
  file_name_re = re.compile('(' + ')|('.join(args.files) + ')')

  try:
    # Spin up a bunch of tool-launching threads.
    queue = Queue.Queue(max_task)
    runner = ToolRunner()
    for _ in range(max_task):
      t = threading.Thread(target=runner,
                           args=(args, tmpdir, build_path, queue))
      t.daemon = True
      t.start()

    # Fill the queue with files.
    for name in files:
      if file_name_re.search(name):
        queue.put(name)

    # Wait for all threads to be done.
    queue.join()

    if runner.failed:
      print >>sys.stderr, '\nError occurred while creating replacements, goodbye.'
      sys.exit(1)

  except KeyboardInterrupt:
    # This is a sad hack. Unfortunately subprocess goes
    # bonkers with ctrl-c and we start forking merrily.
    print '\nCtrl-C detected, goodbye.'
    if args.fix:
      shutil.rmtree(tmpdir)
    os.kill(0, 9)

  if args.fix:
    print 'Applying fixes ...'
    apply_fixes(args, tmpdir)

if __name__ == '__main__':
  main()
