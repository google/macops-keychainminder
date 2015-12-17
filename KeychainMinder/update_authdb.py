#!/usr/bin/env python
# Copyright 2015 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""
Python module for installing/removing the KeychainMinder mechanism
from the authorization database. Only designed for 10.8+.

This can either be used as a standalone script or imported and used
in another Python script.
"""

import argparse
import plistlib
import os
import subprocess
import sys


KEYCHAIN_MINDER_MECHANISM = 'KeychainMinder:check,privileged'
SCREENSAVER_RULE = 'authenticate-session-owner'
SCREENSAVER_RULE_ALLOW_ADMIN_UNLOCK = 'authenticate-session-owner-or-admin'
SCREENSAVER_PRETTY_RULE = 'use-login-window-ui'

AUTHENTICATE_RIGHT = 'authenticate'
LOGIN_DONE_RIGHT = 'system.login.done'
SCREENSAVER_RIGHT = 'system.login.screensaver'


def _GetRightData(right):
  """Get the current configuration for the requested right as a dict."""
  output = subprocess.check_output(
      ['/usr/bin/security', 'authorizationdb', 'read', right],
      stderr=subprocess.PIPE)
  data = plistlib.readPlistFromString(output)
  return data


def _SetRightData(right, data):
  """Update the configuration for the requested right."""
  data = plistlib.writePlistToString(data)
  p = subprocess.Popen(
      ['/usr/bin/security', 'authorizationdb', 'write', right],
      stdin=subprocess.PIPE,
      stderr=subprocess.PIPE)
  _, stderr = p.communicate(input=data)
  return stderr.count('YES') == 1


def InstallPlugin(allow_admin_unlock, no_screensaver):
  """Install the plugin to both rules and update screensaver right."""
  for right in [AUTHENTICATE_RIGHT, LOGIN_DONE_RIGHT]:
    data = _GetRightData(right)
    mechanisms = data.get('mechanisms', [])
    if not mechanisms.count(KEYCHAIN_MINDER_MECHANISM):
      mechanisms.append(KEYCHAIN_MINDER_MECHANISM)
      data['mechanisms'] = mechanisms
      if _SetRightData(right, data):
        print '%s: Mechanism installed.' % right
      else:
        print '%s: Failed to install mechanism' % right
    else:
      print '%s: Mechanism already installed.' % right

  if no_screensaver:
    return

  target_rule = SCREENSAVER_RULE
  if allow_admin_unlock:
    target_rule = SCREENSAVER_RULE_ALLOW_ADMIN_UNLOCK

  data = _GetRightData(SCREENSAVER_RIGHT)
  if data.get('rule') != [target_rule]:
    data['rule'] = [target_rule]
    if _SetRightData(SCREENSAVER_RIGHT, data):
      print '%s: Rule updated.' % SCREENSAVER_RIGHT
    else:
      print '%s: Failed to update rule.' % SCREENSAVER_RIGHT
  else:
    print '%s: Rule already correct.' % SCREENSAVER_RIGHT


def RemovePlugin(restore_screensaver):
  """Remove the plugin from both rules."""
  for right in [AUTHENTICATE_RIGHT, LOGIN_DONE_RIGHT]:
    data = _GetRightData(right)
    mechanisms = data.get('mechanisms', [])
    if mechanisms.count(KEYCHAIN_MINDER_MECHANISM):
      mechanisms.remove(KEYCHAIN_MINDER_MECHANISM)
      data['mechanisms'] = mechanisms
      if _SetRightData(right, data):
        print '%s: Mechanism removed.' % right
      else:
        print '%s: Failed to remove mechanism.' % right
    else:
      print '%s: Mechanism already removed.' % right

    if restore_screensaver:
      data = _GetRightData(SCREENSAVER_RIGHT)
      if data.get('rule') != [SCREENSAVER_PRETTY_RULE]:
        data['rule'] = [SCREENSAVER_PRETTY_RULE]
        if _SetRightData(SCREENSAVER_RIGHT, data):
          print '%s: Rule updated.' % SCREENSAVER_RIGHT
        else:
          print '%s: Failed to update rule.' % SCREENSAVER_RIGHT
      else:
        print '%s: Rule already correct.' % SCREENSAVER_RIGHT


def CheckForRoot():
  if not os.geteuid() == 0:
    sys.exit('This script requires root privileges')


def ParseOptions():
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers(dest='subparser_name')

  parser_install = subparsers.add_parser('install')
  parser_install.add_argument(
      '--allow-admin-unlock', action='store_true', dest='allow_admin_unlock',
      help='Allow administrators to unlock any session')
  parser_install.add_argument('--no-screensaver', action='store_true',
      dest='no_screensaver', help='Don\'t update screensaver rule')

  parser_remove = subparsers.add_parser('remove')
  parser_remove.add_argument(
      '--restore-screensaver', action='store_true', dest='restore_screensaver',
      help='Restore \'new\' screensaver UI')

  return parser.parse_args()


def main(argv):
  CheckForRoot()
  options = ParseOptions()

  if options.subparser_name == 'install':
    InstallPlugin(allow_admin_unlock=options.allow_admin_unlock,
                  no_screensaver=options.no_screensaver)
  elif options.subparser_name == 'remove':
    RemovePlugin(restore_screensaver=options.restore_screensaver)


if __name__ == '__main__':
  main(sys.argv)
