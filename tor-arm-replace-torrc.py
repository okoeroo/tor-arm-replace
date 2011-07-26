#!/usr/bin/python

"""
This is a python wrapper to overwrite /etc/tor/torrc when called by a user in
GROUP. This must be called from tor-arm-replace-torrc and tor-arm-replace-torrc
must be marked as setuid root where only root and GROUP are allowed to execute
it. Please see tor-arm-replace-torrc.c for details on how it must be marked.

arm should write a valid Tor configuration file to ARM_CONFIG_FILE and then
it should run the tor-arm-replace-torrc program. If that program is successful
arm should instruct Tor to reload it's configuration (via HUP or ControlPort).
"""

import os
import sys
import grp
import pwd
import time
import shutil
import tempfile
import signal

USER = "tor-arm"
GROUP = "tor-arm"
TOR_CONFIG_FILE = "/etc/tor/torrc"
ARM_CONFIG_FILE = "/var/lib/tor-arm/torrc"

if __name__ == "__main__":
  # sanity check that we're on linux
  if os.name != "posix":
    print "This is a script specifically for configuring Debian Gnu/Linux"
    sys.exit(1)

  orig_uid = os.getuid()
  orig_euid = os.geteuid()
  orig_gid = os.getgid()
  orig_egid = os.getegid()
  # We must have USER and GROUP 
  try:
    dropped_id_pwn = pwd.getpwnam(USER)
  except:
    print "Our tor-arm user was not found - this is unsafe; exiting now!"
    exit(1)
  dropped_uid = dropped_id_pwn.pw_uid
  dropped_euid = dropped_id_pwn.pw_uid
  dropped_gid = grp.getgrnam(GROUP).gr_gid
  dropped_egid = grp.getgrnam(GROUP).gr_gid
  
  # check that we're running effectively as root
  if orig_euid != 0:
    print "This script needs to be run as root"
    sys.exit(1)
  
  # if we're actually root, we skip this group check
  # root can get away with all of this
  if orig_uid != 0:
    # check that the user is in GROUP
    try:
      # checks if that's a group we're in
      if not dropped_gid in os.getgroups():
        print "Your user needs to be a member of the %s group for this to work" % GROUP
        sys.exit(1)
    except KeyError:
      print "The %s group doesn't exist on this system" % GROUP
      sys.exit(1)

  # Drop to the unpriv'ed group, and really lose the rest of the groups
  os.setgid(dropped_gid)
  os.setegid(dropped_egid)
  os.setresgid(dropped_gid, dropped_egid, dropped_gid)
  os.setgroups([dropped_gid])
   
  # open a tempfile and chown it to 116
  # Make a tempfile and write out the contents
  try:
    tf = tempfile.NamedTemporaryFile(delete=False) # This uses mkstemp internally
    os.chown(tf.name, dropped_uid, orig_euid) # this allows our child process to write to tf.name (not only if their uid matches, not their gid) 
  except:
    print "We were unable to make a temporary file"
    sys.exit(1)

  parent_pid = os.getpid()
  fork_pid = os.fork()
  # open the suspect config after we drop privs
  # we assume the dropped privs are still enough to write to the tf
  if (fork_pid == 0):
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    # Drop privs forever in the child process
    # I believe this drops os.setfsuid os.setfsgid stuff
    # Clear all other supplemental groups for dropped_uid
    os.setgroups([dropped_gid])
    os.setresgid(dropped_gid, dropped_egid, dropped_gid)
    os.setresuid(dropped_uid, dropped_euid, dropped_uid)
    os.setgid(dropped_gid)
    os.setegid(dropped_egid)
    os.setuid(dropped_uid)
    os.seteuid(dropped_euid)
    
    try:
      af = open(ARM_CONFIG_FILE) # this is totally unpriv'ed
      # ensure that the fd we opened has the properties we requrie
      configStat = os.fstat(af.fileno()) # this happens on the unpriv'ed FD
      if configStat.st_gid != dropped_gid:
        print "Arm's configuration file (%s) must be owned by the group %s" % (ARM_CONFIG_FILE, GROUP)
        sys.exit(1)
      # if everything checks out, we're as safe as we're going to get
      armConfig = af.read(1024 * 1024) # limited read but not too limited
      af.close()
      tf.file.write(armConfig)
      tf.flush()
    except:
      print "Unable to open the arm config as unpriv'ed user"
      sys.exit(1)
    finally:
      tf.close()
      sys.exit(0)
  else:
    # If we're here, we're in the parent waiting for the child's death
    # man, unix is really weird...
    child_pid, status = os.waitpid(fork_pid, 0)
  if status != 0:
    print "The child seems to have failed; exiting!"
    tf.close()
    sys.exit(1)

  # attempt to verify that the config is OK
  if os.path.exists(tf.name):
    # construct our SU string
    SUSTRING = "su -c 'tor --verify-config -f " + str(tf.name) + "' " + USER
    # We raise privs to drop them with 'su'
    os.setuid(0)
    os.seteuid(0)
    os.setgid(0)
    os.setegid(0)
    # We drop privs here and exec tor to verify it as the dropped_uid 
    print "Using Tor to verify that arm will not break Tor's config:"
    success = os.system(SUSTRING)
    if success != 0:
      print "Tor says the new configuration file is invalid: %s (%s)" % (ARM_CONFIG_FILE, tf.name)
      sys.exit(1)

  # backup the previous tor config
  if os.path.exists(TOR_CONFIG_FILE):
    try:
      backupFilename = "%s_backup_%i" % (TOR_CONFIG_FILE, int(time.time()))
      shutil.copy(TOR_CONFIG_FILE, backupFilename)
    except IOError, exc:
      print "Unable to backup %s (%s)" % (TOR_CONFIG_FILE, exc)
      sys.exit(1)
  
  # overwrites TOR_CONFIG_FILE with ARM_CONFIG_FILE as loaded into tf.name
  try:
    shutil.copy(tf.name, TOR_CONFIG_FILE)
    print "Successfully reconfigured Tor"
  except IOError, exc:
    print "Unable to copy %s to %s (%s)" % (tf.name, TOR_CONFIG_FILE, exc)
    sys.exit(1)

  # unlink our temp file
  try:
    os.remove(tf.name)
  except:
    print "Unable to close temp file %s" % tf.name
    sys.exit(1)

  sys.exit(0)
