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



class tor_arm_replace_torrc(object):
    def __init__(self):
        if os.name != "posix":
            print "This is a script specifically for configuring Debian Gnu/Linux and other Unix like systems"
            sys.exit(1)

        # 1. Remove the environment, do not pass go otherwise
        remove_environment()

        # 2. Set the trusted user and group information
        set_trusted_account_info(USER, GROUP)

        # 3. Set configuration file information
        self.tor_config_file = TOR_CONFIG_FILE
        self.arm_config_file = ARM_CONFIG_FILE

        # 4. Am I root? - We need to be root, or effective root. Without it continuation is futile
        if not self.got_sufficient_privileges():
            print "Sorry, insufficient privileges. Continuation is futile"
            sys.exit(1)

        # 4b. Continue with the change_configuration()
        # init is done

    ### Run in init
    def remove_environment(self):
        for i in os.environ:
            print i
            os.unsetenv(i)

    ### Run in init
    def set_trusted_account_info(self, user="tor-arm", group="tor-arm"):
        self.trusted_user  = user
        self.trusted_group = group
        try:
            self.trusted_uid = pwd.getpwnam(USER).pw_uid
        except:
            print "Our tor-arm user \"%s\" was not found - this is unsafe; exiting now!" % user
            sys.exit(1)

        try:
            self.trusted_gid = grp.getgrnam(GROUP).gr_gid
        except:
            print "Our tor-arm group \"%s\" was not found - this is unsafe; exiting now!" % group
            sys.exit(1)

    ### Run in init
    def got_sufficient_privileges(self, group="tor-arm"):
        # Am I the big man on the system?
        if os.getuid() == 0:
            return True

        # Can I effectively play as the big cheeze?
        if os.geteuid() == 0:
            print "This script requires (effective) root privileges. Can't continue without it"
            sys.exit(1)

        # Ok, effective root, but am I privileged?
        try:
            # checks if that's a group we're in
            if self.trusted_group in os.getgroups():
                return True
            else:
                print "Your user needs to be a member of the %s group for this to work" % self.trusted_group
                return False
        except:
            # Made pedantic
            print "The %s group doesn't exist on this system" % self.trusted_group
            return False

        return False

    def drop_privileges(self):
        # Drop to the unpriv'ed group, and really lose the rest of the groups
        # - Must set one group to overcome old BSD and current OSX bugs
        try:
            os.setgroups([self.trusted_gid])
            os.setgid(self.trusted_gid)
            os.setegid(self.trusted_gid)

            os.setuid(self.trusted_uid)
            os.seteuid(self.trusted_uid)
        except:
            print "Error: couldn't drop privileges. Do I check myself to be sufficiently privileged to get here?"
            sys.exit(1)

    def reraise_privs(self):
        os.setuid(0)
        os.seteuid(0)
        os.setgid(0)
        os.setegid(0)
        # Secondary GIDs don't have a saved equivalent

    def backup_configuration_file(self):
        # backup the previous tor config
        if os.path.exists(TOR_CONFIG_FILE):
            try:
                # TODO: Safety check
                backupFilename = "%s_backup_%i" % (TOR_CONFIG_FILE, int(time.time()))
                shutil.copy(TOR_CONFIG_FILE, backupFilename)
            except IOError, exc:
                print "Unable to backup %s (%s)" % (TOR_CONFIG_FILE, exc)
                sys.exit(1)

    def is_configuration_file_correct(self, configfile):
        TOR_VERIFY_SHELL = 'tor --verify-config -f ' + configfile

        print "Using Tor to verify that arm will not break Tor's configuration"
        rc = os.system(TOR_VERIFY_SHELL)
        if rc == 0:
            return True
        else:
            print "Tor says the new configuration file is invalid: \"%s\" (%s)" % configfile
            return False

    def act_like_a_parent(self, child_pid):
        # Wait until our child got back - It should have succefully written the configuration file
        child_pid, status = os.waitpid(child_pid, 0)

        # Done?
        sys.exit(0)

        # As parents we can cheat and reraise privileges - full root now
        #self.reraise_privs()


  # unlink our temp file
  try:
    os.remove(tf.name)
  except:
    print "Unable to close temp file %s" % tf.name
    sys.exit(1)

    def act_like_a_child(self):
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)

        # Make a tempfile and write out the contents
        try:
            # TODO: Check path before HERE!!!
            tf = tempfile.NamedTemporaryFile(delete=False) # This uses mkstemp internally
        except:
            print "We were unable to make a temporary file"
            sys.exit(1)


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

        # Check the configuration file for correctness
        if self.is_configuration_file_correct('FFOOOOFOFOFOF'):
            print "Configuration file is correct"
        else:
            print "Configuration file is unusable, bailing out"
            sys.exit(1)

    def spoon(self):
        fork_pid = os.fork()
        if (fork_pid == 0):
            # Start to play ball
            self.act_like_a_child()
        else:
            # Start parenting
            self.act_like_a_parent(fork_pid)

    def change_configuration(self):
        # I'm (effective) root here
        # 5. Backup current configuration file
        self.backup_configuration_file()

        # 6. Lower privileges to a more humble level - less privileges, more trust
        self.drop_privileges()

        

        # 7. Fork! - Parent will continue to wait until the child is done.
        #            The child will exchange the configuration file
        self.spoon()


if __name__ == "__main__":
    tor_arm = tor_arm_replace_torrc()
    tor_arm.change_configuration()

    sys.exit(0)
