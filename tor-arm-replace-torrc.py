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

"""
Script walkthrough:
1.  Clean the environment variables. The LD_* is cleaned by the kernel due to
    setuid bit, but there are less obvious risks.
2.  Initialize source and destingation paths and lookup the trusted accounts,
    and fail the group or user wasn't found.
3.  Am I sufficiently privileged? Either I'm root or effective root. On the
    later I need to check if we're associated with the trusted group
4.  Backup the current configuration file, this is TOR_CONFIG_FILE
5.  Test new configuration file with 'tor --verify-config -f <config file>,
    using the ARM_CONFIG_FILE as input
6.  Fork.
6a. Parent will wait for the child to come back.
6b. The child will lose the saved uid and gid and update the tor file
6.  Move/copy new configuration file to new location
7.  Done
"""

import os
import sys
import grp
import pwd
import time
import shutil
import tempfile
import signal
from stat import *

USER = "tor-arm"
GROUP = "tor-arm"
USER = "okoeroo"
GROUP = "admin"

ARM_CONFIG_FILE = "/var/lib/tor-arm/torrc"    # Source
TOR_CONFIG_FILE = "/etc/tor/torrc"            # Destination


"""
The following class is a pure Python simplified version of the Safefile library
from Kupsch & Miller of the University of Wisconsin
"""
class SimpleSafeFile(object):
    PRIVATE   = 1
    TRUSTED   = 2
    UNTRUSTED = 4

    def __init__(self, filepath):
        # Make path non-relative, relative to the current working directory
        filepath =  self.unrelativePath(filepath)
        self.handle = open(filepath)

        trust = self.determineTrustLevel(self.handle, filepath)
        self.__set_trust_level(trust)
#        print self.trustLevelToString(self.get_trust_level())

    def get_trust_level(self):
        return self.determined_trustlevel

    def __set_trust_level(self, trust):
        self.determined_trustlevel = trust

    def unrelativePath(self, filePath):
        if filePath[0] == '/':
            return filePath
        else:
            return os.getcwd() + "/" +  filePath

    def splitPath(self, filePath):
        path = []
        last_cut = filePath
        while last_cut != '/':
            path.append(os.path.split(last_cut)[1])
            last_cut = os.path.split(last_cut)[0]

        # The loop is filtering the '/'
        path.append('/')
        path.reverse()
        return path

    def expandPaths(self, decomposed_path):
        expanded_path = []
        for i in decomposed_path:
            if i == '/':
                current_path = "/"
            elif current_path == "/":
                current_path += i
            else:
                current_path += "/" + i

            expanded_path.append(current_path)
        return expanded_path

    def checkTrustLevel(self, path):
        mode = os.stat(path).st_mode

        # Others can write
        if mode & S_IWOTH == S_IWOTH and not mode & S_ISVTX == S_ISVTX:
            return self.UNTRUSTED

        # Special device are not trusted - might change in the future
        if not S_ISDIR(mode) and not S_ISREG(mode):
            return self.UNTRUSTED

        if S_ISDIR(mode):
            # Sticky bit - When this bit is set on a directory it means that a
            #              file in that directory can be renamed or deleted
            #              only by the owner of the file, by the owner of the
            #              directory, or by a privileged process.
            if mode & S_ISVTX == S_ISVTX:
                return self.TRUSTED

            # Ownered by root, or myself, and nobody else can look or work in the directory
            if  (os.stat(path).st_uid == 0 or os.stat(path).st_uid == os.geteuid()) and \
                (os.stat(path).st_gid == 0 or os.stat(path).st_gid == os.getegid()) and \
                not (mode & S_IROTH == S_IROTH or mode & S_IXOTH == S_IXOTH):
                return self.PRIVATE

            # Ownered by root, or myself
            if  (os.stat(path).st_uid == 0 or os.stat(path).st_uid == os.geteuid()) and \
                (os.stat(path).st_gid == 0 or os.stat(path).st_gid == os.getegid()):
                return self.TRUSTED

            # Owned by root user or myself
            if  (os.stat(path).st_uid == 0 or os.stat(path).st_uid == os.geteuid()) and \
                not (mode & S_IWOTH == S_IWOTH or mode & S_IWGRP == S_IWGRP):
                return self.TRUSTED


            # All else is untrusted
            return self.UNTRUSTED

        elif S_ISREG(mode):
            # Can't be world writeable due to above directive, the rest is ok
            return self.TRUSTED
        else:
            return self.UNTRUSTED

    def trustLevelToString(self, trust_level):
        if trust_level == self.PRIVATE:
            return "Private"
        elif trust_level == self.TRUSTED:
            return "Trusted"
        elif trust_level == self.UNTRUSTED:
            return "Untrusted"

    def isFileHandleAtPath(self, fileHandle, filePath):
        if  os.stat(filePath).st_ino == os.fstat(fileHandle.fileno()).st_ino and \
            os.stat(filePath).st_dev == os.fstat(fileHandle.fileno()).st_dev:
            return True
        else:
            return False

    def determineTrustLevel(self, fileHandle, filePath):
        # Cut the path and, build it from / up to the file. Must end up in the same file
        unrelative_path           = self.unrelativePath(filePath)
        decomposed_paths          = self.splitPath(unrelative_path)
        expanded_decomposed_paths = self.expandPaths(decomposed_paths)

        # Initialize like its perfect and downgrade, until hope is lost
        trustlevel = self.PRIVATE

        for i in expanded_decomposed_paths:
            trust = self.checkTrustLevel(i)
#            print "%s      :  %s" % (self.trustLevelToString(trust), i)

            # Still private, cool, continue please
            if (trust == self.PRIVATE) and (trustlevel == self.PRIVATE):
                continue

            # Downgrade a PRIVATE trustlevel to TRUSTED
            if trust == self.TRUSTED and trustlevel == self.PRIVATE:
                trustlevel = self.TRUSTED
                continue

            # All bets are off, good bye
            if trust == self.UNTRUSTED:
                return self.UNTRUSTED

        # Check if the file handle (already opened and held, is the same file as to be found at the path)
        if not self.isFileHandleAtPath(fileHandle, filePath):
            return self.UNTRUSTED

        return trustlevel

    def getHandle(self):
        return self.handle

class tor_arm_replace_torrc(object):
    def __init__(self, trusted_user, trusted_group, src_conf_file, dst_conf_file):
        if os.name != "posix":
            print "This is a script specifically for configuring Debian Gnu/Linux and other Unix like systems"
            sys.exit(1)

        # 1. Remove the environment, do not pass go otherwise
        self.remove_environment()

        # 2a. Initialize input
        self.src_conf_file = src_conf_file
        self.dst_conf_file = dst_conf_file

        # 2b. Set the trusted user and group information - Test if they exist, or bail
        self.set_trusted_account_info(trusted_user, trusted_group)

        # 3. Am I root? - We need to be root, or effective root. Without it continuation is futile
        if not self.got_sufficient_privileges():
            print "Sorry, insufficient privileges. Continuation is futile"
            sys.exit(1)

        # Init is done - Continue by calling change_configuration()

    ### Run in init
    def remove_environment(self):
        for i in os.environ:
            os.unsetenv(i)

    ### Run in init
    def set_trusted_account_info(self, user="tor-arm", group="tor-arm"):
        try:
            self.trusted_uid = pwd.getpwnam(user).pw_uid
            self.trusted_user  = user
        except:
            print "Our tor-arm user \"%s\" was not found - this is unsafe; exiting now!" % user
            sys.exit(1)

        try:
            self.trusted_gid = grp.getgrnam(group).gr_gid
            self.trusted_group = group
        except:
            print "Our tor-arm group \"%s\" was not found - this is unsafe; exiting now!" % group
            sys.exit(1)

    ### Run in init
    def got_sufficient_privileges(self, group="tor-arm"):
        # Am I the big man on the system?
        if os.getuid() == 0:
            return True

        # Can I effectively play as the big cheeze?
        if os.geteuid() != 0:
            print "This script requires (effective) root privileges. Can't continue without it"
            sys.exit(1)

        # Ok, effective root, but am I privileged?
        try:
            # checks if that's a group we're in
            if self.trusted_gid in os.getgroups():
                return True
            else:
                print "Your user needs to be a member of the \"%s\" group for this to work" % self.trusted_group
                return False
        except:
            # Made pedantic
            print "The %s group doesn't exist on this system" % self.trusted_group
            return False

        return False

    def drop_privileges(self):
        # Drop to the unpriv'ed user and group - Must set one secondary group
        # to overcome old BSD and current OSX bugs
        try:
            os.setgroups([self.trusted_gid])
            os.setgid(self.trusted_gid)
            os.setegid(self.trusted_gid)

            os.setuid(self.trusted_uid)
            os.seteuid(self.trusted_uid)
        except:
            print "Error: couldn't drop privileges. Did I check myself to be sufficiently privileged to get here?"
            sys.exit(1)

    # This is probably a useless function
    def reraise_privs(self):
        os.setuid(0)
        os.seteuid(0)
        os.setgid(0)
        os.setegid(0)
        # Secondary GIDs don't have a saved equivalent

    def backup_configuration_file(self):
        # backup the previous tor config
        if os.path.exists(self.dst_conf_file):
            try:
                # Determine the trust level of the file and underlying directories
                s = SimpleSafeFile(self.dst_conf_file)
                if not (s.get_trust_level() == SimpleSafeFile.PRIVATE or \
                        s.get_trust_level() == SimpleSafeFile.TRUSTED):
                    print "File at %s is not trusted, not making a move" % self.dst_conf_file
                    raise

                backupFilename = "%s_backup_%i" % (self.dst_conf_file, int(time.time()))
                shutil.copy(self.dst_conf_file, backupFilename)
            except IOError, exc:
                print "Unable to backup %s (%s)" % (self.dst_conf_file, exc)
                sys.exit(1)

    def is_configuration_file_correct(self, configfile):
        TOR_VERIFY_SHELL = 'tor --verify-config -f ' + configfile

        print "Using Tor to verify that arm will not break Tor's configuration"
        rc = os.system(TOR_VERIFY_SHELL)
        if rc == 0:
            return True
        else:
            return False

    def act_like_a_parent(self, child_pid):
        # Wait until our child got back - It should have succefully written the configuration file
        child_pid, status = os.waitpid(child_pid, 0)

        # Done?
        sys.exit(0)

        # As parents we can cheat and reraise privileges - gaining full root
        #self.reraise_privs()

    # All privileges are dropped to the trusted target user
    def act_like_a_child(self):
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)

        # Before we perform any work, let's check if the configuration file is ok by Tor.
        # This assums that the tor program is able to read it
        if not self.is_configuration_file_correct(self.src_conf_file):
            # Tor didn't like the new configuration file. Time to bail out
            print "Tor says the new configuration file is invalid: \"%s\"" % self.src_conf_file
            sys.exit(1)

        # Make a tempfile and write out the contents
        try:
            # Check path before on /tmp - I'm paranoid
            mode = os.stat("/tmp").st_mode

            if not mode & S_ISVTX == S_ISVTX:
                print "The /tmp is not safe, not sticky bit detected. This is weird... bailing out"
                raise

            tf = tempfile.NamedTemporaryFile(delete=False) # This uses mkstemp internally
        except:
            print "We were unable to make a temporary file"
            sys.exit(1)

        try:
            s = SimpleSafeFile(self.src_conf_file)
            if not (s.get_trust_level() == SimpleSafeFile.PRIVATE or \
                    s.get_trust_level() == SimpleSafeFile.TRUSTED):
                print "File at %s is not trusted, not making a move" % self.src_conf_file
                raise


            # Get the checked and verified file handle
            af = s.getHandle()

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

        # Check the configuration file for correctness
        if self.is_configuration_file_correct(self.dst_conf_file):
            print "New configuration file is copied and correct"
            sys.exit(0)
        else:
            print "New set configuration file is unusable, this is a problem."
            sys.exit(1)

    def change_configuration(self):
        # I'm (effective) root here due to the object initializer

        # 4. Backup current configuration file
        self.backup_configuration_file()

        # 5. Lower privileges to a more humble level - less privileges, more trust
        self.drop_privileges()

        # 6. Spoon! - Parent will continue to wait until the child is done.
        #            The child will exchange the configuration file
        fork_pid = os.fork()
        if (fork_pid == 0):
            # Start to play ball
            self.act_like_a_child()
        else:
            # Start parenting
            self.act_like_a_parent(fork_pid)

if __name__ == "__main__":
    tor_arm = tor_arm_replace_torrc(USER, GROUP, ARM_CONFIG_FILE, TOR_CONFIG_FILE)
    tor_arm.change_configuration()

    sys.exit(0)
