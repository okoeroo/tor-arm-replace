//
// This is a very small C wrapper that invokes
// $(DESTDIR)/usr/bin/tor-arm-replace-torrc.py to work around setuid scripting
// issues on the Gnu/Linux operating system.
//
// We assume you have installed it as such for GROUP
// "debian-arm" - This should ensure that only members of the GROUP group will
// be allowed to run this program. When run this program will execute the
// $(DESTDIR)/usr/bin/tor-arm-replace-torrc.py program and will run with the
// uid and group as marked by the OS.
//
// Compile it like so:
// 
//  make
//
// Or by hand like so:
//
//  gcc -o tor-arm-replace-torrc tor-arm-replace-torrc.c
// 
// Make it useful like so:
//
//  chown root:debian-arm tor-arm-replace-torrc
//  chmod 04750 tor-arm-replace-torrc
//
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!WARNING!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
//
// If you place a user inside of the $GROUP - they are now able to reconfigure
// Tor. This may lead them to do nasty things on your system. If you start Tor
// as root,  you should consider that adding a user to $GROUP is similar to
// giving those users root directly.
//
// This program was written simply to help a users who run arm locally and is
// not required if arm is communicating with a remote Tor process.
//
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!WARNING!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "tor-arm-replace-torrc.h"

int main()
{
    /* Without a proper argv, the execve'd process has nog argv point, which is
     * against the convention. */
    char *argv[] = { TOR_ARM_REPLACE_TORRC, NULL };
    int rc = 0;

    rc = execve(TOR_ARM_REPLACE_TORRC, argv, NULL);
    /* execve() overwrites the current process image. Getting here means the call failed */
    if (rc == -1) {
        printf ("Failed to execute \"%s\". Error: %s\n", "./tor-arm-replace-torrc.py", strerror(errno));
    }
    return 1;
}
