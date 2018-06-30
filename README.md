nsscache
========

The nsscache binary provides an interface to NetAuth that generates
files suitable for consumption by
[libnss-cache](https://github.com/google/libnss-cache).  This is the
canonical way to pull network accounts to UNIX derived systems and
will insulate against NSS failures due to transient network
partitions.

This binary must be run as root since it will need to write files as
root and set permissions such that only root can read.  Fortunately
the amount of code in this program is minimal.

Running the binary as root will do the right thing, assuming that you
have your certificate located at `/etc/netauth.cert` and your
configuration file at `/etc/netauth.toml`.

Important options from the help output:

```
  -group-file string
Group cache to write to (default "/etc/group.cache")
  -homedir string
Home directory to provide if none is available from NetAuth (default "/tmp/{UID}")
  -indirects
Include indirect relationships in the group map (default true)
  -min-gid int
Minimum GID number to accept (default 2000)
  -min-uid int
Minimum UID number to accept (default 2000)
  -passwd-file string
Passwd cache to write to (default "/etc/passwd.cache")
  -shadow-file string
Shadow cache to write to (default "/etc/shadow.cache")
  -shell string
Default shell to use if none is provided in the directory (default "/bin/nologin")
```

Of these, the following are important to understand:

  * `--homedir`: The home directory to provide in the passwd map.
    This will perform a string substitution on the string `{UID}`
    which maps to the NetAuth concept of an entity ID.  This can be
    useful for specifying where to mount the home directory into.
  * `--shell`: If the shell is not provided by the directory, or if
    the shell provided by the directory does not exist on this system,
    this shell will be provided to the passwd map instead.  Choose
    carefully between default security and user friendliness here.
    The secure option is the default, the friendly one is usually
    /bin/bash.
  * `--indirects`: Include indirect memberships in the group map.  For
    systems of highly secure nature, you may wish to disable this and
    only include groups that an entity is directly a member of.
  * `--min-gid` and `--min-uid`: These values control the minimum
    numeric group ID and user ID values to map.  Values below these
    are dropped from the maps.  The defaults should generally be safe,
    but ensure that you don't inadvertently cause a collision with
    local users and groups.
  * `--passwd-file`, `--group-file`, and `--shadow-file`: These files
    point to non default locations for the map files.  In general you
    should not modify these unless you have a good reason to do so.

nsscache provides single shot updates to the files.  You must run
nsscache on some sort of job controller if you want to update and pick
up new values.  Choose the update frequency that is right for you.  A
good default choice if you have no idea what to set here is 15
minutes.  This will be slightly annoying to users that have just been
created in the system, but won't otherwise hammer the NetAuth server.
