# Usage — the CLI tools

Nine small tools, one action apiece, all reading the same
[nisabarc](configuration.md). The `plu*` tools tend users, the `plg*`
tools tend groups, and `plngmod` tends netgroups — names carried over
from the dist's former life as Plugtools. Each exits `0` on success and
with the App::Nisaba error code otherwise; each has its own perldoc.

## Users

### pluadd

Inscribe a new user. With only `-u` everything else is picked for
you... a free UID and GID at or above `UIDstart`/`GIDstart`, a primary
group named after the user, `defaultShell`, and a home from
`HOMEproto`.

```shell
# all defaults
pluadd -u vixen

# explicit UID, existing primary group, bash
pluadd -u vixen -U 2001 -g staff -s /usr/local/bin/bash
```

| switch | what                                                 |
|--------|-------------------------------------------------------|
| `-u`   | username, required                                    |
| `-U`   | UID; auto-allocated if omitted                        |
| `-g`   | primary group name; defaults to the username          |
| `-G`   | GID for the primary group; auto-allocated if omitted  |
| `-c`   | GECOS; defaults to the username                       |
| `-h`   | home directory; defaults from `HOMEproto`             |
| `-s`   | shell; defaults from `defaultShell`                   |
| `-S`   | skeleton dir; defaults from `skeletonHome`            |
| `-H`   | 0/1, override `createHome`                            |
| `-O`   | 0/1, override `chownHome`                             |
| `-p`   | 0/1, override `chmodHome`                             |
| `-P`   | override `chmodValue`                                 |
| `-l`   | dump the resulting LDAP entry                         |

### plumod

Change one attribute of a user; `-a` picks which.

```shell
plumod -u vixen -a gecos -c 'Vixen Fox'
plumod -u vixen -a shell -s /bin/sh
plumod -u vixen -a home  -H /home/foxes/vixen
plumod -u vixen -a uid   -U 3001
plumod -u vixen -a gid   -g 1005
```

### plupass

Set a user's password, prompting twice with echo off. The hash is made
by the LDAP server via the password-modify extension, with whatever
scheme it is configured for.

```shell
plupass -u vixen
```

### plurm

Strike a user from the tablet. By default the home directory is kept
(`removeHome=0`) and the primary group is removed if it is left empty
(`removeGroup=1`); `-H` and `-G` override per run.

```shell
# remove the user, keep the home
plurm -u vixen

# remove the user and burn the home too
plurm -u vixen -H 1
```

## Groups

### plgadd

```shell
# auto-allocated GID
plgadd -g foxes

# explicit GID
plgadd -g foxes -G 5000
```

### plgmod

Membership, GID, or description; `-a` picks which.

```shell
plgmod -g foxes -a add    -u vixen
plgmod -g foxes -a remove -u vixen
plgmod -g foxes -a gid    -G 5001
plgmod -g foxes -a description -c 'the den'
```

When changing a GID, `-U 0/1` controls whether members whose primary
GID pointed at the old number are updated too (default from
`userUpdate`).

### plgrm

```shell
plgrm -g foxes
```

### plgclean

Sweep every group for `memberUid` values naming users that no longer
exist, and remove them. `-l` prints each entry it modifies.

```shell
plgclean -l
```

## Netgroups

### plngmod

Requires `netgroupbase` to be set. Modifies or deletes `nisNetgroup`
entries; creation is done from the admin web UI. Triples are
`host,user,domain` — parentheses are added for you, and any field may
be left empty to match anything.

```shell
plngmod -g servers -a description   -c 'production servers'
plngmod -g servers -a triple_add    -t 'web01,,example.com'
plngmod -g servers -a triple_remove -t 'web01,,example.com'
plngmod -g all     -a member_add    -m servers
plngmod -g all     -a member_remove -m servers
plngmod -g old     -a delete
```
