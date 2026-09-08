#!/bin/sh
# Prove one architecture's artifacts contain what they claim.
#
# A package is what users actually install, and nothing else in the suite looks
# inside one. Without this a path typo ships a package that installs a binary
# nobody can run, and the pipeline reports success doing it.
set -eu

deb="$1"
rpm="$2"
archive="$3"

fail() {
    echo "$1" >&2
    exit 1
}

# Everything a working install needs. The unit refers to the binary by absolute
# path and the logrotate config to the log directory, so a package missing
# either installs a service that cannot start.
for want in ./usr/bin/nostmesh ./lib/systemd/system/nostmesh.service ./etc/logrotate.d/nostmesh; do
    dpkg-deb -c "$deb" | grep -q " $want\$" || fail "missing $want in $deb"
done

# The unit and the binary have to agree about where the binary is. They are
# generated from different files, and a mismatch is exactly the kind of thing
# that survives review and fails on a user's machine.
dpkg-deb --fsys-tarfile "$deb" | tar -xO ./lib/systemd/system/nostmesh.service |
    grep -q '^ExecStart=/usr/bin/nostmesh ' ||
    fail "$deb: the unit does not start /usr/bin/nostmesh"

# The maintainer scripts have to be there, or the service account is never
# created and the unit fails with status=217/USER.
dpkg-deb --info "$deb" preinst >/dev/null 2>&1 || fail "$deb: no preinst script"
dpkg-deb --info "$deb" postinst >/dev/null 2>&1 || fail "$deb: no postinst script"

# The binary must run on the architecture the package names. `file` is not
# installed here, so the ELF machine field is read directly: byte 18 is 0x3e for
# x86-64 and 0xb7 for aarch64.
dpkg-deb --fsys-tarfile "$deb" | tar -xO ./usr/bin/nostmesh > /tmp/nostmesh.bin
head -c 4 /tmp/nostmesh.bin | grep -q 'ELF' || fail "$deb: the binary is not an ELF executable"

case "$deb" in
    *amd64*) want_machine='3e' ;;
    *arm64*) want_machine='b7' ;;
    *) fail "$deb: unknown architecture in the filename" ;;
esac
machine=$(od -An -tx1 -j18 -N1 /tmp/nostmesh.bin | tr -d ' \n')
[ "$machine" = "$want_machine" ] ||
    fail "$deb: binary machine is 0x$machine, expected 0x$want_machine"
rm -f /tmp/nostmesh.bin

# The archive carries the licence: Apache-2.0 requires it, and a user who
# downloaded a tarball has nothing else to read.
tar -tzf "$archive" | grep -q './LICENSE' || fail "$archive: no LICENSE"
tar -tzf "$archive" | grep -q './nostmesh' || fail "$archive: no binary"

# The RPM is not opened — rpm is not in this image, and installing it to read
# one file would add a dependency for a check nfpm's own build already makes.
# Its presence and size are what is asserted here.
[ -s "$rpm" ] || fail "$rpm is empty"

# The published filename has to be the one SHA256SUMS lists. GitHub rejects "~"
# in a release asset name and rewrites it to ".", so a package built as
# 0.2.4~1b is published as 0.2.4.1b — and `sha256sum -c` then matches nothing
# and reports "no file was verified". A checksum nobody can check is worse than
# no checksum, because it looks like verification.
case "$deb" in
    *'~'*) fail "$deb: '~' in the filename; GitHub will rewrite it and break SHA256SUMS" ;;
esac
case "$rpm" in
    *'~'*) fail "$rpm: '~' in the filename; GitHub will rewrite it and break SHA256SUMS" ;;
esac

echo "$(basename "$deb"): ok"
echo "$(basename "$rpm"): present"
echo "$(basename "$archive"): ok"
