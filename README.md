# rise

Finds Windows named pipes with weak permissions, the kind that sometimes lead
to local privilege escalation.

Plenty of services run as SYSTEM and talk to normal-user processes over a named
pipe. If that pipe has a sloppy DACL, any user can connect to it. Whether that
gets you anywhere depends entirely on what the service does with what you send,
but a weak pipe is where you start looking. rise finds them so you don't have
to eyeball every pipe by hand.

## What it flags

- pipes that let Everyone or Anonymous read/write
- null DACLs, which is no protection at all, everyone gets full control
- pipes where a normal user can rewrite the permissions (WRITE_DAC)

It splits third-party pipes from the built-in Windows RPC ones so you're not
wading through lsass and friends to find the interesting stuff.

## Build

Developer Command Prompt for Visual Studio, then:

    cl /EHsc /O2 rise.cpp advapi32.lib

## Run

Run it as a normal user, not admin. The point is to see what an unprivileged
process can reach.

    rise.exe

Output:

    [3rd] SomeVendorService   <== POSSIBLE LPE CANDIDATE
           null DACL (everyone, full control)

    198 pipes, readable=46, open_failed=152, flagged=30, candidates=8

A candidate is a lead, not a bug. Most go nowhere. You still have to reverse the
owning service and work out whether the pipe actually controls anything you
care about. See INVESTIGATION.md for how that's gone so far, including a few
pipes that turned out to match real CVEs.

## todo

- resolve the owning process per pipe (GetNamedPipeServerProcessId) instead of
  "server pid unknown"
- service DACLs and unquoted service paths
- writable service directories and registry autoruns

## note

Only run against machines you own.
