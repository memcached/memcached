---
name: Bug report
about: Include some extra information to help with bug reports
title: ''
labels: ''
assignees: ''

---

**DO NOT SUBMIT SECURITY REPORTS HERE**

If you have a security vulnerability, _please report it to the maintainers
privately_. You will be able to file your bug and claim credit once we have a
fix implemented.

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Any information useful for reproducing the bug or crash. Workload, changes in workload, versions affected. If seeing a new issue after an upgrade, please include both before and after versions.

**System Information**
 - OS/Distro:
 - Version of OS/distro:
 - Version of memcached:
 - Hardware detail:

**Detail (please include!)**
Always include the output of `stats`, `stats settings`, and optionally `stats items` and `stats slabs`. These can be provided to a maintainer privately if necessary. Please sanitize anything secret from the data.

If you have a segfault or crash, please try to resolve the crash with `addr2line`. If possible, get a core dump and include a full back trace.
