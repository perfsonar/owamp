| CentOS        | [![Build Status (CentOS)](https://perfsonar-dev3.grnoc.iu.edu/jenkins/buildStatus/icon?job=owamp-centos)](https://perfsonar-dev3.grnoc.iu.edu/jenkins/view/Debian/job/owamp-centos/) | Debian      | [![Build Status (Debian)](https://perfsonar-dev3.grnoc.iu.edu/jenkins/buildStatus/icon?job=owamp-debian-source)](https://perfsonar-dev3.grnoc.iu.edu/jenkins/view/Debian/job/owamp-debian-source/) |
| -------------|-------------|-------------|-------------|

# OWAMP

This release is contains implementations of the OWAMP (one-way active measurement protocol) defined by https://tools.ietf.org/html/rfc4656 and the TWAMP (two-way active measurement protocol) defined by https://tools.ietf.org/html/rfc5357

## Code Organization
It is organized as follows:

Directory | Description
--- | ---
I2util/ | convienient utility functions... Error reporting, hash funcs...
owamp/ | directory for owamp api - a high level abstraction for speaking the owamp/twamp protocols.
owampd/ | OWAMP and TWAMP server implementations.
owping/ | A command line owamp client (one way ping) and twamp client (two way ping).
powstream/ | A client-daemon for continuous one-way tests. 
conf/ | Example config files. (not installed - EXAMPLES!)
doc/ | html and man page descriptions of owamp and twamp tools.
test/ | unit tests.

