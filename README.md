#owamp

This release is an implementation of the OWAMP (one-way active measurement protocol) defined by http://www.internet2.edu/~shalunov/ippm/draft-ietf-ippm-owdp-14.txt.

##Code Organization
It is organized as follows:

Directory | Description
--- | ---
I2util/ | convienient utility functions... Error reporting, hash funcs...
owamp/ | directory for owamp api - a high level abstraction for speaking the owamp protocol.
owampd/ | An owamp server implementation.
owping/ | A command line owamp client (one way ping).
powstream/ | A client-daemon for continuous one-way tests. 
conf/ | Example config files. (not installed - EXAMPLES!)
doc/ | html and man page descriptions of owamp tools.
test/ | validate programs.

