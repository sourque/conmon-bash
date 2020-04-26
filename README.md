# conmon.sh

__WARNING__: This project is awful, I'm leaving it up as a testament to how you really can solve everything in bash, but sometimes that's not a good thing.

Connection monitor (conmon). Written in pure bash, only one file (although it uses text files for storage). 

![Main Screen Example](img/screenshot1.png)

### Dependencies
- bash
- ss (primary network tool)
- dsniff (for tcpkill utility)
- sysdig (for spy_users)
- strace (for reading ssh session data)

### Features
- k (kill): kill PID and send RST to given IP address for 5 seconds (tcpkill)
- b (block, ban): ban IP through iptables command
- e (examine): depends on service. gives more detail about connection
- h (help): print help
- q (quit): quit

	
### Storage details
- conns.txt --> scratchpad for connection data
- output.txt --> used for referencing data if it changes (conNum pid ip serviceName)
- graveyard.txt --> inactive conns (serviceName timeout pid ip)
- newyard.txt --> temp. storage for old connections
- info.txt --> temp. storage for reporting info

