#!/bin/bash

clear
cat << EOF


 ______     ______     __   __     __    __     ______     __   __    
/\  ___\   /\  __ \   /\ "-.\ \   /\ "-./  \   /\  __ \   /\ "-.\ \   
\ \ \____  \ \ \/\ \  \ \ \-.  \  \ \ \-./\ \  \ \ \/\ \  \ \ \-.  \  
 \ \_____\  \ \_____\  \ \_\\\"\_\  \ \_\ \ \_\  \ \_____\  \ \_\\\"\_\ 
  \/_____/   \/_____/   \/_/ \/_/   \/_/  \/_/   \/_____/   \/_/ \/_/ 
                                                                      
                              v0.1
                             @543hn


EOF

# Configurable options
graveyardTimeout=10
refreshDelay=3 # in seconds

# Varibles that need to be set
evalProgress=$(mktemp)
echo "false" > $evalProgress
readProgress=$(mktemp)
echo "false" > $readProgress
cmdInput=$(mktemp)

# Clear files
echo -n > output.txt
echo -n > conns.txt
echo -n > info.txt
echo -n > newyard.txt
echo -n > graveyard.txt
echo -n > sysdig.txt
echo -n > strace.txt


 
# Color codes
gt="\e[1;32m"
rt="\e[1;31m"
gb="\e[42m"
rst="\e[0m"


trapShutdown() {
	tput rmcup
	clear; echo
	echo -e "\nShutting down..."
	kill $sysdig_pid && echo -e "\tKilled sysdig..." || echo -e "\tError: failed to kill sysdig"
	echo -e "\tExiting!\n"
	exit
}

trap trapShutdown SIGINT SIGTERM

services=()
echo -e "Services loaded:$gt"
serviceList=( ssh apache2 nginx )
for service in "${serviceList[@]}"; do
	systemctl is-active $service >/dev/null && echo -e "\t$service" && services+=("$service")
done
echo -e "$rst"

echo "Checking dependencies..."
deps=(ss sysdig tcpkill strace )
for dep in "${deps[@]}"; do
	command -v $dep > /dev/null || echo -e "\t${rt}ERROR${rst}: $dep not found!"
done
echo -e "\t${gt}DONE${rst}\n"

echo "Launching background monitoring..."
echo -en "\tRunning sysdig... "
sysdig --unbuffered -c spy_users >> sysdig.txt &
sysdig_pid=$! && echo -e "${gt}DONE${rst}\n"

read -p "Press enter to begin..."
errorMsg=" "
clear

cleanGraveyard() {
	egrep "^$1*" graveyard.txt > conns.txt
	while read line; do
		timeout=$(echo $line | cut -d " " -f2)
		pid=$(echo $line | cut -d " " -f3)
		ip=$(echo $line | cut -d " " -f4)
		if ! grep -q $pid output.txt; then
			if ! (( $timeout < 1 )); then
				echo -e "\t[$conNum] (INACTIVE) $ip (pid: $pid) ($timeout)"
				echo "$conNum $pid $ip" >> output.txt
				echo "$1 $((timeout - 1)) $pid $ip" >> newyard.txt
				((outputLength++))
				((conNum++))
			fi
		fi		
	done < conns.txt
}


loadService() { # take name of service, load variables and stuff
	case $1 in
		ssh)
		port=$(grep 'Port' /etc/ssh/sshd_config | cut -d " " -f2)
		ssh_header="${gb}sshd listening on port $port ${rst}"
		;;

		apache2) :
			;;

		nginx)
		port=$(echo 80)
		nginx_header="${gb}nginx listening on port $port ${rst}"
		;;
	esac
}


checkService() { # run check of connections
	case $1 in
		ssh)
		echo -e "$ssh_header"
		((outputLength++))
		ss -op '( sport = :22 )'  | tail -n +2 | tr -s ' ' > conns.txt
		while read line; do
			ip=$(echo $line | cut -d " " -f6)
			pid=$(echo $line | egrep -o "pid=[0-9]*")
			if [ -z "$pid" ]; then # SCENARIO #1: PID not found (TCP FIN-WAIT or smth)
				:
			elif (( $(echo $line | grep -o "pid" | wc -l) < 2 )); then # SCENARIO #2: 1 PID
				pid=$(echo $pid | cut -d '=' -f2)
				echo -e "\t[$conNum] $ip (pid: $pid) is currently logging in."
				echo "$conNum $pid $(echo $ip | cut -d ':' -f1)" >> output.txt
				echo "ssh $graveyardTimeout $pid $(echo $ip \
					| cut -d ':' -f1)" >> newyard.txt
				((conNum++))				
				((outputLength++))
			else # SCENARIO #3: 2 PIDs
				IFS=" " read cpid ppid <<< $(echo $pid) 
				ppid=$(echo $ppid | cut -d "=" -f2)
				cpid=$(echo $cpid | cut -d "=" -f2)
				pts=$(who -a | tr -s " " | grep "$ppid" | cut -d " " -f3)
				arg=$(egrep "^$(pgrep -P $cpid)*" sysdig.txt | tail -1 | cut -d ")" -f2)
				if (( $(echo $arg | wc -c) > 28 )); then arg="${arg:0:28}..."; fi
				if [ -z "$arg" ]; then arg=" n/a"; fi
				if [ -z "$pts" ]; then
					echo -e "\t[$conNum] $ip (pid: $ppid) is currently logging in."
				else
					user=$(w -h | tr -s " " | grep "$pts" | cut -d " " -f1)
					echo -e "\t[$conNum] $user from $ip (ppid: $ppid) on $pts (cmd:$arg)"
				fi
				echo "$conNum $ppid $(echo $ip | cut -d ':' -f1) ssh" >> output.txt
				echo "ssh $graveyardTimeout $ppid $(echo $ip | cut -d ':' -f1)" >> newyard.txt
				((conNum++))				
				((outputLength++))				
			fi
		done < conns.txt
		cleanGraveyard "ssh"
		;;

		apache2)
			:
			;;


		nginx) echo -e "$nginx_header"
			((outputLength++))

			ss -op '( sport = :80 )'  | tail -n +2 | tr -s ' ' | \
				tr -t "," " " | sort  | \
				awk -F"[pid=]" '!a[$1]++' > conns.txt

			while read line; do

				ip=$(echo $line | cut -d " " -f6)
				pid=$(echo $line | egrep -o "pid=[0-9]*" | cut -d "=" -f2)
				pts=$(who -a | tr -s " " | grep "$((pid + 1))" | cut -d " " -f3)	
				req=$(cat /var/log/nginx/access.log | grep $(echo $ip | \
					cut -d ":" -f1) | egrep -v "*.css|.js *" | \
					tail -1 | cut -d '"' -f2)
					
				if [ -z "$pid" ]; then # SCENARIO #1: PID not found
					echo -e "\t[$conNum] $req from $ip (tcp fin-wait)"
				else # SCENARIO 2: 1 PID, because it's an http server
					echo -e "\t[$conNum] $req from $ip (pid: $pid)"
					echo "$conNum $pid $(echo $ip \
						| cut -d ':' -f1) nginx" >> output.txt
					echo "nginx $graveyardTimeout $pid \
						$(echo $ip | cut -d ':' -f1)" >> newyard.txt
				fi
				
				((conNum++))
				((outputLength++))

			done < conns.txt
			cleanGraveyard "nginx"
			;;

	esac
}

examineConn() {

	pid=$(grep "^$1" output.txt | cut -d " " -f2)
	ip=$(grep "^$1" output.txt | cut -d " " -f3)
	service=$(grep "^$1" output.txt | cut -d " " -f4)
	
	tput smcup
	case $service in
		ssh)    echo -e "### PRESS ENTER TO RETURN TO MAIN SCREEN ###\n"
			echo -e "SSH EXAMINE CONNECTION\n"
			echo -e "\tPPID: $pid"
			echo -e "\tCPID: $(pgrep -P $pid)"
			echo -e "\tIP: $ip"
			echo -e "\tLOGIN TIME: TODO"
			echo -e "\tTIME SINCE LOGIN: TODO"
			echo -e "\tUSER: TODO"
			echo -e "\tSHELL: TODO"
			echo -e "\tDIR: TODO"
			echo -e "\nLAST TEN COMMANDS:"
			placeholder_pid=$(pgrep -P $pid); # CHECK WITH TMUX. HATE
			term_pid=$pid;
			while [ -n "$placeholder_pid" ]; do
				term_pid=$placeholder_pid
				placeholder_pid=$(pgrep -P $placeholder_pid)
			done
			grep "^$term_pid*" sysdig.txt | tail -10
			echo -e "\nLIVE SESSION KEYLOG:"
			strace -p $(pgrep -P $pid) -e write -o strace.txt &
			strace_pid=$! # MAKE BACKSPACE PRETTIER
			(sleep 0.3; stdbuf -oL tail -f strace.txt \ 
				--pid $strace_pid | grep --line-buffered "write(9" | stdbuf -oL cut \
				-d '"' -f2 | stdbuf -oL sed -e "s/\\\r/+/g" | stdbuf -o0 tr -d "\n" \
				| stdbuf -o0  tr "+" "\n") & 
			strace_read_pid=$! # ADD CHECK IF CONNECTION DIED!
			;;
		nginx)  echo "HTTP EXAMINE CONNECTION"
			;;
			
	esac
	read

	case $service in
		ssh) kill $strace_pid
		     kill $strace_read_pid
		     ;;	
		nginx)  echo "HTTP EXAMINE CONNECTION"
			;;	
	esac
	tput rmcup

}

evalCommand() { # change -- only one command at a time ?
	echo "true" > $evalProgress
	cmd=$1
	cnum=${cmd:1:1}
	pid=$(grep "^$cnum" output.txt | cut -d " " -f2)
	ip=$(grep "^$cnum" output.txt | cut -d " " -f3)
	while (( $(echo $cmd | wc -c) >= 3 )); do 
		case $cmd in
			k*) if [[ $pid ]]; then
				kill $pid
				tcpkill host $ip 2>/dev/null &
				kill_pid=$!; (sleep 5; kill $kill_pid) &
				errorMsg="  killed $cnum"
			    else 
				errorMsg="  couldn't kill $cnum"  
			    fi;;
			b*) if [[ $ip ]]; then
				iptables -I INPUT -s $ip -j DROP # CUSTOM BLOCKING COMMAND HERE
				tcpkill host $ip 2>/dev/null &
				kill_pid=$!; (sleep 5; kill $kill_pid) &
				errorMsg="  blocked $cnum"
			    else 
				errorMsg="  couldn't block $cnum" 
			    fi;;
			e*) examineConn "$cnum"
			    ;;
			*) errorMsg="  invalid command, sorry :(";;
		esac
		# if command includes dash use range... oops doesn't suport more than single digit numbers
		cmd=${cmd:2}
	done
	echo "false" > $evalProgress
	echo "false" > $readProgress
}


# M A I N

for service in "${services[@]}"; do
	loadService $service
done

while true; do

	outputLength=0
	conNum=1
	lines=$(tput lines)
	columns=$(tput cols)

	for service in "${services[@]}"; do
		checkService $service
	done

	# Calculate distance to space prompt
		#UNSOLVED CASE: what if output is longer than terminal? also... if the lines are longer than term cols, outputlength is wrong
	(( promptSpace = lines - outputLength - 1 ))
	for ((i=0;i<promptSpace;i++)); do
		echo
	done
	
	echo -en "$errorMsg > "
	
	if [ "$(cat $evalProgress)" = "false" ]; then
		(if [ "$(cat $readProgress)" = "false" ]; then
			echo "true" > $readProgress;
			read input && errorMsg=" " && \
			if [ -n $input ]; then 
				echo "$input" > $cmdInput 
			fi
		fi) &
	fi
	
	for i in {1..15}; do
		sleep 0.1
		if [ -s "$cmdInput" ]; then
			evalCommand $(cat $cmdInput)
			echo -n > $cmdInput
			break
		fi
	done
	
	clear
	cat newyard.txt > graveyard.txt
	echo -n > newyard.txt
	echo -n > output.txt

done
