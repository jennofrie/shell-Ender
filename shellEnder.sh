#!/bin/bash
#Author: Jennofrie
#Codename: Fl4r3w0lf


who="$(whoami)"
null=''
num=1

function shellBash () {

	#BashShell
	local AttIpPort="$(netstat -tp | grep 'bash' | awk '{print $5}')"
	local LocalIpPort="$(netstat -tp | grep 'bash' | awk '{print $4}')"
	bashPID="$(netstat -tp | grep 'bash' | awk '{print$7}' | cut -d '/' -f1)"
	local psName="$(netstat -tp | grep 'bash' | awk '{print$7}' | cut -d '/' -f2)"
	local ConnctState="$(netstat -tp | grep 'bash' | awk '{print$6}')"


	if [[ $psName == [b,B]ash ]]; then

		printf "\n\e[31m[!]$psName shell process detected! \n";

		printf "\n\e[33m[!]POTENTIAL ATTACKERS IP ADDRESS AND PORT: \e[31m$AttIpPort \n\n";

                printf "\e[33m[!]YOUR/COMPROMISE LOCAL IP AND PORT: \e[31m$LocalIpPort \n\n";

                printf "\e[33m[!]CURRENT CONNECTION STATE: \e[31m$ConnctState \n\n"

	elif [[ $psName == "$null" ]]; then

		printf "\n\e[32m[*]bash shell process not detected! \n";

	else

		printf "\n\e[5m\e[32m[!]Something went wrong! If either of the above did not execute! (Bash)\n"

	fi

}

function shellAwk () {

	#awk
	local psName="$(netstat -tp | grep 'awk' | awk '{print$7}' | cut -d '/' -f2)"
	awkPID="$(netstat -tp | grep 'awk' | awk '{print$7}' | cut -d '/' -f1)"
	local AttIpPort="$(netstat -tp | grep 'awk' | awk '{print $5}')"
	local LocalIpPort="$(netstat -tp | grep 'awk' | awk '{print $4}')"
	local ConnctState="$(netstat -tp | grep 'awk' | awk '{print$6}')"



	if [[ $psName == [a,A]wk ]]; then

                printf "\n\e[31m[!]$psName shell process detected! \n";

		printf "\n\e[33m[!]POTENTIAL ATTACKERS IP ADDRESS AND PORT: \e[31m$AttIpPort0 \n\n";

		printf "\e[33m[!]YOUR/COMPROMISE LOCAL IP AND PORT: \e[31m$LocalIpPort0 \n\n";

		printf "\e[33m[!]CURRENT CONNECTION STATE: \e[31m$ConnctState0 \n\n"



        elif [[ $psName == "$null" ]]; then

        	printf "\n\e[32m[*]awk shell process not detected! \n";

        else
                printf "\n\e[5m\e[32m[!]Something went wrong! If either of the above did not execute! (Awk)\n";

        fi

}

function shellNcat () {

	#netcat
	local psName="$(netstat -tp | grep 'ncat' | awk '{print$7}' | cut -d '/' -f2)"
	netcatPID="$(netstat -tp | grep 'ncat' | awk '{print$7}' | cut -d '/' -f1)"
	local AttIpPort="$(netstat -tp | grep 'ncat' | awk '{print $5}')"
	local LocalIpPort="$(netstat -tp | grep 'ncat' | awk '{print $4}')"
	local ConnctState="$(netstat -tp | grep 'ncat' | awk '{print$6}')"

	if [[ $psName == "ncat" ]]; then

                printf "\n\e[31m[!]$psName shell process detected! \n";

		printf "\n\e[33m[!]POTENTIAL ATTACKERS IP ADDRESS AND PORT: \e[31m$AttIpPort \n\n";

                printf "\e[33m[!]YOUR/COMPROMISE LOCAL IP AND PORT: \e[31m$LocalIpPort \n\n";

                printf "\e[33m[!]CURRENT CONNECTION STATE: \e[31m$ConnctState \n\n"


        elif [[ $psName == "$null" ]]; then

                printf "\n\e[32m[*]netcat or ncat shell process not detected! \n";

        else

                printf "\n\e[5m\e[32m[!]Something went wrong! If either of the above did not execute! (Netcat)\n";

        fi
}

function shellZsh () {

	#zsh
	local psName="$(netstat -tp | grep 'zsh' | awk '{print$7}' | cut -d '/' -f2)"
	zshPID="$(netstat -tp | grep 'zsh' | awk '{print$7}' | cut -d '/' -f1)"
	local AttIpPort="$(netstat -tp | grep 'zsh' | awk '{print $5}')"
	local LocalIpPort="$(netstat -tp | grep 'zsh' | awk '{print $4}')"
	local ConnctState="$(netstat -tp | grep 'zsh' | awk '{print$6}')"

	if [[ $psName == [z,Z]sh ]]; then

                printf "\n\e[31m[!]$psName shell process detected! \n\n";

		printf "\n\e[33m[!]POTENTIAL ATTACKERS IP ADDRESS AND PORT: \e[31m$AttIpPort \n\n";

                printf "\e[33m[!]YOUR/COMPROMISE LOCAL IP AND PORT: \e[31m$LocalIpPort \n\n";

                printf "\e[33m[!]CURRENT CONNECTION STATE: \e[31m$ConnctState \n\n"

		printf "\e[37m";


        elif [[ $psName == "$null" ]]; then

                printf "\n\e[32m[*]zsh shell process not detected! \n\n";

        else

                printf "\n\e[5m\e[32m[!]Something went wrong! If either of the above did not execute! (Netcat)\n";

        fi

}


function ascii_art () {
	clear;
	banner=" _____________________________________________________

███████╗██╗  ██╗███████╗██╗     ██╗
██╔════╝██║  ██║██╔════╝██║     ██║
███████╗███████║█████╗  ██║     ██║
╚════██║██╔══██║██╔══╝  ██║     ██║
███████║██║  ██║███████╗███████╗███████╗
╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝

███████╗███╗   ██╗██████╗ ███████╗██████╗
██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗
█████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
███████╗██║ ╚████║██████╔╝███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
 _____________________________________________________";

	# mind-blowing banner rendering
	for ((b=0; b<${#banner}; b++ ));do
		sleep .001;
		printf "${c[1]}%s${c[0]}" "${banner:$b:1}";
	done;
	printf "\n\n ░ by @Jennofrie_\n\n";
	sleep 1.5
};


function shKill () {


	PShell=(
		$bashPID
		$awkPID
		$netcatPID
		$zshPID
		)


	for i in ${PShell[@]}; do

		if [[ ${PShell[@]} != "$null" ]]; then 

			kill -9 "$i"
		else
			printf "\n\n[!]Process Contains NULL VALUE! \n\n";
		fi

	done
}

meNu () {
	#Calling out Function inside function
	shellBash
	shellAwk
	shellNcat
	shellZsh

	echo "
	ShellEnder Toolkit Fl4r3w0lf (BLUETEAM)
        ***************************************

        1) Terminate ALL Detected Shell
        2) Check ESTABLISHED Connections
        3) Check LISTENING Connections
        4) Check USERS PROCESSES (PS AUX)
        5) Exit
        "
	read -p "Select Options: " x00
        case $x00 in

		1) shKill ;;
		2) $a="echo $(netstat -tp)" ;;
		3) $b="echo $(netstat -a | grep 'LISTENING')" ;;
		4) $c="echo $(ps aux | grep $USER)" ;;
		5) clear
			exit ;;
		*)echo "[!]Invalid Selection"
			meNu ;;
	esac
}

if [[ $who == "root" ]]; then

		ascii_art
		sleep 1

		#Add for Presentation Purposes. Ideal for Automation. W/O user interaction

		while [ $num -lt 5 ]; do

			meNu
			num=$(( num+1 ))

		done

elif [[ $who != [r,R]oot ]]; then

	printf "\n\e[32m\e[5m[*]shellEnder requires sudo or root! \n\n";

else
	printf "\n\e[32m\e[5m[!]Something went wrong! \n\n"

fi
