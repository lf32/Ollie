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


#
# Reverse Shell
#
# Reverse Shell Encoding Payload Type
#
revShellPayloadEncoding() {
	echo ""
	echo "[REVERSE SHELL] Choose The Encoding Type"
	echo "[1] None [2] URL Encode [3] Double URL Encode [4] Base64"
	read -p "Pick an Encoding Type from abouve [Default=1]: " r3venc0d1ng
}
revShellPayloadEncoding


#
# Reverse Shell
#
# Reverse Shell Tools
#
revShellPayloadTools() {
	echo ""
	echo "[REVERSE SHELL] Choose The Type Of Tool You Wish To Use"
	echo "[1] Bash -i\t\t[2] Bash 196\t\t[3] Bash readline"
	echo "[4] Bash 5\t\t[5] Bash udp\t\t[6] nc mkfifo"
	echo "[7] nc -e\t\t[8] BusyBox nc -e\t[9] nc -c"
	echo "[10] ncat -e\t\t[11] ncat udp\t\t[12] rustcat"
	echo "[13] C\t\t\t[14] C# TCP Client\t[15] C# Bash -i"
	echo "[16] Haskel #1\t\t[17] Perl\t\t[18] Perl no sh"
	echo "[19] Perl PentestMonkey\t[20] PHP PentestMonkey\t[21] PHP Ivan Sincek"
	echo "[22] PHP cmd\t\t[23] PHP cmd 2\t\t[24] PHP cmd small"
	echo "[25] PHP exec\t\t[26] PHP shell_exec\t[27] PHP system"
	echo "[28] PHP passthru\t[29] PHP \`\t\t[30] PHP popen"
	echo "[31] PHP proc_open\t[32] Python #1\t\t[33] Python #2"
	echo "[34] Python3 #1\t\t[35] Python3 #2\t\t[36] Python3 shortest"
	echo "[37] Ruby #1\t\t[38] Ruby no sh\t\t[39] socat #1"
	echo "[40] socat #2 (TTY)\t[41] node.js\t\t[42] node.js #2"
	echo "[43] Java #1\t\t[44] Java #2\t\t[45] Java #3"
	echo "[46] Java Web\t\t[47] Java Two Way\t[48] Javascript"
	echo "[49] telnet\t\t[50] zsh\t\t[51] Lua #1"
	echo "[52] Lua #2\t\t[53] GoLang\t\t[54] Vlang"
	echo "[55] Awk\t\t[56] Dart"
	read -p "Pick a number from above [Default=1]: " r3vp4yl04dt00l
}
revShellPayloadTools