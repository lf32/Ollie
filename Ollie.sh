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
