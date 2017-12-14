#!/bin/bash

####################################################################
# Bash script to install OSSEC, Fail2ban and logwatch. 
# For Debian 8, 9, Ubuntu 14, 16 , 17 and CentOS 6, 7 systems.
# Written by Parra Arroyo Fernando Marcos
#			 Castro Rendón Virgilio
# Requirements:
#	Internet Connection
#	User Root
####################################################################


#==========================================#
	LOG="`pwd`/../log/installAnalyzers.log"	
	
	LOG_APACHE="/var/log/apache2/"
	OSSEC_CONF_TEMP="`pwd`/../templates/ossec.conf"
	OSSEC_RULES_TEMP="`pwd`/../templates/local_rules.xml"	
	OSSEC_CONF="/var/ossec/etc/ossec.conf"
	OSSEC_RULES="/var/ossec/rules/local_rules.xml"
	F2B_TEMP="`pwd`/../templates/jail.conf"

	userName=`whoami`
	repositoryChange=0

	#This vars are for fail2ban times and the emails for the other programms this script installs
	bantime=30
	findtime=600
	maxretry=3
	destemail="root@localhost"
	sender="root@localhost"

	#COLORS
	# Reset
	Color_Off='\033[0m'       # Text Reset

	# Regular Colors
	Red='\033[0;31m'          # Red
	Green='\033[0;32m'        # Green
	Yellow='\033[0;33m'       # Yellow
	Purple='\033[0;35m'       # Purple
	Cyan='\033[0;36m'         # Cyan
#==========================================#
#####################################################################################################
#Checks the user running the script. If it's not the root user, ends.
user_install()
{
	echo -e "$Cyan \nChecking root permissions..\n $Color_Off"
	if [ "$(id -u)" != "0" ]; then
		echo -e  "$Red ERROR ################################# $Color_Off" 1>&2
	   	echo -e  "$Red ERROR #This script must be run as root# $Color_Off" 1>&2
	   	echo -e  "$Red ERROR ################################# \n$Color_Off" 1>&2
		exit 1
	fi
}
#####################################################################################################
#Detecting Distribution
check_distribution()
{
	DISTR=`grep -E "^ID=" /etc/*release | cut -d "=" -f2 |sed -r 's/"//g'`
	log_command $? "grep -E \"^ID=\" /etc/*release | cut -d \"=\" -f2 | sed -r 's/\"//g'"
	VERSION=`grep -E "^VERSION_ID=" /etc/*release | cut -d "=" -f2 |sed -r 's/"//g'`
	log_command $? "grep -E \"^VERSION_ID=\" /etc/*release | cut -d \"=\" -f2 | sed -r 's/\"//g'"
	EXCEPT=`grep -i centos /etc/issue`

	
	if [[ "$EXCEPT" == *"CentOS"*"6"* ]]; then
	        log_command $? "grep -i centos /etc/issue"
	        echo "CentOS 6"
	fi
	if [[ "$DISTR" == "centos" && "$VERSION" == "7"* ]]; then
	        echo "CentOS 7"
	fi
	if [[ "$DISTR" == "debian" && "$VERSION" == "8"* ]]; then
	        echo "Debian 8"
	fi
	if [[ "$DISTR" == "debian" && "$VERSION" == "9"* ]]; then
	        echo "Debian 9"
	fi
	if [[ "$DISTR" == "ubuntu" && "$VERSION" == "16"* ]]; then
	        echo "Ubuntu 16"
	fi
	if [[ "$DISTR" == "ubuntu" && "$VERSION" == "14"* ]]; then
	        echo "Ubuntu 14"
	fi
	if [[ "$DISTR" == "ubuntu" && "$VERSION" == "17"* ]]; then
	        echo "Ubuntu 17"
	fi
}
#####################################################################################################
#Banner that inits log file
banner_log()
{
	echo -e "$Cyan                                              
                 MMMMMMMMMMMMMMMMMMMMMMMMM                  
           MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM            
         MMMMMMMMMMMMMMM           MMMMMMMMMMMMMMM        
         MMMMMM       MMMM       MMMM       MMMMMM         
         M         MMMMMMMM    MMMMMMMMM                    
          MMMMM      MMMMMM    MMMMM        MMMMM           
        MMMMMMMM       MMMM   MMMMMM       MMMMMMMM         
        MMMMMMMM      MMMMMM  MMMMMMMM     MMMMMMMM         
        MMMMMMMMMMMMMMMMM         MMMMMMMMMMMMMMMMM         
        MMMMMMMMMMMMMMM             MMMMMMMMMMMMMMM         
        MMMMMMMMMMMMM   MMMMMMMMMMM   MMMMMMMMMMMMM         
        MMMMMMMMMMMM   MMM MMMMM MMM   MMMMMMMMMMMM         
        MMMMMMMMMMM  MMM       MM  MMM  MMMMMMMMMMM         
        MMMMMMMMMM   MMM       MMM MMM   MMMMMMMMMM         
        MMMMMMMMMM  MMMMM         MMMMM  MMMMMMMMMM         
        MMMMMMMMMM  MMMMMM          MMM  MMMMMMMMMM         
        MMMMMMMMMM  MMMMM  MM       MMM  MMMMMMMMMM         
        MMMMMMMMMM   MMM  MM  MM    MM   MMMMMMMMMM         
        MMMMMMMMMMM  MMM MM MMMMMMMMM   MMMMMMMMMMM         
        MMMMMMMMMMMM   MMMMMMMMMMMMM   MMMMMMMMMMMM         
                         MMMMMMMMM                          
                                                            
        M       M  MM      M     MM      M       M          
        M       M  M M     M     MM     MMM     MM          
        M       M  M  MM   M    M  M    M M    M M          
        M       M  M    M  M   MMMMMM   M  M  M  M          
         M     M   M     MMM  M     MM  M   MM   M         
          M M M    M       M  M      M  M        M         
                                                            
           MMMM      MMMMM      MMMM       MMMMMMMM        
        MM           M          M    M        MM           
        M            M          M    M        MM           
       MM            MMMM       M M           MM           
        M            M          M  MM         MM           
          MMMMMM     MMMMM      M    M        MM $Color_Off"

    sleep 5
	echo                                           > $LOG
	echo                                          >> $LOG
	echo "######################################" >> $LOG
	echo "###    ANALYZERS INSTALLATION     ####" >> $LOG
	echo "######################################" >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo            
	echo -e "$Cyan \n######################################"
	echo -e "###    ANALYZERS INSTALLATION   ####"
	echo -e "###################################### \n$Color_Off"
	echo
	echo
	echo -e "$Cyan \nDetecting Distribution..\n $Color_Off"
}

#####################################################################################################
#Writes in log file the command and if it was correct or not
log_command()
{
	if [ $1 -ne 0 ]; then
		echo "[`date +"%F %X"`] : $2 : [ERROR]" >> $LOG
		exit_install
	else
		echo "[`date +"%F %X"`] : $2 : [OK]" 	>> $LOG
	fi
}

#####################################################################################################
#Modifies sources.list file to install the packages
modify_repository()
{
	echo
	echo -e "$Cyan \nModify repository ...\n $Color_Off"
	echo
	echo                         >> $LOG
	echo "Modify repository ..." >> $LOG
	echo                         >> $LOG
	repositoryChange=1
	if [[ "$1" == *"Debian"* ]]; then
		cmd="cp /etc/apt/sources.list /etc/apt/sources.list.old"
		$cmd
		log_command $? "$cmd"
		sourcesList="/etc/apt/sources.list"
		if [[ "$1" == *"9"* ]]; then
		    sourcesPreferences="/etc/apt/preferences.d/jessie"
		    name="stretch"
			echo "Package: *" 			 > $sourcesPreferences
			echo "Pin: release n=stretch" 		 >> $sourcesPreferences
			echo "Pin-Priority: 900" 		 >> $sourcesPreferences
			echo "Package: *" 			 >> $sourcesPreferences
			echo "Pin: release n=jessie" 		 >> $sourcesPreferences
			echo "Pin-Priority: 400" 		 >> $sourcesPreferences
		fi
		if [[ "$1" == *"8"* ]]; then
		       	name="jessie"
	    fi
		echo "deb http://ftp.mx.debian.org/debian/ version main non-free contrib"	      | sed "s/version/$name/"  >  $sourcesList
		echo "deb-src http://ftp.mx.debian.org/debian/ version main non-free contrib"         | sed "s/version/$name/"  >> $sourcesList
		echo "deb http://security.debian.org/ version/updates main contrib non-free"          | sed "s/version/$name/"  >> $sourcesList
		echo "deb-src http://security.debian.org/ version/updates main contrib non-free"      | sed "s/version/$name/"  >> $sourcesList
		echo "deb http://ftp.mx.debian.org/debian/ version-updates main contrib non-free"     | sed "s/version/$name/"  >> $sourcesList
		echo "deb-src http://ftp.mx.debian.org/debian/ version-updates main contrib non-free" | sed "s/version/$name/"  >> $sourcesList
		echo "deb http://mirrors.kernel.org/debian version-updates main contrib non-free"     | sed "s/version/$name/"  >> $sourcesList
		echo "deb-src http://mirrors.kernel.org/debian version-updates main contrib non-free" | sed "s/version/$name/"  >> $sourcesList
		echo "deb http://ftp.debian.org/debian/ version-backports main contrib non-free"      | sed "s/version/$name/"  >> $sourcesList
		echo "deb http://mmc.geofisica.unam.mx/debian jessie main contrib non-free"  >> $sourcesList
		cmd="apt-get update"
		$cmd
		log_command $? "$cmd"
	fi
	if [[ "$1" == *"Ubuntu"* ]]; then
		cmd="cp /etc/apt/sources.list /etc/apt/sources.list.old"
		$cmd
		log_command $? "$cmd"
		sourcesList="/etc/apt/sources.list"
		if [[ "$1" == *"16"* ]]; then
		       	name="xenial"
	    fi
		if [[ "$1" == *"14"* ]]; then
		       	name="trusty"
	    fi
		if [[ "$1" == *"17"* ]]; then
		       	name="zesty"
	    fi
		echo "deb http://us.archive.ubuntu.com/ubuntu/ version main restricted"	      				| sed "s/version/$name/"  >  $sourcesList
		echo "deb http://us.archive.ubuntu.com/ubuntu/ version-updates main restricted"        			| sed "s/version/$name/"  >> $sourcesList
		echo "deb http://us.archive.ubuntu.com/ubuntu/ version universe"          				| sed "s/version/$name/"  >> $sourcesList
		echo "deb http://us.archive.ubuntu.com/ubuntu/ version-updates universe"      				| sed "s/version/$name/"  >> $sourcesList
		echo "deb http://us.archive.ubuntu.com/ubuntu/ version multiverse"     					| sed "s/version/$name/"  >> $sourcesList
		echo "deb http://us.archive.ubuntu.com/ubuntu/ version-updates multiverse" 				| sed "s/version/$name/"  >> $sourcesList
		echo "deb http://us.archive.ubuntu.com/ubuntu/ version-backports main restricted universe multiverse"   | sed "s/version/$name/"  >> $sourcesList
		echo "deb http://security.ubuntu.com/ubuntu version-security main restricted" 				| sed "s/version/$name/"  >> $sourcesList
		echo "deb http://security.ubuntu.com/ubuntu version-security universe"      				| sed "s/version/$name/"  >> $sourcesList
		echo "deb http://security.ubuntu.com/ubuntu version-security multiverse"      				| sed "s/version/$name/"  >> $sourcesList
		cmd="apt-get update"
		$cmd
		log_command $? "$cmd"
	fi
#	if [[ "$1" == *"Centos"* ]]; then
#		cmd="rpm -Uvh --force https://epel.mirror.constant.com/6/i386/epel-release-6-8.noarch.rpm"
#		$cmd
#		log_command "$?" "$cmd"
#	fi

}
#####################################################################################################
#Exits if script failed
exit_install()
{
	echo >> $LOG
	echo "[`date +"%F %X"`] - The installation script failed" >> $LOG
	echo >> $LOG
	echo
	echo -e "$Red \n[`date +"%F %X"`] - The installation script failed\n $Color_Off"
	echo
	exit 1
}

#####################################################################################################
#Returns sources.list to original state
end_repository()
{
	if [ $repositoryChange -eq 1 ]; then
		echo
		echo -e "$Cyan \nReturn repository to original condition ...\n $Color_Off"
		echo
		echo                                               >> $LOG
		echo "Return repository to original condition ..." >> $LOG
		echo                                               >> $LOG
		distribution=$(check_distribution)
		if [[ $distribution == *"Debian"* ]] || [[ $distribution == *"Ubuntu"* ]]; then
			cmd="cp /etc/apt/sources.list.old /etc/apt/sources.list"
			$cmd
			log_command $? "$cmd"
			cmd="apt-get update"
			$cmd
			log_command $? "$cmd"
#		else
#			cmd="rm /etc/yum.repos.d/epel.repo"
#			$cmd
#			log_command $? "$cmd"
		fi
	fi
}
#####################################################################################################
#Installs and configures OSSEC
configure_ossec()
{
	echo                                          >> $LOG
	echo "######################################" >> $LOG
	echo "###    	OSSEC INSTALLATION     	####" >> $LOG
	echo "######################################" >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo
	echo
	echo -e "$Cyan \n######################################"
	echo -e "###    	OSSEC INSTALLATION     	####"
	echo -e "###################################### \n $Color_Off"
	echo
	echo
			
	#Installs dependencies
	if [[ "$1" == *"Debian"*  ]] || [[ "$1" == *"Ubuntu"*  ]]; then
		cmd="apt-get -y install mailutils build-essential inotify-tools ntp postfix"
		$cmd
		log_command $? "$cmd"
	else
		cmd="yum install -y gcc gcc-c++ make openssl-devel inotify-tools postfix"
	fi
	
	#Downloads latest version and moves to created folder
	cmd="cd /opt"
	$cmd
	log_command "$?" "cmd"

	cmd="wget https://github.com/ossec/ossec-hids/archive/2.9.0.tar.gz"
	$cmd
	log_command "$?" "$cmd"

	cmd="tar zxvf 2.9.0.tar.gz"
	$cmd
	log_command "$?" "$cmd"

	cmd="cd ossec-hids-2.9.0"
	$cmd
	log_command "$?" "$cmd"

	#Modifies preloaded rules so installation script is not "too" interactive
	cmd="cp etc/preloaded-vars.conf.example etc/preloaded-vars.conf"
	$cmd
	log_command "$?" "$cmd"

	#Installation type = local	
	sed -i 's/^#\(USER_INSTALL_TYPE="local"\)/\1/' etc/preloaded-vars.conf
	log_command "$?" "sed -i 's/^#\(USER_INSTALL_TYPE=\"local\"\)/\1/' etc/preloaded-vars.conf"
	
	#Installation directory = /var/ossec
	sed -i 's~^#\(USER_DIR="/var/ossec"\)~\1~' etc/preloaded-vars.conf
	log_command "$?" "sed -i 's~^#\(USER_DIR=\"/var/ossec\"\)~\1~' etc/preloaded-vars.conf"
	
	#Enable rootcheck
	sed -i 's/^#\(USER_ENABLE_ROOTCHECK="y"\)/\1/' etc/preloaded-vars.conf	
	log_command "$?" "sed -i 's/^#\(USER_ENABLE_ROOTCHECK=\"y\"\)/\1/' etc/preloaded-vars.conf"
	
	#Enable syscheck
	sed -i 's/^#\(USER_ENABLE_SYSCHECK="y"\)/\1/' etc/preloaded-vars.conf	
	log_command "$?" "sed -i 's/^#\(USER_ENABLE_SYSCHECK=\"y\"\)/\1/' etc/preloaded-vars.conf"
	
	#Enable email
	sed -i 's/^#\(USER_ENABLE_EMAIL="y"\)/\1/' etc/preloaded-vars.conf	
	log_command "$?" "sed -i 's/^#\(USER_ENABLE_EMAIL=\"y\"\)/\1/' etc/preloaded-vars.conf"

	#USER_EMAIL_ADDRESS="root@localhost"
#	sed -i "s/^#\(USER_EMAIL_ADDRESS=\).*/\1\"$destemail\"/" etc/preloaded-vars.conf
#	log_command "$?" "sed -i \"s/^#\(USER_EMAIL_ADDRESS=\).*/\1\"$destemail\"/\ etc/preloaded-vars.conf"

	#USER_ENABLE_SYSLOG="y"
	sed -i 's/^#\(USER_ENABLE_SYSLOG="y"\)/\1/' etc/preloaded-vars.conf	
	log_command "$?" "sed -i 's/^#\(USER_ENABLE_SYSLOG=\"y\"\)/\1/' etc/preloaded-vars.conf"

	#USER_ENABLE_FIREWALL_RESPONSE="y"
	sed -i 's/^#\(USER_ENABLE_FIREWALL_RESPONSE="y"\)/\1/' etc/preloaded-vars.conf	
	log_command "$?" "sed -i 's/^#\(USER_ENABLE_FIREWALL_RESPONSE=\"y\"\)/\1/' etc/preloaded-vars.conf"


	#Runs script that installs ossec
	cmd="./install.sh"
	$cmd
	log_command "$?" "$cmd"

	#Copying rules template
	cmd="mv $OSSEC_RULES $OSSEC_RULES.bak"
	$cmd
	log_command "$?" "$cmd"
    
	cmd="cp $OSSEC_RULES_TEMP $OSSEC_RULES"
	$cmd
	log_command "$?" "$cmd"

    #Copying configuration template
    cmd="mv $OSSEC_CONF $OSSEC_CONF.bak"
    $cmd
	log_command "$?" "$cmd"
    
    cmd="cp $OSSEC_CONF_TEMP $OSSEC_CONF"
    $cmd
	log_command "$?" "$cmd"
	#Starts service
	cmd="service ossec start"
	$cmd
	log_command "$?" "$cmd"
}

#####################################################################################################
configure_f2b()
{
	echo                                          >> $LOG
	echo "######################################" >> $LOG
	echo "###    FAIL2BAN INSTALLATION	####" >> $LOG
	echo "######################################" >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo
	echo
	echo -e "$Cyan \n######################################"
	echo -e "###    FAIL2BAN INSTALLATION	####"
	echo -e "######################################\n $Color_Off"
	echo
	echo

	#Installs fail2ban from packages
	if [[ "$1" == *"Debian"*  ]] || [[ "$1" == *"Ubuntu"*  ]]; then
		cmd="apt-get -y install fail2ban mailutils"
		$cmd
		log_command $? "$cmd"
	else
		cmd="yum install -y epel-release"
		$cmd
		log_command $? "$cmd"

		cmd="yum install -y fail2ban postfix"
		$cmd
		log_command $? "$cmd"
	fi

	if [[ "$1" == *"Debian"*  ]] || [[ "$1" == *"Ubuntu"*  ]]; then
		apache_name="apache2"
		mysql_name="mysql"
		nginx_name="nginx"
		list_services="service --status-all"
	elif [[ "$1" = *"CentOS 6"* ]]; then
		apache_name="httpd"
		mysql_name="mysqld"
		nginx_name="nginx"
		list_services="service --status-all"
	else
		apache_name="httpd"
		mysql_name="mariadb"
		nginx_name="nginx"
		list_services="systemctl list-unit-files"
	fi
		


	#This file will be used to change configurations instead of jail.conf
	jail="/etc/fail2ban/jail.local"

	#Copies from jail.conf to jail.local all lines that are not commented
	sed -e '/#.*$/d' -e '/^$/d' $F2B_TEMP > $jail
	log_command "$?" "sed -e '/#.*$/d' -e '/^$/d' $F2B_TEMP > $jail"
 
	#Sets default bantime
	sed -i "0,/\(bantime[ \t]*=\).*/s/\(bantime[ \t]*=\).*/\1 $bantime/" $jail
	log_command "$?" "sed -i \"0,/\(bantime[ \t]*=\).*/s/\(bantime[ \t]*=\).*/\1 $bantime/\" $jail"
	
	#Sets default findtime
	sed -i "0,/\(findtime[ \t]*=\).*/s/\(findtime[ \t]*=\).*/\1 $findtime/" $jail
	log_command "$?" "sed -i \"0,/\(findtime[ \t]*=\).*/s/\(findtime[ \t]*=\).*/\1 $findtime/\" $jail"
	
	#Sets default maxretry
	sed -i "0,/\(maxretry[ \t]*=\).*/s/\(maxretry[ \t]*=\).*/\1 $maxretry/" $jail
	log_command "$?" "sed -i \"0,/\(maxretry[ \t]*=\).*/s/\(maxretry[ \t]*=\).*/\1 $maxretry/\" $jail"

	#Sets the email that will receive alert from a new ban
	sed -i "s/\(^destemail[ \t]*=\).*/\1 $destemail/" $jail
	log_command "$?" "sed -i \"s/\(^destemail[ \t]*=\).*/\1 $destemail/\" $jail"
		
	#Configures the email that sends alerts 
	sed -i "s/\(^sender[ \t]*=\).*/\1 $sender/" $jail
	log_command "$?" "sed -i \"s/\(^sender[ \t]*=\).*/\1 $sender/\" $jail"
	
	#Sets the action to send mail with the log lines
	sed -i "s/\(^action[ \t]*=\).*/\1 %(action_mwl)s/" $jail
	log_command "$?" "sed -i \"s/\(^action[ \t]*=\).*/\1 %(action_mwl)s/\" $jail"

	#Enables sshd protection
	sed -i 's/\(\[sshd\]\)/\1 \nenabled = true/' $jail
		log_command "$?" "sed -i 's/\(\[sshd\]\)/\1 \nenabled = true/' $jail"

	#Detects if apache is installed. If so, enables protection
	service=$($list_services | grep $apache_name)
	if [[ $service == *"$apache_name"*  ]]; then
		sed -i 's/\(\[apache-auth\]\)/\1 \nenabled = true/' $jail
		log_command "$?" "sed -i 's/\(\[apache-auth\]\)/\1 \nenabled = true/' $jail"
		sed -i 's/\(\[apache-badbots\]\)/\1 \nenabled = true/' $jail
		log_command "$?" "sed -i 's/\(\[apache-badbots\]\)/\1 \nenabled = true/' $jail"
		sed -i 's/\(\[apache-shellshock\]\)/\1 \nenabled = true/' $jail
		log_command "$?" "sed -i 's/\(\[apache-shellshock\]\)/\1 \nenabled = true/' $jail"
	fi

	#Get the running service ports
	ssh_port=`netstat -natp | column -t | grep "sshd\|ssh" | awk '{print $4}' | rev |cut -d':' -f 1 | rev| uniq`
	apache_port=`netstat -natp | column -t | grep apache2 | awk '{print $4}' | rev |cut -d':' -f 1 | rev| uniq`
	httpd_port=`netstat -natp | column -t | grep httpd | awk '{print $4}' | rev |cut -d':' -f 1 | rev| uniq`
	nginx_port=`netstat -natp | column -t | grep nginx | awk '{print $4}' | rev |cut -d':' -f 1 | rev| uniq`

	#If the ssh service is active, it is configured
	if [ -n "$ssh_port" ];then
	    echo "SSH Port:$ssh_port"
	    sed -i "s/\(^port*=\)*SSH_PORT$/\1 $ssh_port /" $jail
	fi

	#If the apache service is active, it is configured
	if [ -n "$apache_port" ];then
	    tmp_arr=$(echo $apache_port | tr " " "\n")
	    apache=''
	    for x in $tmp_arr
	    do
		if [ "$apache" = "" ];then
	            apache="$x"
	        else
	            apache="$apache,$x"
	        fi
	    done
	#    echo "Web Ports:$apache"
	    sed -i "s/\(^port*=\)*APACHE_PORT$/\1 $apache /" $jail
	fi

	#If the httpd service is active, it is configured
	if [ -n "$httpd_port" ];then
	    tmp_arr=$(echo $httpd_port | tr " " "\n")
	    httpd=''
	    for x in $tmp_arr
	    do
	        if [ "$httpd" = "" ];then
	            httpd="$x"
	        else
	            httpd="$httpd,$x"
	        fi
	    done
	#    echo "Web Ports:$httpd"
	    sed -i "s/\(^port*=\)*APACHE_PORT$/\1 $httpd /" $jail
	fi

	#If the nginx service is active, it is configured
	if [ -n "$nginx_port" ];then
	    tmp_arr=$(echo $nginx_port | tr " " "\n")
	    nginx=''
	    for x in $tmp_arr
	    do
	        if [ "$nginx" = "" ];then
	            nginx="$x"
	        else
	            nginx="$nginx,$x"
	        fi
	    done
	#    echo "Nginx Ports:$nginx"
	    sed -i "s/\(^port*=\)*NGINX_PORT$/\1 $httpd /" $jail
	fi


#	#Detects if mysql is installed. If so, enables protection
#	service=$($list_services | grep $mysql_name)
#	if [[ $service == *"$mysql_name"*  ]]; then
#		sed -i 's/\(\[mysqld-auth\]\)/\1 \nenabled = true/' $jail
#		log_command "$?" "sed -i 's/\(\[mysqld-auth\]\)/\1 \nenabled = true/' $jail"
#	fi

	#Detects it nginx is installed. If so, enables protection
	service=$($list_services | grep $nginx_name)
	if [[ $service == *"$nginx_name"*  ]]; then
		sed -i 's/\(\[nginx-http-auth\]\)/\1 \nenabled = true/' $jail
		log_command "$?" "sed -i 's/\(\[nginx-http-auth\]\)/\1 \nenabled = true/' $jail"
	fi

	if [[ "$1" = *"Ubuntu 14"* ]]; then
		sed -i "s/\[ssh-route\]/#[ssh-route]/" /etc/fail2ban/jail.local
		sed -i "s/\[recidive\]/#[recidive]/" /etc/fail2ban/jail.local
	fi


	#Restart service
	cmd="service fail2ban restart"
	$cmd
	log_command "$?" "$cmd"
}

#####################################################################################################
#Installing and configuring logwatch
configure_lw()
{
	echo                                          >> $LOG
	echo "######################################" >> $LOG
	echo "###    LOGWATCH INSTALLATION	####" >> $LOG
	echo "######################################" >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo
	echo
	echo -e "$Cyan \n######################################"
	echo -e "###    LOGWATCH INSTALLATION	####"
	echo -e "######################################\n $Color_Off"
	echo
	echo

	#Installs logwatch from packages
	if [[ "$1" == *"Debian"*  ]] || [[ "$1" == *"Ubuntu"*  ]]; then
		cmd="apt-get -y install logwatch mailutils postfix"
		$cmd
		log_command $? "$cmd"
	else
		cmd="yum install -y epel-release"
		$cmd
		log_command $? "$cmd"

		cmd="yum install -y logwatch postfix"
		$cmd
		log_command $? "$cmd"
	fi
	
	#logwtch.conf is the main configuration file for logwatch
	lwconf="/usr/share/logwatch/default.conf/logwatch.conf"
	
	#Output = mail 
	sed -i "s/\(^Output[ \t]*=\).*/\1 mail/" $lwconf
	log_command "$?" "sed -i \"s/\(^Output[ \t]*=\).*/\1 mail/\" $lwconf"

	#Sets mail that will receive reports
	sed -i "s/\(^MailTo[ \t]*=\).*/\1 $destemail/" $lwconf
	log_command "$?" "sed -i \"s/\(^MailTo[ \t]*=\).*/\1 $destemail/\" $lwconf"

	#Sets the detail level as low (low, med, high)
	sed -i "s/\(^Detail[ \t]*=\).*/\1 Low/" $lwconf
	log_command "$?" "sed -i \"s/\(^Detail[ \t]*=\).*/\1 Low/\" $lwconf"
	
	#Creates cron job to execute logwatch at 1:15 everyday
	crontab -l | { cat; echo "15 1 * * * /usr/sbin/logwatch"; } | crontab -
	log_command "$?" "crontab -l | { cat; echo \"15 1 * * * /usr/sbin/logwatch\"; } | crontab -"
}

#####################################################################################################
#Installing and configuring logcheck
configure_lc()
{
	echo                                          >> $LOG
	echo "######################################" >> $LOG
	echo "###    LOGCHECK INSTALLATION	####" >> $LOG
	echo "######################################" >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo
	echo
	echo -e "$Cyan \n######################################"
	echo -e "###    LOGCHECK INSTALLATION	####"
	echo -e "######################################\n $Color_Off"
	echo
	echo

	#Installs logwatch from packages
	if [[ "$1" == *"Debian"*  ]] || [[ "$1" == *"Ubuntu"*  ]]; then
		cmd="apt-get -y install logcheck mailutils postfix"
		$cmd
		log_command $? "$cmd"
	else
		cmd="yum install -y epel-release"
		$cmd
		log_command $? "$cmd"

		cmd="yum install -y logcheck postfix"
		$cmd
		log_command $? "$cmd"
	fi

	#Log paths
	apache_access="/var/log/apache2/access.log"
	apache_error="/var/log/apache2/error.log"
	httpd_access="log/httpd/access_log"
	httpd_error="log/httpd/error_log"
	nginx_access="/var/log/nginx/access.log"
	nginx_error="/var/log/nginx/error.log"
	mysql_log="/var/log/mysql.log"
	mail_log_1="/var/log/mail.log"
	mail_log_2="/var/log/maillog"


	
	#logcheck.conf is the main configuration file for logwcheck
	lcconf="/etc/logcheck/logcheck.conf"
	
	#logcheck.files, it contains the log files to audit
	lcfiles="/etc/logcheck/logcheck.logfiles "

	#Sets mail that will receive reports
	sed -i "s/SENDMAILTO=\"logcheck\"/SENDMAILTO=\"$destemail\"/" $lcconf
	log_command "$?" "sed -i \"s/SENDMAILTO=\"logcheck\"/SENDMAILTO=\"$destemail\"/\" $lcconf"

	if [ -f "$apache_access" ]; then 
        echo "$apache_access" >> lcfiles
	fi
	if [ -f "$apache_error" ]; then 
        echo "$apache_error" >> lcfiles
	fi
	if [ -f "$httpd_access" ]; then 
        echo "$httpd_access" >> lcfiles
	fi
	if [ -f "$httpd_error" ]; then 
        echo "$httpd_error" >> lcfiles
	fi
	if [ -f "$nginx_access" ]; then 
        echo "$nginx_access" >> lcfiles
	fi
	if [ -f "$nginx_error" ]; then 
        echo "$nginx_error" >> lcfiles
	fi
	if [ -f "$mysql_log" ]; then 
        echo "$mysql_log" >> lcfiles
	fi
	if [ -f "$mail_log_1" ]; then 
        echo "$mail_log_1" >> lcfiles
	fi
	if [ -f "$mail_log_2" ]; then 
        echo "$mail_log_2" >> lcfiles
	fi

	#Creates cron job to execute logwatch at 1:15 everyday
	#crontab -l | { cat; echo "15 1 * * * /usr/sbin/logwatch"; } | crontab -
	#log_command "$?" "crontab -l | { cat; echo \"15 1 * * * /usr/sbin/logwatch\"; } | crontab -"
}

#########################################
#	Starts the installation		        #
#########################################

user_install
banner_log
distribution=$(check_distribution)
modify_repository "$distribution"
if [[ $distribution == *"CentOS 7"* ]]; then
	list_services="systemctl list-unit-files"
else
	list_services="service --status-all"
fi

#Checks if OSSEC service is installed and if not, configures it
serv=$($list_services | grep 'ossec')
if [[ $serv == *"ossec"* ]]; then
	echo "OSSEC already installed" >> $LOG
	echo -e "$Cyan \nOSSEC already installed \n $Color_Off"
else
	configure_ossec "$distribution"
fi


#Checks if FAIL2BAN service is installed and if not, configures it
serv=$($list_services | grep 'fail2ban')
if [[ $serv == *"fail2ban"* ]]; then
	echo "FAIL2BAN already installed" >> $LOG
	echo -e "$Cyan \nFAIL2BAN already installed \n $Color_Off"
else
	configure_f2b "$distribution"
fi

#Checks if LOGWATCH program is installed and if not, configures it
lw=$(which logwatch)
if [[ $lw == *"logwatch"*  ]]; then
	echo "LOGWATCH already installed" >> $LOG
	echo -e "$Cyan \nLOGWATCH already installed\n $Color_Off"	
else
	configure_lw "$distribution"
fi

#Checks if LOGCHECK program is installed and if not, configures it
lw=$(which logcheck)
if [[ $lw == *"logcheck"*  ]]; then
	echo "LOGCHECK already installed" >> $LOG
	echo -e "$Cyan \nLOGCHECK already installed\n $Color_Off"	
	echo -e "$Cyan \nReturn repository to original condition ...\n $Color_Off"	
else
	configure_lc "$distribution"
fi