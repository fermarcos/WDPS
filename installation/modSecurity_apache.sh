#!/bin/bash

####################################################################
# Bash script to install ModSecurity. For Debian 8, 9, Ubuntu 14, 16 , 17 and CentOS 6, 7 systems.
# Written by Fernando Marcos Parra Arroyo
# Requirements:
#	Internet Connection
#	User Root
####################################################################

#LogFile
LOG="`pwd`/installModSecurity.log"

#COLORS
# Reset
Color_Off='\033[0m'       # Text Reset

# Regular Colors
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan


#Checking root permissions
check_user()
{
	echo -e "$Cyan \nChecking root permissions..\n $Color_Off"
	if [ "$(id -u)" != "0" ]; then
		echo -e  "$Red ERROR ################################# $Color_Off" 1>&2
	   	echo -e  "$Red ERROR #This script must be run as root# $Color_Off" 1>&2
	   	echo -e  "$Red ERROR ################################# \n$Color_Off" 1>&2
		exit 1
	fi
}

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

	echo                                           > $LOG
	echo                                          >> $LOG
	echo "######################################" >> $LOG
	echo "###    MODSECURITY INSTALLATION   ####" >> $LOG
	echo "######################################" >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo            
	echo -e "$Cyan \n######################################"
	echo -e "###    MODSECURITY INSTALLATION   ####"
	echo -e "###################################### $Color_Off"
	echo
	echo
	echo -e "$Cyan \nDetecting Distribution..\n $Color_Off"
	sleep 5
}

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

#Installing dependencies
#Modifies sources.list file to install the packages
install_dependencies_apache()
{
	echo
	echo -e "$Cyan \nInstalling dependencies ...\n $Color_Off"
	echo
	echo                         >> $LOG
	echo "Installing dependencies ..." >> $LOG
	echo                         >> $LOG

	if [[ "$1" == *"Debian"* ]]; then
		cmd="apt-get update"
		$cmd
		log_command $? "$cmd"
	fi
	if [[ "$1" == *"Ubuntu"* ]]; then
		cmd="apt-get update"
		$cmd
		log_command $? "$cmd"
	fi
	if [[ "$1" == *"CentOS"* ]]; then
		cmd="rpm -Uvh --force https://epel.mirror.constant.com/6/i386/epel-release-6-8.noarch.rpm"
		$cmd
		log_command "$?" "$cmd"
	fi

}
#Installing Modsecurity
install_modsecurity_apache()
{
	echo
	echo -e "$Cyan \nInstalling ModSecurity ...\n $Color_Off"
	echo
	echo                         >> $LOG
	echo "Installing ModSecurity ..." >> $LOG
	echo                         >> $LOG

	if [[ "$1" == *"Debian"* || "$1" == *"Ubuntu"*  ]]; then
		cmd="apt-get install git libapache2-mod-security2 -y"
		$cmd
		log_command $? "$cmd"

		echo
		echo -e "$Cyan \nConfiguring ModSecurity ...\n $Color_Off"
		echo
		echo                         >> $LOG
		echo "Configuring ModSecurity ..." >> $LOG
		echo                         >> $LOG

		if [ -f "/etc/modsecurity/modsecurity.conf-recommended" ]; then
			cmd="mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf"
			$cmd
			log_command $? "$cmd"		
		fi

		sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/modsecurity/modsecurity.conf
		log_command $? "sed -i \"s/SecRuleEngine DetectionOnly/SecRuleEngine On/\" /etc/modsecurity/modsecurity.conf"

		sed -i "s/SecResponseBodyAccess On/SecResponseBodyAccess Off/" /etc/modsecurity/modsecurity.conf 
		log_command $? "sed -i \"s/SecResponseBodyAccess On/SecResponseBodyAccess Off/\" /etc/modsecurity/modsecurity.conf "

		cmd="a2enmod security2"
		$cmd
		log_command $? "$cmd"

		cmd="/etc/init.d/apache2 restart"
		$cmd
		log_command $? "$cmd"
	fi

	if [[ "$1" == *"CentOS"* ]]; then
		cmd="yum install git mod_security mod_security_crs -y"
		$cmd
		log_command "$?" "$cmd"


		echo
		echo -e "$Cyan \nConfiguring ModSecurity ...\n $Color_Off"
		echo
		echo                         >> $LOG
		echo "Configuring ModSecurity ..." >> $LOG
		echo                         >> $LOG


		sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/httpd/conf.d/mod_security.conf
		log_command "$?" "$cmd"

		sed -i "s/SecResponseBodyAccess On/SecResponseBodyAccess Off/" /etc/httpd/conf.d/mod_security.conf
		log_command "$?" "sed -i \"s/SecResponseBodyAccess On/SecResponseBodyAccess Off/\" /etc/httpd/conf.d/mod_security.conf"

		cmd="service httpd restart"
		$cmd
		log_command "$?" "$cmd"
	fi

}


configuring_rules()
{

	echo
	echo -e "$Cyan \nConfiguring rules ...\n $Color_Off"
	echo
	echo                         >> $LOG
	echo "Configuring rules ..." >> $LOG
	echo                         >> $LOG	

	if [[ "$1" == *"Debian"* || "$1" == *"Ubuntu"*  ]]; then


		echo -e "$Cyan \nDetecting Apache Version $Color_Off"
		apachectl -v | grep version | cut -d" " -f3
		log_command "$?" "apachectl -v | grep version | cut -d\" \" -f3"

		V1=`apachectl -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f1`
		V2=`apachectl -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f2`
		V3=`apachectl -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f3`


		if [[ "$V1" -lt "2" || "$V2" -lt "4" || "$V3" -lt "11" ]]; then
			echo "You need to upgrade Apache to a version equal to or greater than Apache 2.4.11 to apply the OWASP rule set. For more information visit https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0.0-rc2/KNOWN_BUGS."

			echo -e "$Cyan \nConfiguring Default Rules $Color_Off"


			sed -i "s/IncludeOptional \/usr\/share\/modsecurity-crs\/owasp-crs\.load/#IncludeOptional \/usr\/share\/modsecurity-crs\/owasp-crs\.load/" /etc/apache2/mods-enabled/security2.conf
			sed -i "s/IncludeOptional \/etc\/modsecurity\/\*\.conf/IncludeOptional \/etc\/modsecurity\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/activated_rules\/\*\.conf    /" /etc/apache2/mods-enabled/security2.conf
			log_command "$?" "sed -i \"s/IncludeOptional \/etc\/modsecurity\/\*\.conf/IncludeOptional \/etc\/modsecurity\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/activated_rules\/\*\.conf    /\" /etc/apache2/mods-enabled/security2.conf"

			cmd="cd /usr/share/modsecurity-crs/activated_rules"
			$cmd
			log_command "$?" "$cmd"

			cmd="ln -s ../base_rules/modsecurity_crs_41_xss_attacks.conf ."
			$cmd
			log_command "$?" "$cmd"

			cmd="ln -s ../base_rules/modsecurity_40_generic_attacks.data ."
			$cmd
			log_command "$?" "$cmd"

			cmd="ln -s ../base_rules/modsecurity_crs_40_generic_attacks.conf ."
			$cmd
			log_command "$?" "$cmd"

			cmd="ln -s ../base_rules/modsecurity_crs_41_sql_injection_attacks.conf ."
			$cmd
			log_command "$?" "$cmd"

			cmd="/etc/init.d/apache2 restart"
			$cmd
			log_command "$?" "$cmd"

			cmd="/etc/init.d/apache2 restart"
			$cmd
			log_command "$?" "$cmd"			
		else
			echo -e "$Cyan \nConfiguring OWASP Rules $Color_Off"

			sed -i "s/IncludeOptional \/usr\/share\/modsecurity-crs\/owasp-crs\.load/#IncludeOptional \/usr\/share\/modsecurity-crs\/owasp-crs\.load/" /etc/apache2/mods-enabled/security2.conf
			cmd="rm -rf /usr/share/modsecurity-crs"
			$cmd
			log_command "$?" "$cmd"

			cmd="git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git /usr/share/modsecurity-crs"
			$cmd
			log_command "$?" "$cmd"

			cmd="cp /usr/share/modsecurity-crs/crs-setup.conf.example /usr/share/modsecurity-crs/crs-setup.conf"
			$cmd
			log_command "$?" "$cmd"

			cmd="cp  /etc/apache2/mods-enabled/security2.conf /etc/apache2/mods-enabled/security2.conf.bak"
			$cmd
			log_command "$?" "$cmd"

			sed -i "s/IncludeOptional \/etc\/modsecurity\/\*\.conf/IncludeOptional \/etc\/modsecurity\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/rules\/\*\.conf    /" /etc/apache2/mods-enabled/security2.conf
			log_command "$?" "sed -i \"s/IncludeOptional \/etc\/modsecurity\/\*\.conf/IncludeOptional \/etc\/modsecurity\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/rules\/\*\.conf    /\" /etc/apache2/mods-enabled/security2.conf"

			cmd="/etc/init.d/apache2 restart"
			$cmd
			log_command "$?" "$cmd"
		fi
	fi

	if [[ "$1" == *"CentOS"* ]]; then

		echo -e "$Cyan \nDetecting Apache Version $Color_Off"

		httpd -v | grep version | cut -d" " -f3
		log_command $? "httpd -v | grep version | cut -d\" \" -f3"

		V1=`httpd -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f1`
		V2=`httpd -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f2`
		V3=`httpd -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f3`

		if [[ "$V1" -lt "2" || "$V2" -lt "4" || "$V3" -lt "11" ]]; then
		    echo "You need to upgrade Apache to a version equal to or greater than Apache 2.4.11 to apply the OWASP rule set. For more information visit https://github.com/SpiderLabs/owasp-modsecurity-crs/blob/v3.0.0-rc2/KNOWN_BUGS."

		    echo -e "$Cyan \nConfiguring Default Rules $Color_Off"

		    sed -i 's/^\(SecRuleEngine\).*/\1 On/' /etc/httpd/conf.d/mod_security.conf
			log_command $? "sed -i 's/^\(SecRuleEngine\).*/\1 On/' /etc/httpd/conf.d/mod_security.conf"	
	
		    #sed -i "s/IncludeOptional \/etc\/modsecurity\/\*\.conf/IncludeOptional \/etc\/modsecurity\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/activated_rules\/\*\.conf    /" /etc/apache2/mods-enabled/security2.conf
			#log_command "$?" "sed -i \"s/IncludeOptional \/etc\/modsecurity\/\*\.conf/IncludeOptional \/etc\/modsecurity\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/activated_rules\/\*\.conf    /\" /etc/apache2/mods-enabled/security2.conf"

			cmd="mv /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_50_outbound.conf /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_50_outbound.conf.example"
			$cmd
			log_command "$?" "$cmd"

			cmd="mv /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_21_protocol_anomalies.conf /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_21_protocol_anomalies.conf.example"
			$cmd
			log_command "$?" "$cmd"

			cmd="mv /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_30_http_policy.conf /etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_30_http_policy.conf.example"
			$cmd
			log_command "$?" "$cmd"

			cmd="service httpd restart"
			$cmd
			log_command "$?" "$cmd"
	
		else
		    echo -e "$Cyan \nConfiguring OWASP Rules $Color_Off"
			#rm -rf /usr/share/modsecurity-crs
			#yum install -y git
			#git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git /usr/share/modsecurity-crs
			#cp /usr/share/modsecurity-crs/crs-setup.conf.example /usr/share/modsecurity-crs/crs-setup.conf
			#cp  /etc/apache2/mods-enabled/security2.conf /etc/apache2/mods-enabled/security2.conf.bak
			#sed -i "s/IncludeOptional \/etc\/modsecurity\/\*\.conf/IncludeOptional \/etc\/modsecurity\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/\*\.conf \n\tIncludeOptional \/usr\/share\/modsecurity-crs\/rules\/\*\.conf    /" /etc/apache2/mods-enabled/security2.conf
			#/etc/init.d/apache2 restart
		fi
	fi
}

#Running functions
check_user
banner_log
distribution=$(check_distribution)
echo $distribution


install_dependencies_apache "$distribution" 
install_modsecurity_apache "$distribution"
configuring_rules "$distribution"