#!/bin/bash

##########################################################################
### Bash script to install ModSecurity. For Debian 8, 9, Ubuntu 14, 16 ###
### 17 and CentOS 6, 7 systems.                                        ###
### Written by Fernando Marcos Parra Arroyo                            ###
### Requirements:                                                      ###
###	Internet Connection                                                ###
###	User Root                                                          ###
##########################################################################


#==========================================#
	#LogFile
	LOG="`pwd`/../log/installModSecurity.log"

	#COLORS
	Color_Off='\033[0m'       # Text Reset
	# Regular Colors
	Red='\033[0;31m'          # Red
	Green='\033[0;32m'        # Green
	Yellow='\033[0;33m'       # Yellow
	Purple='\033[0;35m'       # Purple
	Cyan='\033[0;36m'         # Cyan
#==========================================#

###################################################################
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
###################################################################
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
###################################################################
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
}
###################################################################
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
###################################################################
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
install_dependencies_nginx()
{
	echo
	echo -e "$Cyan \nInstalling dependencies ...\n $Color_Off"
	echo
	echo                         >> $LOG
	echo "Installing dependencies ..." >> $LOG
	echo                         >> $LOG
	repositoryChange=1
	if [[ "$1" == *"Debian"* ]]; then
		cmd="apt-get install -y git zlibc zlib1g zlib1g-dev libgeoip-dev libgeoip1 git build-essential libpcre3 libpcre3-dev libssl-dev libtool autoconf apache2-dev libxml2-dev libcurl4-openssl-dev automake pkgconf"
		$cmd
		log_command $? "$cmd"
	fi
	if [[ "$1" == *"Ubuntu"* ]]; then
		cmd="apt-get update"
		$cmd
		log_command $? "$cmd"

		cmd="apt-get install -y git zlibc zlib1g zlib1g-dev libgeoip-dev libgeoip1 git build-essential libpcre3 libpcre3-dev libssl-dev libtool autoconf apache2-dev libxml2-dev libcurl4-openssl-dev automake pkgconf"
		$cmd
		log_command $? "$cmd"
	fi
	if [[ "$1" == *"CentOS"* ]]; then
#		cmd="rpm -Uvh --force https://epel.mirror.constant.com/6/i386/epel-release-6-8.noarch.rpm"
#		$cmd
#		log_command "$?" "$cmd"

		yum groupinstall -y "Development Tools"
		log_command "$?" "yum groupinstall -y \"Development Tools\""


		cmd="yum install -y git  libtool autoconf  automake httpd httpd-devel pcre pcre-devel libxml2 libxml2-devel curl curl-devel openssl openssl-devel"
		$cmd
		log_command "$?" "$cmd"
	fi

}
###################################################################
#Installing Modsecurity
install_modsecurity_nginx()
{

	echo
	echo -e "$Cyan \nInstalling ModSecurity ...\n $Color_Off"
	echo
	echo                         >> $LOG
	echo "Installing ModSecurity ..." >> $LOG
	echo                         >> $LOG


	if [[ "$1" == *"Debian"* || "$1" == *"Ubuntu"* || "$1" == "CentOS 7" ]]; then
#		cmd="apt-get install git libapache2-mod-security2 -y"
#		$cmd
#		log_command $? "$cmd"

		#Download folder
		cmd="cd /opt"
		$cmd
		log_command $? "$cmd"
		#Downloading ModSecurity
		cmd="git clone https://github.com/SpiderLabs/ModSecurity"
		$cmd
		log_command $? "$cmd"

		cmd="cd ModSecurity"
		$cmd
		log_command $? "$cmd"  

		cmd="git checkout -b v3/master origin/v3/master"
		$cmd
		log_command $? "$cmd"  

		 
		#Compiling ModSecurity
		cmd="sh build.sh"
		$cmd
		log_command $? "$cmd"

		cmd="git submodule init"
		$cmd
		log_command $? "$cmd"

		cmd="git submodule update"
		$cmd
		log_command $? "$cmd"

		cmd="./configure"
		$cmd
		log_command $? "$cmd"

		cmd="make"
		$cmd
		log_command $? "$cmd"

		cmd="make install"
		$cmd
		log_command $? "$cmd"

		#Modsecurity and nginx Connector

		cmd="cd /opt/"
		$cmd
		log_command $? "$cmd"

		cmd="git clone https://github.com/SpiderLabs/ModSecurity-nginx.git"
		$cmd
		log_command $? "$cmd"
	fi

	if [[ "$1" == *"CentOS 6"* ]]; then
		cmd="cd /opt/"
		$cmd
		log_command "$?" "$cmd"

		cmd="git clone -b nginx_refactoring https://github.com/SpiderLabs/ModSecurity.git"
		$cmd
		log_command "$?" "$cmd"

		cmd="cd ModSecurity"
		$cmd
		log_command "$?" "$cmd"

		cmd="./autogen.sh"
		$cmd
		log_command "$?" "$cmd"

		cmd="./configure --enable-standalone-module --disable-mlogc"
		$cmd
		log_command "$?" "$cmd"

		cmd="make"
		$cmd
		log_command "$?" "$cmd"

		cmd="make install"
		$cmd
		log_command "$?" "$cmd"
	fi
}
###################################################################
install_nginx()
{

	echo
	echo -e "$Cyan \nInstalling Nginx ...\n $Color_Off"
	echo
	echo                         >> $LOG
	echo "Installing Nginx ..." >> $LOG
	echo                         >> $LOG


	if [[ "$1" == *"Debian"* || "$1" == *"Ubuntu"* || "$1" == "CentOS 7" ]]; then
		cmd="cd /opt"
		$cmd
		log_command $? "$cmd"

		cmd="wget http://nginx.org/download/nginx-1.12.0.tar.gz "
		$cmd
		log_command $? "$cmd"

		cmd="tar -zxf nginx-1.12.0.tar.gz "
		$cmd
		log_command $? "$cmd"

		cmd="cd nginx-1.12.0"
		$cmd
		log_command $? "$cmd"

		cmd="./configure --user=www-data --group=www-data --with-pcre-jit --with-debug --with-http_ssl_module --with-http_realip_module --add-module=/opt/ModSecurity-nginx "
		$cmd
		log_command $? "$cmd"

		cmd="make"
		$cmd
		log_command $? "$cmd"

		cmd="make install"
		$cmd
		log_command $? "$cmd"
	fi	


	if [[ "$1" == *"CentOS 6"* ]]; then
		cmd="cd /opt"
		$cmd
		log_command "$?" "$cmd"

		cmd="wget http://nginx.org/download/nginx-1.12.0.tar.gz"
		$cmd
		log_command "$?" "$cmd"

		cmd="tar -zxf nginx-1.12.0.tar.gz"
		$cmd
		log_command "$?" "$cmd"

		cmd="cd nginx-1.12.0"
		$cmd
		log_command "$?" "$cmd"

		cmd="groupadd -r nginx"
		$cmd
		log_command "$?" "$cmd"
		
		cmd="useradd -r -g nginx -s /sbin/nologin -M nginx"
		$cmd
		log_command "$?" "$cmd"

		cmd="./configure --user=nginx --group=nginx --add-module=/opt/ModSecurity/nginx/modsecurity --with-http_ssl_module"
		$cmd
		log_command "$?" "$cmd"

		cmd="make"
		$cmd
		log_command "$?" "$cmd"

		cmd="make install"
		$cmd
		log_command "$?" "$cmd"
	fi
}
###################################################################
configuring_nginx()
{

	echo
	echo -e "$Cyan \nConfiguring Nginx ...\n $Color_Off"
	echo
	echo                         >> $LOG
	echo "Configuring Nginx ..." >> $LOG
	echo                         >> $LOG	


	if [[ "$1" == *"Debian"* || "$1" == *"Ubuntu"*  ]]; then

		cmd="cp /opt/ModSecurity/modsecurity.conf-recommended /usr/local/nginx/conf/modsecurity.conf"
		$cmd
		log_command $? "$cmd"

		cmd="ln -s /usr/local/nginx/sbin/nginx /bin/nginx"
		$cmd
		log_command $? "$cmd"

		cmd="mkdir /usr/local/nginx/conf/sites-available "
		$cmd
		log_command $? "$cmd"

		cmd="mkdir /usr/local/nginx/conf/sites-enabled"
		$cmd
		log_command $? "$cmd"

		cmd="mkdir /usr/local/nginx/conf/ssl "
		$cmd
		log_command $? "$cmd"

		cmd="mkdir /etc/nginx"
		$cmd
		log_command $? "$cmd"

		cmd="ln -s /usr/local/nginx/conf/ssl /etc/nginx/ssl"
		$cmd
		log_command $? "$cmd"

		cmd="cp /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/nginx.bak"
		$cmd
		log_command $? "$cmd"


		sed -i "s/#user  nobody;/user www-data;/" /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -i \"s/#user  nobody;/user www-data;/\" /usr/local/nginx/conf/nginx.conf"

		sed -ie '$s/}/include \/usr\/local\/nginx\/conf\/sites-enabled\/\*;\n}/' /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -ie '$s/}/include \/usr\/local\/nginx\/conf\/sites-enabled\/\*;\n}/'' /usr/local/nginx/conf/nginx.conf"

		cmd="wget https://raw.github.com/JasonGiedymin/nginx-init-ubuntu/master/nginx -O /etc/init.d/nginx"
		$cmd
		log_command $? "$cmd"

		cmd="chmod +x /etc/init.d/nginx"
		$cmd
		log_command $? "$cmd"

		cmd="update-rc.d nginx defaults"
		$cmd
		log_command $? "$cmd"

		cmd="service nginx start"
		$cmd
		log_command $? "$cmd"

		cmd="cd /opt/"
		$cmd
		log_command $? "$cmd"

		cmd="git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git"
		$cmd
		log_command $? "$cmd"

		cmd="cd owasp-modsecurity-crs/"
		$cmd
		log_command $? "$cmd"

		cmd="cp -R rules/ /usr/local/nginx/conf/ "
		$cmd
		log_command $? "$cmd"

		cmd="cp /opt/owasp-modsecurity-crs/crs-setup.conf.example /usr/local/nginx/conf/crs-setup.conf"
		$cmd
		log_command $? "$cmd"

		echo "#Load OWASP Config
	Include crs-setup.conf
	#Load all other Rules
	Include rules/*.conf
	#Disable rule by ID from error message
	#SecRuleRemoveById 920350" >> /usr/local/nginx/conf/modsecurity.conf
		log_command $? "echo '#Load OWASP Config\nInclude crs-setup.conf\n#Load all other Rules\nInclude rules/*.conf\n#Disable rule by ID from error message\n#SecRuleRemoveById 920350' >> /usr/local/nginx/conf/modsecurity.conf"

		sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /usr/local/nginx/conf/modsecurity.conf
		log_command $? "sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /usr/local/nginx/conf/modsecurity.conf"

		cmd="mv /usr/local/nginx/conf/rules/REQUEST-921-PROTOCOL-ATTACK.conf /usr/local/nginx/conf/rules/REQUEST-921-PROTOCOL-ATTACK.conf.example"
		$cmd
		log_command $? "$cmd"

		sed -i 's/#charset koi8-r;/#charset koi8-r;\n\tmodsecurity on;/' /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -i 's/#charset koi8-r;/#charset koi8-r;\n\tmodsecurity on;/' /usr/local/nginx/conf/nginx.conf"

		sed -i '0,/location \/ {/s/location \/ {/location \/ {\n\tmodsecurity_rules_file \/usr\/local\/nginx\/conf\/modsecurity.conf;/' /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -i '0,/location \/ {/s/location \/ {/location \/ {\n\tmodsecurity_rules_file \/usr\/local\/nginx\/conf\/modsecurity.conf;/' /usr/local/nginx/conf/nginx.conf"

		cmd="service nginx reload"
		$cmd
		log_command $? "$cmd"
	fi

	if [[ "$1" == *"CentOS 6"* ]]; then

		sed -i "s/#user  nobody;/user nginx nginx;/" /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -i \"s/#user  nobody;/user nginx nginx;/\" /usr/local/nginx/conf/nginx.conf"

		cmd="cp /opt/ModSecurity/modsecurity.conf-recommended /usr/local/nginx/conf/modsecurity.conf"
		$cmd
		log_command $? "$cmd"

		cmd="cp /opt/ModSecurity/unicode.mapping /usr/local/nginx/conf/"
		$cmd
		log_command $? "$cmd"

		sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /usr/local/nginx/conf/modsecurity.conf
		log_command $? "sed -i \"s/SecRuleEngine DetectionOnly/SecRuleEngine On/\" /usr/local/nginx/conf/modsecurity.conf"

		echo "include modsecurity.conf
		include owasp-modsecurity-crs/crs-setup.conf
		include owasp-modsecurity-crs/rules/*.conf" > /usr/local/nginx/conf/modsec_includes.conf
		log_command $? "echo \"include modsecurity.conf\ninclude owasp-modsecurity-crs/crs-setup.conf\ninclude owasp-modsecurity-crs/rules/*.conf\" > /usr/local/nginx/conf/modsec_includes.conf"


		sed -i '0,/location \/ {/s/location \/ {/location \/ {\n\t    ModSecurityEnabled on;\n\t    ModSecurityConfig modsec_includes.conf;/' /usr/local/nginx/conf/nginx.conf

		log_command $? "sed -i '0,/location \/ {/s/location \/ {/location \/ {\n\t    ModSecurityEnabled on;\n\t    ModSecurityConfig modsec_includes.conf;/' /usr/local/nginx/conf/nginx.conf"

		cmd="cd /usr/local/nginx/conf"
		$cmd
		log_command $? "$cmd"

		cmd="git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git"
		$cmd
		log_command $? "$cmd"

		cmd="cd owasp-modsecurity-crs"
		$cmd
		log_command $? "$cmd"

		cmd="mv crs-setup.conf.example crs-setup.conf"
		$cmd
		log_command $? "$cmd"

		cmd="cd rules"
		$cmd
		log_command $? "$cmd"

		cmd="mv REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
		$cmd
		log_command $? "$cmd"

		cmd="mv RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
		$cmd
		log_command $? "$cmd"

		cmd="/usr/local/nginx/sbin/nginx -t -c /usr/local/nginx/conf/nginx.conf"
		$cmd
		log_command $? "$cmd"

		cmd="/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf"
		$cmd
		log_command $? "$cmd"
	fi

	if [[ "$1" == *"CentOS 7"* ]]; then

		cmd="cp /opt/ModSecurity/modsecurity.conf-recommended /usr/local/nginx/conf/modsecurity.conf"
		$cmd
		log_command $? "$cmd"

		cmd="ln -s /usr/local/nginx/sbin/nginx /bin/nginx"
		$cmd
		log_command $? "$cmd"

		cmd="mkdir /usr/local/nginx/conf/sites-available "
		$cmd
		log_command $? "$cmd"

		cmd="mkdir /usr/local/nginx/conf/sites-enabled"
		$cmd
		log_command $? "$cmd"

		cmd="mkdir /usr/local/nginx/conf/ssl "
		$cmd
		log_command $? "$cmd"

		cmd="mkdir /etc/nginx"
		$cmd
		log_command $? "$cmd"

		cmd="ln -s /usr/local/nginx/conf/ssl /etc/nginx/ssl"
		$cmd
		log_command $? "$cmd"

		cmd="cp /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/nginx.bak"
		$cmd
		log_command $? "$cmd"


		cmd="groupadd -r www-data"
		$cmd
		log_command $? "$cmd"

		cmd="useradd -r -g www-data -s /sbin/nologin -M www-data"
		$cmd
		log_command $? "$cmd"


		sed -i "s/#user  nobody;/user www-data;/" /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -i \"s/#user  nobody;/user www-data;/\" /usr/local/nginx/conf/nginx.conf"

		sed -ie '$s/}/include \/usr\/local\/nginx\/conf\/sites-enabled\/\*;\n}/' /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -ie '$s/}/include \/usr\/local\/nginx\/conf\/sites-enabled\/\*;\n}/'' /usr/local/nginx/conf/nginx.conf"

		echo "[Service]
		Type=forking
		ExecStartPre=/usr/local/nginx/sbin/nginx -t -c /usr/local/nginx/conf/nginx.conf
		ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
		ExecReload=/usr/local/nginx/sbin/nginx -s reload
		KillStop=/usr/local/nginx/sbin/nginx -s stop
		KillMode=process
		Restart=on-failure
		RestartSec=42s
		PrivateTmp=true
		LimitNOFILE=200000
		[Install]
		WantedBy=multi-user.target" > /lib/systemd/system/nginx.service
		log_command $? "echo \"[Service]\nType=forking\nExecStartPre=/usr/local/nginx/sbin/nginx -t -c /usr/local/nginx/conf/nginx.conf\nExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf\nExecReload=/usr/local/nginx/sbin/nginx -s reload\nKillStop=/usr/local/nginx/sbin/nginx -s stop\nKillMode=process\nRestart=on-failure\nRestartSec=42s\nPrivateTmp=true\nLimitNOFILE=200000\n[Install]\nWantedBy=multi-user.target\" > /lib/systemd/system/nginx.service"

		cmd="systemctl start nginx.service"
		$cmd
		log_command $? "$cmd"


		cmd="cd /opt/"
		$cmd
		log_command $? "$cmd"

		cmd="git clone https://github.com/SpiderLabs/owasp-modsecurity-crs.git"
		$cmd
		log_command $? "$cmd"

		cmd="cd owasp-modsecurity-crs/"
		$cmd
		log_command $? "$cmd"

		cmd="cp -R rules/ /usr/local/nginx/conf/ "
		$cmd
		log_command $? "$cmd"

		cmd="cp /opt/owasp-modsecurity-crs/crs-setup.conf.example /usr/local/nginx/conf/crs-setup.conf"
		$cmd
		log_command $? "$cmd"

		echo "#Load OWASP Config
	Include crs-setup.conf
	#Load all other Rules
	Include rules/*.conf
	#Disable rule by ID from error message
	#SecRuleRemoveById 920350" >> /usr/local/nginx/conf/modsecurity.conf
		log_command $? "echo '#Load OWASP Config\nInclude crs-setup.conf\n#Load all other Rules\nInclude rules/*.conf\n#Disable rule by ID from error message\n#SecRuleRemoveById 920350' >> /usr/local/nginx/conf/modsecurity.conf"

		sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /usr/local/nginx/conf/modsecurity.conf
		log_command $? "sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /usr/local/nginx/conf/modsecurity.conf"

		cmd="mv /usr/local/nginx/conf/rules/REQUEST-921-PROTOCOL-ATTACK.conf /usr/local/nginx/conf/rules/REQUEST-921-PROTOCOL-ATTACK.conf.example"
		$cmd
		log_command $? "$cmd"

		cmd="mv /usr/local/nginx/conf/rules/REQUEST-910-IP-REPUTATION.conf /usr/local/nginx/conf/rules/REQUEST-910-IP-REPUTATION.conf.example"
		$cmd
		log_command $? "$cmd"

		sed -i 's/#charset koi8-r;/#charset koi8-r;\n\tmodsecurity on;/' /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -i 's/#charset koi8-r;/#charset koi8-r;\n\tmodsecurity on;/' /usr/local/nginx/conf/nginx.conf"

		sed -i '0,/location \/ {/s/location \/ {/location \/ {\n\tmodsecurity_rules_file \/usr\/local\/nginx\/conf\/modsecurity.conf;/' /usr/local/nginx/conf/nginx.conf
		log_command $? "sed -i '0,/location \/ {/s/location \/ {/location \/ {\n\tmodsecurity_rules_file \/usr\/local\/nginx\/conf\/modsecurity.conf;/' /usr/local/nginx/conf/nginx.conf"


		cmd="systemctl stop nginx.service"
		$cmd
		log_command $? "$cmd"

		cmd="systemctl start nginx.service"
		$cmd
		log_command $? "$cmd"
	fi
}
###################################################################
#Running functions
check_user
banner_log
distribution=$(check_distribution)
echo $distribution
install_dependencies_nginx "$distribution"
install_modsecurity_nginx "$distribution"
install_nginx "$distribution"
configuring_nginx "$distribution"
