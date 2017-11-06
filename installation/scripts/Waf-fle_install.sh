#!/bin/bash

####################################################################
# Bash script to install waf-fle. For Debian, Ubuntu and CentOS systems.
# Written by Fernando Marcos Parra Arroyo
#	     Diana Laura Arrieta Jimenez
# Requirements:
#	Internet Connection
#	User Root
####################################################################

#COLORS
# Reset
Color_Off='\033[0m'       # Text Reset

# Regular Colors
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan


#Detecting Operative System
DISTR=`grep -E "^ID=" /etc/*release | cut -d "=" -f2 |sed -r 's/"//g'`
VERSION=`grep -E "^VERSION_ID=" /etc/*release | cut -d "=" -f2 |sed -r 's/"//g'`
EXCEPT=`grep -i centos /etc/issue`


#Checking root permissions
echo -e "$Cyan \nChecking root permissions.. $Color_Off"
if [ "$(id -u)" != "0" ]; then
   echo -e  "$Red ERROR This script must be run as root $Color_Off" 1>&2
   exit 1
fi

#Detecting Operative System
function repositories
{
	echo -e "$Cyan \nDetecting System.. $Color_Off"
	if [[ "$EXCEPT" == *"CentOS"*"6"* ]]; then
	        echo "CentOS 6"
	        rpm -Uvh --force https://epel.mirror.constant.com/6/i386/epel-release-6-8.noarch.rpm
	fi
	if [[ "$DISTR" == "centos" && "$VERSION" == "7"* ]]; then
	        echo "CentOS 7"
	        rpm -Uvh --force https://epel.mirror.constant.com/6/i386/epel-release-6-8.noarch.rpm
	fi
	if [[ "$DISTR" == "debian" && "$VERSION" == "8"* ]]; then
	        echo "Debian 8"
	        apt-get update
	fi
	if [[ "$DISTR" == "debian" && "$VERSION" == "9"* ]]; then
	        echo "Debian 9"
			apt-get update
	fi
	if [[ "$DISTR" == "ubuntu" && "$VERSION" == "16"* ]]; then
	        echo "Ubuntu 16"
	        echo "deb http://us.archive.ubuntu.com/ubuntu yakkety main universe" >> /etc/apt/sources.list
	        apt-get update
	fi
	if [[ "$DISTR" == "ubuntu" && "$VERSION" == "14"* ]]; then
	        echo "Ubuntu 14"
	        apt-get update
	fi
}

function dependencies
{
	echo -e "$Cyan \nDetecting System.. $Color_Off"
	if [[ "$EXCEPT" == *"CentOS"*"6"* ]]; then
		yum install php  mysql-server php-mysql php-pecl-apc php-pecl-geoip perl-libwww-perl perl-File-Pid perl-File-Tail mod_ssl  -y
		/etc/init.d/mysqld start	
		mysql_secure_installation        
	fi
	if [[ "$DISTR" == "centos" && "$VERSION" == "7"* ]]; then


		yum install php mariadb-server php-mysql mod_ssl perl-CPAN perl-libwww-perl -y
		
		yum install GeoIP GeoIP-devel -y
		yum install php-pear php-devel httpd-devel pcre-devel gcc make -y
		pecl install geoip
		echo "extension=geoip.so"  >> /etc/php.ini

		pecl install apc
		echo "extension=apc.so" >> /etc/php.ini
		systemctl restart httpd
	 	cpan File::Pid
	 	cpan File::Tail
	 	cpan LWP::UserAgent
	 	systemctl start mariadb
	 	mysql_secure_installation

	fi
	if [[ "$DISTR" == "debian" && "$VERSION" == "8"* ]]; then
		apt-get install mysql-server php5 php5-geoip php-apc php5-mysql libfile-pid-perl libfile-tail-perl libwww-perl -y
	fi
	if [[ "$DISTR" == "debian" && "$VERSION" == "9"* ]]; then
		apt-get install mysql-server php php-mysql php-geoip php-apcu php-apcu-bc libfile-pid-perl libfile-tail-perl libwww-perl -y 
		mysql_secure_installation
	fi
	if [[ "$DISTR" == "ubuntu" && "$VERSION" == "16"* ]]; then

		apt-get install mysql-server php php-mysql php-geoip  php-apcu-bc libfile-pid-perl libfile-tail-perl libwww-perl -y
	fi
	if [[ "$DISTR" == "ubuntu" && "$VERSION" == "14"* ]]; then
		apt-get install mysql-server php5 php5-geoip php-apc php5-mysql libfile-pid-perl libfile-tail-perl libwww-perl -y
	fi

	cd /usr/share/GeoIP/
	wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
	wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
	wget http://geolite.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz

	rm GeoIP.dat
	gzip -d GeoIP.dat.gz
	gzip -d GeoLiteCity.dat.gz
 	gzip -d GeoIPASNum.dat.gz
 	mv GeoLiteCity.dat GeoIPCity.dat  
	cp GeoIPASNum.dat GeoIPISP.dat
}

function installing
{
	#Installing waffle
	echo -e "$Cyan \nInstalling Waffle $Color_Off"
	cd /usr/local/
	wget http://waf-fle.org/downloads/waf-fle_0.6.4.tar.gz
	tar xzvf waf-fle_0.6.4.tar.gz
	ln -s waf-fle_0.6.4 waf-fle


	#Creating Database
	echo -e "$Cyan \nCreating data base $Color_Off"
	PASSWDDB="hola123,"
	USER="waffleuser"
	MAINDB="waffledb"

	echo "Please enter root user MySQL password!"
	read rootpasswd
	mysql -uroot -p${rootpasswd} -e "CREATE DATABASE ${MAINDB} ;"
	mysql -uroot -p${rootpasswd} -e "CREATE USER ${USER}@localhost IDENTIFIED BY '${PASSWDDB}';"
	mysql -uroot -p${rootpasswd} -e "GRANT ALL PRIVILEGES ON ${MAINDB}.* TO '${USER}'@'localhost';"
	mysql -uroot -p${rootpasswd} -e "FLUSH PRIVILEGES;"
	cd /usr/local/waf-fle
	mysql -uroot -p${rootpasswd} waffledb < extra/waffle.mysql 

	#Configuring waffle
	cd /usr/local/waf-fle/
	cp config.php.example config.php

	sed -i  "s/$DB_USER  = \"waffle_user\";/$DB_USER  = \"${USER}\";/g" /usr/local/waf-fle/config.php
	sed -i  "s/$DB_PASS  = \"<FILL_User_Password>\";/$DB_PASS  = \"${PASSWDDB}\";/g" /usr/local/waf-fle/config.php
	sed -i  "s/$DATABASE = \"waffle\";/$DATABASE = \"${MAINDB}\";/g" /usr/local/waf-fle/config.php 

	sed -i  "s/$SETUP = true;/$SETUP = false;/g" /usr/local/waf-fle/config.php


	if [[ "$EXCEPT" == *"CentOS"*"6"* || "$DISTR" == "centos" ]]; then
		mkdir /etc/httpd/conf-available
		mkdir /etc/httpd/conf-enabled

		#Configuring Apache
		cp /usr/local/waf-fle/extra/waf-fle.conf /etc/httpd/conf-available/
		ln -s /etc/httpd/conf-available/waf-fle.conf /etc/httpd/conf-enabled/
		echo "Include /etc/httpd/conf-enabled/*.conf" >> /etc/httpd/conf/httpd.conf



		echo -e "$Cyan \nDetecting Apache Version $Color_Off"
		httpd -v | grep version | cut -d" " -f3 
		V1=`httpd -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f1`
		V2=`httpd -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f2`
		V3=`httpd -v | grep version | cut -d" " -f3 | cut -d"/" -f2 | cut -d"." -f3`

		if [[ "$V1" -lt "2" || "$V2" -lt "4" ]]; then
			sed -i "s/#Order allow,deny/Order allow,deny/g" /etc/httpd/conf-available/waf-fle.conf 
			sed -i "s/#Allow from all/Allow from all/g" /etc/httpd/conf-available/waf-fle.conf 
			echo "<VirtualHost *:443>
			        DocumentRoot "/usr/local/waf-fle"
			        ErrorLog /var/log/httpd/error_log
			        TransferLog /var/log/httpd/access_log
			        SSLProtocol -All +TLSv1 +TLSv1.1 +TLSv1.2
			        LogLevel warn
			        SSLEngine on
			        SSLCertificateFile /etc/pki/tls/certs/localhost.crt
			        SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
			</VirtualHost>" >> /etc/httpd/conf-available/waf-fle.conf
			service httpd restart
		else
			sed -i "s/#Require all granted/Require all granted/g" /etc/httpd/conf-available/waf-fle.conf 
			service httpd restart
		fi


	fi

	if [[ "$DISTR" == "debian" || "$DISTR" == "ubuntu" ]]; then
		#Configuring Apache
		cp /usr/local/waf-fle/extra/waf-fle.conf /etc/apache2/conf-available/
		ln -s /etc/apache2/conf-available/waf-fle.conf /etc/apache2/conf-enabled/
		sed -i "s/#Require all granted/Require all granted/g" /etc/apache2/conf-available/waf-fle.conf
		echo  "<VirtualHost *:443>
		        DocumentRoot /usr/local/waf-fle
		        ErrorLog ${APACHE_LOG_DIR}/error.log
		        CustomLog ${APACHE_LOG_DIR}/access.log combined
		        SSLEngine on
		        SSLCertificateFile      /etc/ssl/certs/ssl-cert-snakeoil.pem
		        SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
		</VirtualHost>" >> /etc/apache2/conf-enabled/waf-fle.conf
		a2enmod ssl rewrite
		/etc/init.d/apache2 restart
	fi
}

function mlog2waffle
{
 	cd /usr/local/waf-fle/extra/mlog2waffle
 	cp mlog2waffle /usr/sbin
 	cp mlog2waffle.conf /etc
 	cp mlog2waffle.cron /etc/cron.d/mlog2waffle


	mkdir -p /var/log/mlog2waffle/data
	chown -R nobody /var/log/mlog2waffle/data
 	chmod 777 /var/log/mlog2waffle/data/

	sed -i "s/$CONSOLE_USERNAME = \"teste\";/$CONSOLE_USERNAME = \"prueba\";/g" /etc/mlog2waffle.conf 
	sed -i "s/$CONSOLE_PASSWORD = \"teste\";/CONSOLE_PASSWORD = \"prueba\";/g" /etc/mlog2waffle.conf
	sed -i "s@$INDEX_FILE = \"\/var\/log\/mlog2waffle\/mlog2waffle-index\";@$INDEX_FILE = \"\/var/log\/mlog2waffle\/modsec_audit\.log\";@g" /etc/mlog2waffle.conf
	sed -i "s/$MODE = \"tail\";/$MODE = \"batch\";/g" /etc/mlog2waffle.conf


	if [[ "$EXCEPT" == *"CentOS"*"6"* || "$DISTR" == "centos" ]]; then
		sed -i "s/SecAuditLogType Serial/SecAuditLogType Concurrent/g" 	/etc/httpd/conf.d/mod_security.conf
 		sed -i "s/SecAuditLog \/var\/log\/httpd\/modsec_audit\.log/SecAuditLog \/var\/log\/mlog2waffle\/modsec_audit\.log\n\tSecAuditLogStorageDir \/var\/log\/mlog2waffle\/data/g" /etc/httpd/conf.d/mod_security.conf
 		sed -i "s/#SecAuditLogStorageDir \/opt\/modsecurity\/var\/audit\//SecAuditLogStorageDir \/var\/log\/mlog2waffle\/data/g" /etc/httpd/conf.d/mod_security.conf
		service httpd restart
	fi

	if [[ "$DISTR" == "debian" || "$DISTR" == "ubuntu" ]]; then
	 	sed -i "s/SecAuditLogType Serial/SecAuditLogType Concurrent/g" /etc/modsecurity/modsecurity.conf 
	 	sed -i "s/SecAuditLog \/var\/log\/apache2\/modsec_audit\.log/SecAuditLog \/var\/log\/mlog2waffle\/modsec_audit\.log/g" /etc/modsecurity/modsecurity.conf
	 	sed -i "s/#SecAuditLogStorageDir \/opt\/modsecurity\/var\/audit\//SecAuditLogStorageDir \/var\/log\/mlog2waffle\/data/g" /etc/modsecurity/modsecurity.conf
		/etc/init.d/apache2 restart
		/etc/init.d/apache2 restart
	fi

	echo -e "$Cyan \nContinue with the instalation on https://<IP-ADDRESS>/waf-fle/login.php the default user and password is admin... $Color_Off"
}

repositories
dependencies
installing
mlog2waffle
