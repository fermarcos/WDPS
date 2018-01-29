#!/bin/bash

#########################################################
###              WDPS PROJECT UNAM-CERT               ###
###    COORDINACION DE SEGURIDAD DE LA INFORMACION    ###
###     Plan de becarios en Seguridad Informatica     ###
###     -----------------------------------------     ###
###           Diana Laura Arrieta Jimenez             ###
###                                                   ###
#########################################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#
####################################################
######      AWStats INSTALLATION              ######
####################################################

#==========================================#
	LOG="`pwd`/../log/AWStats_install.log"	
	USER=`whoami`	
	DISTR="`cat /etc/*release`"
	UNAME="`uname -a`"
	
	LOG_APACHE="/var/log/apache2/"
	LOG_HTTPD="/var/log/httpd"
	SITES_APACHE="/etc/apache2/sites-available"
	SITES_HTTPD="/etc/httpd/conf.d"
	AWSTATS_APACHE_CONF="`pwd`/../templates/site_awstats_apache.conf"
	AWSTATS_HTTPD_CONF="`pwd`/../templates/site_awstats_httpd.conf"

	TEMPLATES="`pwd`/../templates"

	
	LOG_NGINX="/var/log/nginx/"
	SITES_NGINX="/etc/nginx/sites-available"
	SITES_NGINX_CENTOS="/etc/nginx/"
	AWSTATS_NGINX_CONF="`pwd`/../templates/site_awstats_nginx_du"
	AWSTATS_NGINX_CONF_CENTOS="`pwd`/../templates/site_awstats_nginx_ce"
	
#==========================================#


###################################################################
user_install()
{
	if [ $USER != "root" ]; then
		echo ""
		echo ""
		echo "#####################################################"
		echo "# You must be root to exec this installation script #"
		echo "#####################################################"
		echo ""
		echo ""
		echo ""
		echo ""
		exit 1
	fi
}
#####################################################################################################
exit_install()
{
	echo
	echo
	echo "[`date +"%F %X"`] - [AWStats_install | EXIT_INSTALL]   The installation script has been terminated with some errors" >> $LOG
	echo "[`date +"%F %X"`] - [AWStats_install | EXIT_INSTALL]   The installation script has been terminated with some errors"
	echo
	echo
	exit 1
}
#####################################################################################################
exec_install()
{
	if [ $1 -ne 0 ]; then
		echo "[`date +"%F %X"`] - [AWStats_install | EXEC_INSTALL]   ERROR - Installation of $2" >> $LOG
		exit_install
	else
		echo "[`date +"%F %X"`] - [AWStats_install | EXEC_INSTALL]   $2 has been installed OK"  >> $LOG	
	fi
}
#####################################################################################################
exec_cmd()
{
        if [ $1 -ne 0 ]; then
                echo "[`date +"%F %X"`] - [AWStats_install | EXEC_CMD]  ERROR - $2" >> $LOG
                exit_install
        else
                echo "[`date +"%F %X"`] - [AWStats_install | EXEC_CMD]  The command $2 has been executed OK" >> $LOG
        fi
}
#####################################################################################################
install_aws()
{
	apache2 -v 2> /dev/null
	apache=$?
	nginx -v 2> /dev/null
	nginx=$?
	httpd -v 2> /dev/null
	httpd=$?
	which awstats 2> /dev/null
	aws=$?
	
	if [[ "$apache" == 127 && "$nginx" == 127 && "$httpd" == 127 ]]; then
			echo "You don't have install a web server (Apache o Nginx)"
			exit 1
	fi
	if [[ "$aws" == 0 ]]; then
			echo "You have install awstats"
			exit 1
	fi
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [AWStats_install | INSTALL_AWSTATS]   Installing AWStats " >> $LOG
		cmd="apt-get install awstats apache2-utils php -y"
		$cmd
		exec_cmd $? "AWStats $cmd"
	fi
	if [[ "$DISTR" == *"CentOS"* ]]; then
		echo "[`date +"%F %X"`] - [AWStats_install | INSTALL_AWSTATS]   Installing AWStats " >> $LOG

		if [[ "$UNAME" == *"x86_64"* ]]; then
			cmd="cd $TEMPLATES/rpm"
			$cmd
			exec_cmd $? "AWStats $cmd"
			
			cmd="rpm -Uhv rpmforge-release-0.5.3-1.el5.rf.x86_64.rpm"
			$cmd
			exec_cmd $? "AWStats $cmd"
		fi
		
		if [[ "$UNAME" == *"i386"* ]]; then
			cmd="cd $TEMPLATES/rpm"
			$cmd
			exec_cmd $? "AWStats $cmd"
			
			cmd="rpm -Uhv rpmforge-release-0.5.2-2.el5.rf.i386.rpm"
			$cmd
			exec_cmd $? "AWStats $cmd"
		fi
	
		cmd="yum -y install awstats httpd-tools mod_ssl php"
		$cmd
		exec_cmd $? "AWStats $cmd"
	fi
}
#####################################################################################################
configure_aws()
{
	apache2 -v 2> /dev/null
	apache=$?
	nginx -v 2> /dev/null
	nginx=$?
	httpd -v 2> /dev/null
	httpd=$?
		
	if [[ "$nginx" == 0 ]]; then
			configure_aws_nginx 	
			
		elif [[ "$apache" == 0 || "$httpd" == 0 ]]; then
			configure_aws_apache
	fi		
}
#####################################################################################################
configure_aws_apache()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
	
		echo "[`date +"%F %X"`] - [AWStats_install | CONFIGURE_AWSTATS]   Configuring AWStats " >> $LOG
						
		cmd="unzip -d $TEMPLATES/ $TEMPLATES/awstats_dir.zip"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cd $LOG_APACHE"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"		

		
		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
				let count=count+1
				log=`ls -1 *access*log | sed -n $count'p'`
				sitio="${log//_/.}"			
				
				# Copia del archivo de configuracion  awstats.conf
				
				cmd="cp /etc/awstats/awstats.conf /etc/awstats/awstats.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				config_file=/etc/awstats/awstats.$sitio.conf				
				cmd="sed -i s/access.log/$log/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="sed -i s/SiteDomain=\"\"/SiteDomain=\"$sitio\"/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="mkdir -p /var/www/estadisticas/awstats/awstats.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				/usr/lib/cgi-bin/awstats.pl -config=$sitio -update -output > /var/www/estadisticas/awstats/awstats.$sitio/index.html
								
				echo "* * * * * root /usr/lib/cgi-bin/awstats.pl -config=$sitio -update -output > /var/www/estadisticas/awstats/awstats.$sitio/index.html" >> /etc/crontab

				cmd="cd $LOG_APACHE"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
		done
		
		cmd="cp -rf $TEMPLATES/awstats_dir/* /var/www/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cp -rf $TEMPLATES/awstats/* /var/www/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		#----------- Configuracion Apache2 ---------
				
		cmd="cp $AWSTATS_APACHE_CONF $SITES_APACHE/awstats.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
				
		cmd="a2ensite awstats.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
				
		cmd="a2enmod cgi"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="htpasswd -c /etc/apache2/auth_users_awstats $us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		echo "Listen 2292" >> /etc/apache2/ports.conf
		
		cmd="a2enmod ssl"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cp -f $TEMPLATES/estadisticas.* /etc/ssl/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		service apache2 restart
		
	fi
	
	if [[ "$DISTR" == *"CentOS"* ]]; then
	
		echo "[`date +"%F %X"`] - [AWStats_install | CONFIGURE_AWSTATS]   Configuring AWStats " >> $LOG
		
		cmd="unzip -d $TEMPLATES/ $TEMPLATES/awstats_dir.zip"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
	
		cmd="cd $LOG_HTTPD"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"	
		
		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
			let count=count+1
			log=`ls -1 *access*log | sed -n $count'p'`
			sitio="${log//_/.}"	
	
			# Copia del archivo de configuracion  awstats.conf
			
			cmd="cp /etc/awstats/awstats.localhost.localdomain.conf /etc/awstats/awstats.$sitio.conf"
			$cmd
			exec_cmd $? "CONFIGURE APACHE $cmd"

			config_file=/etc/awstats/awstats.$sitio.conf				
			cmd="sed -i s/httpd\/access_log/httpd\/$log/g $config_file"
			$cmd
			exec_cmd $? "CONFIGURE APACHE $cmd"
			
			cmd="sed -i s/SiteDomain=\"\"/SiteDomain=\"$sitio\"/g $config_file"
			$cmd
			exec_cmd $? "CONFIGURE APACHE $cmd"
			
			cmd="mkdir -p /var/www/estadisticas/awstats/awstats.$sitio"
			$cmd
			exec_cmd $? "CONFIGURE APACHE $cmd"

			/var/www/awstats/awstats.pl -config=$sitio -update -output > /var/www/estadisticas/awstats/awstats.$sitio/index.html

			echo "* * * * * root /var/www/awstats/awstats.pl -config=$sitio -update -output > /var/www/estadisticas/awstats/awstats.$sitio/index.html" >> /etc/crontab
			
			cmd="cd $LOG_HTTPD"
			$cmd
			exec_cmd $? "CONFIGURE APACHE $cmd"

		done
		
		cmd="cp -rf $TEMPLATES/awstats_dir/* /var/www/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cp -rf $TEMPLATES/awstats/* /var/www/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="chmod -R 755 /var/www/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		#----------- Configuracion Apache2 ---------
		
		mkdir /etc/httpd/sites-available
		rm -f /etc/httpd/conf.d/awstats.conf
		
		cmd="cp -rf $AWSTATS_HTTPD_CONF /etc/httpd/sites-available/awstats.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"	

		cmd="ln -s /etc/httpd/sites-available/awstats.conf /etc/httpd/conf.d/awstats.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"		
		
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="htpasswd -c /etc/httpd/auth_users_awstats $us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cp -f $TEMPLATES/estadisticas.* /etc/ssl/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		service httpd restart
	
	fi
	
}
#####################################################################################################
configure_aws_nginx()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		
		apt-get install php-fpm php-cli -y
		echo "cgi.fix_pathinfo=0" >> /etc/php/*.*/fpm/php.ini
		sed s/listen/;listen/g >> /etc/php/*.*/fpm/pool.d/www.conf
		echo "listen=127.0.0.1:9000" >> /etc/php/*.*/fpm/pool.d/www.conf
		service php* restart 
		
		mkdir /etc/nginx/sites-available
		
		echo "[`date +"%F %X"`] - [AWStats_install | CONFIGURE_AWSTATS]   Configuring AWStats " >> $LOG
						
		cmd="unzip -d $TEMPLATES/ $TEMPLATES/awstats_dir.zip"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cd $LOG_NGINX"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"		

		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
				let count=count+1
				log=`ls -1 *access*log | sed -n $count'p'`
				sitio="${log//_/.}"
				
				# Copia del archivo de configuracion  awstats.conf
				
				cmd="cp /etc/awstats/awstats.conf /etc/awstats/awstats.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				config_file=/etc/awstats/awstats.$sitio.conf				
				cmd="sed -i s/apache2\/access.log/nginx\/$log/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				cmd="sed -i s/SiteDomain=\"\"/SiteDomain=\"$sitio\"/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				cmd="mkdir -p /usr/share/nginx/estadisticas/awstats/awstats.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				/usr/lib/cgi-bin/awstats.pl -config=$sitio -update -output > /usr/share/nginx/estadisticas/awstats/awstats.$sitio/index.html
					
				echo "* * * * * root /usr/lib/cgi-bin/awstats.pl -config=$sitio -update -output > /usr/share/nginx/estadisticas/awstats/awstats.$sitio/index.html" >> /etc/crontab

				cmd="cd $LOG_NGINX"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	

		done
		
		cmd="cp -rf $TEMPLATES/awstats_dir/* /usr/share/nginx/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		cmd="cp -rf $TEMPLATES/awstats/* /usr/share/nginx/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		#----------- Configuracion Nginx ---------
				
		cmd="cp $AWSTATS_NGINX_CONF $SITES_NGINX/awstats.conf"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
				
		cmd="ln -s $SITES_NGINX/awstats.conf /etc/nginx/conf.d/awstats.conf"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
				
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="htpasswd -c /etc/nginx/auth_users_awstats $us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="cp -f $TEMPLATES/estadisticas.* /etc/ssl/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		service nginx restart
		
	fi
	
	if [[ "$DISTR" == *"CentOS"* ]]; then
		
		yum install php-fpm php-cli
		echo "cgi.fix_pathinfo=0" >> /etc/php.ini
		service php-fpm restart
	
		echo "[`date +"%F %X"`] - [AWStats_install | CONFIGURE_AWSTATS]   Configuring AWStats " >> $LOG
						
		cmd="unzip -d $TEMPLATES/ $TEMPLATES/awstats_dir.zip"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cd $LOG_NGINX"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"		

		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
				let count=count+1
				log=`ls -1 *access*log | sed -n $count'p'`
				sitio="${log//_/.}"
								
				# Copia del archivo de configuracion  awstats.conf
				
				cmd="cp /etc/awstats/awstats.localhost.localdomain.conf /etc/awstats/awstats.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				config_file=/etc/awstats/awstats.$sitio.conf				
				cmd="sed -i s/httpd\/access_log/nginx\/$log/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				cmd="sed -i s/SiteDomain=\"\"/SiteDomain=\"$sitio\"/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				cmd="mkdir -p /var/www/estadisticas/awstats/awstats.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				/var/www/awstats/awstats.pl -config=$sitio -update -output > /var/www/estadisticas/awstats/awstats.$sitio/index.html
					
				echo "* * * * * root /var/www/awstats/awstats.pl -config=$sitio -update -output > /var/www/estadisticas/awstats/awstats.$sitio/index.html" >> /etc/crontab

				cmd="cd $LOG_NGINX"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				
		
		done 
		
		cmd="cp -rf $TEMPLATES/awstats_dir/* /var/www/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		cmd="cp -rf $TEMPLATES/awstats/* /var/www/estadisticas/awstats/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		#----------- Configuracion Nginx ---------
		
		mkdir /etc/nginx/sites-available
		rm -f /etc/nginx/conf.d/awstats.conf
		
		cmd="cp -rf $AWSTATS_NGINX_CONF_CENTOS /etc/nginx/sites-available/awstats.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"	

		cmd="ln -s /etc/nginx/sites-available/awstats.conf /etc/nginx/conf.d/awstats.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"						
				
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="htpasswd -c /etc/nginx/auth_users_awstats $us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="cp -f $TEMPLATES/estadisticas.* /etc/ssl/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		service nginx restart	
	
	fi
}
#####################################################################################################
banner_log()
{
	echo "######################################" >  $LOG
	echo "###     AWStats INSTALLATION      ####" >> $LOG
	echo "######################################" >> $LOG
	echo "______________________________________" >> $LOG
	echo "Started @ [`date`]"                     >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo "######################################" 
	echo "###     AWStats INSTALLATION      ####"
	echo "######################################"
	echo "______________________________________"
	echo "Started @ [`date`]"                    
	echo                                        
	echo                                       
}

#####################################################################################################
end_install()
{
		echo "############################################"
        echo "The installation of AWStats has been completed"
        echo "############################################"
        echo ""
        echo "############################################" >> $LOG
        echo "[`date +"%F %X"`] - [AWStats_install | END_INSTALL]  The installation of AWStats has been completed" >> $LOG
        echo "############################################"  >> $LOG
        echo "" >> $LOG
        echo "" >> $LOG
        echo "For more detail, see LOG file"
        echo ""
        echo "-----------------------------"
        echo "By UNAM-CERT WDPS Project"
        echo "diana.arrieta@cert.unam.mx"
		echo "fernando.parra@cert.unam.mx"
		echo "diana.arrieta@cert.unam.mx" >> $LOG
		echo "fernando.parra@cert.unam.mx" >> $LOG
}
#####################################################################################################
#####################################################################################################

	banner_log
	user_install	
	install_aws
	configure_aws
	end_install
