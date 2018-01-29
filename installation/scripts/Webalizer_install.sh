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
######      WEBALIZER INSTALLATION            ######
####################################################

#==========================================#
	LOG="`pwd`/../log/Webalizer_install.log"	
	USER=`whoami`	
	DISTR="`cat /etc/*release`"
	UNAME="`uname -a`"
	
	LOG_APACHE="/var/log/apache2/"
	LOG_HTTPD="/var/log/httpd"
	SITES_APACHE="/etc/apache2/sites-available"
	SITES_HTTPD="/etc/httpd/sites-available"
	WEBALIZER_APACHE_CONF="`pwd`/../templates/site_webalizer_apache.conf"
	WEBALIZER_HTTPD_CONF="`pwd`/../templates/site_webalizer_httpd.conf"

	TEMPLATES="`pwd`/../templates"
	
	LOG_NGINX="/var/log/nginx/"
	SITES_NGINX="/etc/nginx/sites-available"
	WEBALIZER_NGINX_CONF="`pwd`/../templates/site_webalizer_nginx_du"
	WEBALIZER_NGINX_CONF_CENTOS="`pwd`/../templates/site_webalizer_nginx_ce"
	
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
	echo "[`date +"%F %X"`] - [Webalizer_install | EXIT_INSTALL]   The installation script has been terminated with some errors" >> $LOG
	echo "[`date +"%F %X"`] - [Webalizer_install | EXIT_INSTALL]   The installation script has been terminated with some errors"
	echo
	echo
	exit 1
}
#####################################################################################################
exec_install()
{
	if [ $1 -ne 0 ]; then
		echo "[`date +"%F %X"`] - [Webalizer_install | EXEC_INSTALL]   ERROR - Installation of $2" >> $LOG
		exit_install
	else
		echo "[`date +"%F %X"`] - [Webalizer_install | EXEC_INSTALL]   $2 has been installed OK"  >> $LOG	
	fi
}
#####################################################################################################
exec_cmd()
{
        if [ $1 -ne 0 ]; then
                echo "[`date +"%F %X"`] - [Webalizer_install | EXEC_CMD]  ERROR - $2" >> $LOG
                exit_install
        else
                echo "[`date +"%F %X"`] - [Webalizer_install | EXEC_CMD]  The command $2 has been executed OK" >> $LOG
        fi
}
#####################################################################################################
install_web()
{
	apache2 -v 2> /dev/null
	apache=$?
	nginx -v 2> /dev/null
	nginx=$?
	httpd -v 2> /dev/null
	httpd=$?
	which webalizer 2> /dev/null
	web=$?
	
	if [[ "$apache" == 127 && "$nginx" == 127  && "$httpd" == 127 ]]; then
			echo "You don't have install a web server (Apache o Nginx)"
			exit 1
	fi
	if [[ "$web" == 0 ]]; then
			echo "You have install webalizer"
			exit 1
	fi
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [Webalizer_install | INSTALL_WEBALIZER]   Installing Webalizer " >> $LOG
		cmd="apt-get install webalizer apache2-utils -y"
		$cmd
		exec_cmd $? "Webalizer $cmd"
	fi
	if [[ "$DISTR" == *"CentOS"* ]]; then
		echo "[`date +"%F %X"`] - [Webalizer_install | INSTALL_WEBALIZER]   Installing Webalizer " >> $LOG
		cmd="yum -y install webalizer httpd-tools mod_ssl"
		$cmd
		exec_cmd $? "Webalizer $cmd"
	fi
}
#####################################################################################################
configure_web()
{
	apache2 -v 2> /dev/null
	apache=$?
	nginx -v 2> /dev/null
	nginx=$?
	httpd -v 2> /dev/null
	httpd=$?
		
	if [[ "$nginx" == 0 ]]; then
			configure_web_nginx 	
			
		elif [[ "$apache" == 0 || "$httpd" == 0 ]]; then
			configure_web_apache
	fi
}
#####################################################################################################
configure_web_apache()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [Webalizer_install | CONFIGURE_Webalizer]   Configuring Webalizer " >> $LOG
		
		cmd="cd $LOG_APACHE"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"		

		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
				let count=count+1
				log=`ls -1 *access*log | sed -n $count'p'`
				sitio="${log//_/.}"

				# Copia del archivo de configuracion  webalizer.conf
				
				cmd="cp /etc/webalizer/webalizer.conf /etc/webalizer/webalizer.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				config_file=/etc/webalizer/webalizer.$sitio.conf				
				cmd="sed -i s/access.log.1/$log/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="sed -i s/\/var\/www\/webalizer/\/var\/www\/estadisticas\/webalizer\/webalizer.$sitio/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="mkdir -p /var/www/estadisticas/webalizer/webalizer.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				webalizer -c /etc/webalizer/webalizer.$sitio.conf -d
				
				echo "* * * * * root webalizer -c /etc/webalizer/webalizer.$sitio.conf -d" >> /etc/crontab

				cmd="cd $LOG_APACHE"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"					
				
		done
		
		#----------- Configuracion Apache2 ---------
				
		cmd="cp $WEBALIZER_APACHE_CONF $SITES_APACHE/webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
				
		cmd="sed -i s/SITIO/$sitio/g $SITES_APACHE/webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
				
		cmd="a2ensite webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
				
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="htpasswd -c /etc/apache2/auth_users_webalizer $us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		echo "Listen 2293" >> /etc/apache2/ports.conf
		
		cmd="a2enmod ssl"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cp -f $TEMPLATES/estadisticas.* /etc/ssl/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cp -rf $TEMPLATES/webalizer/* /var/www/estadisticas/webalizer/"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		service apache2 restart
		
	fi
	
	if [[ "$DISTR" == *"CentOS"* ]]; then
	
		echo "[`date +"%F %X"`] - [Webalizer_install | CONFIGURE_Webalizer]   Configuring Webalizer " >> $LOG
		
		cmd="cd $LOG_HTTPD"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"		

		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
				let count=count+1
				log=`ls -1 *access*log | sed -n $count'p'`
				sitio="${log//_/.}"

				# Copia del archivo de configuracion  webalizer.conf
				
				cmd="cp /etc/webalizer.conf /etc/webalizer.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				config_file=/etc/webalizer.$sitio.conf				
				cmd="sed -i s/access.log/$log/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="sed -i s/\/var\/www\/usage/\/var\/www\/estadisticas\/webalizer\/webalizer.$sitio/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="mkdir -p /var/www/estadisticas/webalizer/webalizer.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				webalizer -c /etc/webalizer.$sitio.conf -d
				
				echo "* * * * * root webalizer -c /etc/webalizer/webalizer.$sitio.conf -d" >> /etc/crontab

				cmd="cd $LOG_HTTPD"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"					
				
		done
		
		#----------- Configuracion Apache2 ---------
		
		mkdir /etc/httpd/sites-available
		rm -f /etc/httpd/conf.d/webalizer.conf
				
		cmd="cp $WEBALIZER_HTTPD_CONF /etc/httpd/sites-available/webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
			
		cmd="ln -s /etc/httpd/sites-available/webalizer.conf /etc/httpd/conf.d/webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
				
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="htpasswd -c /etc/httpd/auth_users_webalizer $us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="cp -rf $TEMPLATES/webalizer/* /var/www/estadisticas/webalizer/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		
		#echo "Listen 2293" >> /etc/apache2/ports.conf
		
		service httpd restart
	fi
}
#####################################################################################################
configure_web_nginx()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
	
		echo "[`date +"%F %X"`] - [Webalizer_install | CONFIGURE_WEBALIZER]   Configuring Webalizer " >> $LOG
		
		cmd="cd $LOG_NGINX"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"		

		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
			let count=count+1
			log=`ls -1 *access*log | sed -n $count'p'`
			sitio="${log//_/.}"
			
			# Copia del archivo de configuracion  Webalizer.conf
			
			cmd="cp /etc/webalizer/webalizer.conf /etc/webalizer/webalizer.$sitio.conf"
			$cmd
			exec_cmd $? "CONFIGURE NGINX $cmd"	
			
			config_file=/etc/webalizer/webalizer.$sitio.conf				
			cmd="sed -i s/apache2\/access.log.1/nginx\/$log/g $config_file"
			$cmd
			exec_cmd $? "CONFIGURE NGINX $cmd"	

			cmd="sed -i s/\/var\/www\/webalizer/\/usr\/share\/nginx\/estadisticas\/webalizer\/webalizer.$sitio/g $config_file"
			$cmd
			exec_cmd $? "CONFIGURE APACHE $cmd"				
			
			cmd="mkdir -p /usr/share/nginx/estadisticas/webalizer/webalizer.$sitio"
			$cmd
			exec_cmd $? "CONFIGURE NGINX $cmd"	
			
			webalizer -c /etc/webalizer/webalizer.$sitio.conf -d	

			echo "* * * * * root webalizer -c /etc/webalizer/webalizer.$sitio.conf -d " >> /etc/crontab
			
			cmd="cd $LOG_NGINX"
			$cmd
			exec_cmd $? "CONFIGURE NGINX $cmd"	
			
		done
		
		#----------- Configuracion Nginx ---------
			
		cmd="cp $WEBALIZER_NGINX_CONF $SITES_NGINX/webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
			
		cmd="ln -s $SITES_NGINX/webalizer.conf /etc/nginx/conf.d/webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
			
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="htpasswd -c /etc/nginx/auth_users_webalizer $us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="cp -f $TEMPLATES/estadisticas.* /etc/ssl/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		cmd="cp -rf $TEMPLATES/webalizer/* /usr/share/nginx/estadisticas/webalizer/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		service nginx restart
		
	fi
	
	if [[ "$DISTR" == *"CentOS"* ]]; then
	
		echo "[`date +"%F %X"`] - [Webalizer_install | CONFIGURE_WEBALIZER]   Configuring Webalizer " >> $LOG
		
		cmd="cd $LOG_NGINX"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"		

		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
			let count=count+1
			log=`ls -1 *access*log | sed -n $count'p'`
			sitio="${log//_/.}"
			
			# Copia del archivo de configuracion  Webalizer.conf
			
			cmd="cp /etc/webalizer.conf /etc/webalizer.$sitio.conf"
			$cmd
			exec_cmd $? "CONFIGURE NGINX $cmd"	
			
			config_file=/etc/webalizer.$sitio.conf				
			cmd="sed -i s/httpd\/access.log/nginx\/$log/g $config_file"
			$cmd
			exec_cmd $? "CONFIGURE NGINX $cmd"	

			cmd="sed -i s/\/var\/www\/usage/\/var\/www\/estadisticas\/webalizer\/webalizer.$sitio/g $config_file"
			$cmd
			exec_cmd $? "CONFIGURE APACHE $cmd"				
			
			cmd="mkdir -p /var/www/estadisticas/webalizer/webalizer.$sitio"
			$cmd
			exec_cmd $? "CONFIGURE NGINX $cmd"	
			
			webalizer -c /etc/webalizer.$sitio.conf -d	

			echo "* * * * * root webalizer -c /etc/webalizer.$sitio.conf -d " >> /etc/crontab
			
			cmd="cd $LOG_NGINX"
			$cmd
			exec_cmd $? "CONFIGURE NGINX $cmd"	
			
		done
		
		#----------- Configuracion Nginx ---------
		
		mkdir /etc/nginx/sites-available
		rm -f /etc/nginx/conf.d/webalizer.conf
			
		cmd="cp -rf $WEBALIZER_NGINX_CONF_CENTOS /etc/nginx/sites-available/webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
			
		cmd="ln -s /etc/nginx/sites-available/webalizer.conf /etc/nginx/conf.d/webalizer.conf"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
			
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="htpasswd -c /etc/nginx/auth_users_webalizer $us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="cp -f $TEMPLATES/estadisticas.* /etc/ssl/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		cmd="cp -rf $TEMPLATES/webalizer/* /var/www/estadisticas/webalizer/"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"
		
		service nginx restart
	
	fi
}
#####################################################################################################
banner_log()
{
	echo "######################################" >  $LOG
	echo "###     WEBALIZER INSTALLATION    ####" >> $LOG
	echo "######################################" >> $LOG
	echo "______________________________________" >> $LOG
	echo "Started @ [`date`]"                     >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo "######################################" 
	echo "###     WEBALIZER INSTALLATION    ####"
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
        echo "The installation of Webalizer has been completed"
        echo "############################################"
        echo ""
        echo "############################################" >> $LOG
        echo "[`date +"%F %X"`] - [Webalizer_install | END_INSTALL]  The installation of Webalizer has been completed" >> $LOG
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
	install_web
	configure_web
	end_install
