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
	DIRECTORIO="`pwd`/src"
	LOG="`pwd`/../log/Webalizer_install.log"	
	USER=`whoami`	
	DISTR="`cat /etc/*release`"
	UNAME="`uname -a`"
	
	LOG_APACHE="/var/log/apache2/"
	SITES_APACHE="/etc/apache2/sites-available"
	WEBALIZER_APACHE_CONF="`pwd`/../templates/site_webalizer_apache.conf"
	TEMPLATES="`pwd`/../templates"
	WEBALIZER_URL="`pwd`/../webalizer_url"
	
	LOG_NGINX="/var/log/nginx/"
	SITES_NGINX="/etc/nginx/sites-available"
	WEBALIZER_NGINX_CONF="`pwd`/../templates/site_webalizer_nginx_du"
	
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
	
	if [[ "$apache" == 127 && "$nginx" == 127 ]]; then
			echo "You don't have install a web server (Apache o Nginx)"
			exit 1
	fi
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [Webalizer_install | INSTALL_WEBALIZER]   Installing Webalizer " >> $LOG
		cmd="apt-get install webalizer apache2-utils -y"
		$cmd
		exec_cmd $? "Webalizer $cmd"
	fi
	#if [[ "$DISTR" == *"CentOS"* ]]; then
	#	echo " ----  Install Webalizer ----"
	#	echo " ----  Install Webalizer ----" >> $LOG
	#	if [[ "$UNAME"=*"x86_64"* ]]; then
	#		cd `pwd`/../rpm
	#		rpm -Uhv rpmforge-release-0.5.3-1.el5.rf.x86_64.rpm
	#		yum -y install Webalizer httpd-tools
	#	fi
	#fi
}
#####################################################################################################
configure_web()
{
	apache2 -v 2> /dev/null
	apache=$?
	nginx -v 2> /dev/null
	nginx=$?
	#httpd=
		
	if [[ "$apache" == 0 ]]; then
			configure_web_apache
	fi
	if [[ "$nginx" == 0 ]]; then
			configure_web_nginx
	fi
}
#####################################################################################################
configure_web_apache()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [Webalizer_install | CONFIGURE_Webalizer]   Configuring Webalizer " >> $LOG
		echo "Sitio 	URL" >> $WEBALIZER_URL
		echo " "			 >> $WEBALIZER_URL	
		
		cmd="cd $LOG_APACHE"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"		

		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
				let count=count+1
				sitio=`ls -1 *access*log | sed -n $count'p'`
				
				# Copia del archivo de configuracion  webalizer.conf
				
				cmd="cp /etc/webalizer/webalizer.conf /etc/webalizer/webalizer.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				config_file=/etc/webalizer/webalizer.$sitio.conf				
				cmd="sed -i s/access.log.1/$sitio/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="sed -i s/\/var\/www\/webalizer/\/var\/www\/estadisticas\/webalizer\/webalizer.$sitio/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="mkdir -p /var/www/estadisticas/webalizer/webalizer.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				webalizer -c /etc/webalizer/webalizer.$sitio.conf -d
				
				#----------- Configuracion Apache2 ---------
				
				cmd="cp $WEBALIZER_APACHE_CONF $SITES_APACHE/webalizer.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="sed -i s/SITIO/$sitio/g $SITES_APACHE/webalizer.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="a2ensite webalizer.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				echo "* * * * * root webalizer -c /etc/webalizer/webalizer.$sitio.conf -d" >> /etc/crontab
				
				echo "127.0.0.1 webalizer.$sitio.com" >> /etc/hosts
				
				echo "$sitio -> webalizer.$sitio.com:2293" >> $WEBALIZER_URL 
				
				cmd="cd $LOG_APACHE"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"	
				
		done
		
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		cmd="htpasswd -c /etc/apache2/auth_users_webalizer $us"
		$cmd
		exec_cmd $? "CONFIGURE APACHE $cmd"
		
		echo "Listen 2293" >> /etc/apache2/ports.conf
		
		service apache2 restart
		
	fi
}
#####################################################################################################
configure_web_nginx()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [Webalizer_install | CONFIGURE_WEBALIZER]   Configuring Webalizer " >> $LOG
		echo -e "\nWebalizer for nginx\n\nSitio 	URL\n" >> $WEBALIZER_URL
		
		cmd="cd $LOG_NGINX"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"		

		num_logs=`ls *access*log | wc -l`
		count=0
				
		while  [ $count -lt $num_logs ]; do
				let count=count+1
				sitio=`ls -1 *access*log | sed -n $count'p'`

				
				# Copia del archivo de configuracion  Webalizer.conf
				
				cmd="cp /etc/webalizer/webalizer.conf /etc/webalizer/webalizer.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				config_file=/etc/webalizer/webalizer.$sitio.conf				
				cmd="sed -i s/apache2\/access.log.1/nginx\/$sitio/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	

				cmd="sed -i s/\/var\/www\/webalizer/\/var\/www\/estadisticas\/webalizer\/webalizer.$sitio/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"				
				
				cmd="mkdir -p /var/www/estadisticas/webalizer/webalizer.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				webalizer -c /etc/webalizer/webalizer.$sitio.conf -d
				
				#----------- Configuracion Apache2 ---------
				
				cmd="cp $WEBALIZER_NGINX_CONF $SITES_NGINX/webalizer.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				cmd="sed -i s/SITIO/$sitio/g $SITES_NGINX/webalizer.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				cmd="ln -s $SITES_NGINX/webalizer.$sitio /etc/nginx/sites-enabled/webalizer.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"	
				
				echo "* * * * * root webalizer -c /etc/webalizer/webalizer.$sitio.conf -d " >> /etc/crontab
				
				echo "127.0.0.1 webalizer.$sitio.com" >> /etc/hosts
				
				echo "$sitio -> webalizer.$sitio.com:2293" >> $WEBALIZER_URL 
				
				cmd="cd $LOG_NGINX"
				$cmd
				exec_cmd $? "CONFIGURE NGINX $cmd"		
				
		done
		
		echo "Usuario para acceder a estadisticas: " >> $LOG			
		echo "Usuario para acceder a estadisticas: "
		
		cmd="read us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		cmd="htpasswd -c /etc/nginx/auth_users_webalizer $us"
		$cmd
		exec_cmd $? "CONFIGURE NGINX $cmd"	
		
		service nginx restart
		
	fi
}
#####################################################################################################
banner_log()
{
	echo "######################################" >  $LOG
	echo "###     WEBALIZER INSTALLATION      ####" >> $LOG
	echo "######################################" >> $LOG
	echo "______________________________________" >> $LOG
	echo "Started @ [`date`]"                     >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo "######################################" 
	echo "###     WEBALIZER INSTALLATION      ####"
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