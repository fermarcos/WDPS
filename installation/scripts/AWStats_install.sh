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
	DIRECTORIO="`pwd`/src"
	LOG="`pwd`/../log/AWStats_install.log"	
	USER=`whoami`	
	DISTR="`cat /etc/*release`"
	UNAME="`uname -a`"
	
	LOG_APACHE="/var/log/apache2/"
	SITES_APACHE="/etc/apache2/sites-available"
	AWSTATS_APACHE_CONF="`pwd`/../templates/site_awstats_apache.conf"
	TEMPLATES="`pwd`/../templates"
	AWSTATS_URL="`pwd`/../awstats_url"
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
	dpkg --get-selections | grep -w apache2 | grep -w install
	apache=$?
	dpkg --get-selections | grep -w nginx | grep -w install
	nginx=$?
	
	if [[ "$apache" == 256 || "$nginx" == 256 ]]; then
			print "You don't have install a web server (Apache o Nginx)"
			exit 1
	fi
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [AWStats_install | INSTALL_AWSTATS]   Installing AWStats " >> $LOG
		cmd="apt-get install awstats apache2-utils -y"
		$cmd
		exec_cmd $? "AWStats $cmd"
	fi
	#if [[ "$DISTR" == *"CentOS"* ]]; then
	#	echo " ----  Install awstats ----"
	#	echo " ----  Install awstats ----" >> $LOG
	#	if [[ "$UNAME"=*"x86_64"* ]]; then
	#		cd `pwd`/../rpm
	#		rpm -Uhv rpmforge-release-0.5.3-1.el5.rf.x86_64.rpm
	#		yum -y install awstats httpd-tools
	#	fi
	#fi
}
#####################################################################################################
configure_aws()
{
	dpkg --get-selections | grep -w apache2 | grep -w install
	apache=$?
	dpkg --get-selections | grep -w nginx | grep -w install
	nginx=$?
	#httpd=
		
	if [[ "$apache" == 0 ]]; then
			configure_aws_apache
	fi
	if [[ "$nginx" == 0 ]]; then
			configure_aws_nginx
	fi
}
#####################################################################################################
configure_aws_apache()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [AWStats_install | INSTALL_AWSTATS]   Configuring AWStats " >> $LOG
		echo "Sitio 	URL" >> $AWSTATS_URL
		echo " "			 >> $AWSTATS_URL	
						
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
				sitio=`ls -1 *access*log | sed -n $count'p'`
				#log=`ls -1 *access*log | sed -n $count'p'`
				#sitio=`ls -1 *access*log | sed -n $count'p' | cut -d "." -f1`
					

				
				# Copia del archivo de configuracion  awstats.conf
				
				cmd="cp /etc/awstats/awstats.conf /etc/awstats/awstats.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				config_file=/etc/awstats/awstats.$sitio.conf				
				cmd="sed -i s/access.log/$sitio/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="sed -i s/SiteDomain=\"\"/SiteDomain=\"$sitio\"/g $config_file"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="mkdir -p /var/www/estadisticas/awstats/awstats.$sitio"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				/usr/lib/cgi-bin/awstats.pl -config=$sitio -update -output > /var/www/estadisticas/awstats/awstats.$sitio/awstats.$sitio.html
				
				cmd="cp -r $TEMPLATES/awstats_dir/* /var/www/estadisticas/awstats/awstats.$sitio/"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				#----------- Configuracion Apache2 ---------
				
				cmd="cp $AWSTATS_APACHE_CONF $SITES_APACHE/awstats.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="sed -i s/SITIO/$sitio/g $SITES_APACHE/awstats.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				cmd="a2ensite awstats.$sitio.conf"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"
				
				echo "awstats.$sitio.com"
				
				echo "* * * * * root /usr/lib/cgi-bin/awstats.pl -config=$sitio -update -output > /var/www/estadisticas/awstats/awstats.$sitio/awstats.$sitio.html" >> /etc/crontab
				
				echo "127.0.0.1 awstats.$sitio.com" >> /etc/hosts
				
				echo "$sitio -> awstats.$sitio.com:2292" >> $AWSTATS_URL 
				
				cmd="cd $LOG_APACHE"
				$cmd
				exec_cmd $? "CONFIGURE APACHE $cmd"	
				
		done
		
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
		
		service apache2 restart
		
	fi
}
#####################################################################################################
configure_aws_nginx()
{
		echo "hola"
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