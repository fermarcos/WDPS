#!/bin/bash
LOG="`pwd`/../log/AWStats_install.log"
DISTR="`cat /etc/*release`"
UNAME="`uname -a`"


#Banner that inits log file
banner_log()
{
	echo                                          	>> $LOG
	echo                                          	>> $LOG
	echo "########################################" >> $LOG
	echo "###     Webalizer INSTALLATION      ####" >> $LOG
	echo "########################################" >> $LOG
	echo                                          	>> $LOG
	echo                                          	>> $LOG
	echo
	echo
	echo "########################################"
	echo "###     Webalizer INSTALLATION      ####"
	echo "########################################"
	echo
	echo
}

install_web()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo " ----  Install webalizer ----"
		echo " ----  Install webalizer ----" >> $LOG
		apt-get install webalizer -y
	fi
	if [[ "$DISTR" == *"CentOS"* ]]; then
		echo " ----  Install webalizer ----"
		echo " ----  Install webalizer ----" >> $LOG
		
		yum install webalizer -y httpd-tools
		
		#if [[ "$UNAME"=*"x86_64"* ]]; then
			#cd `pwd`/../rpm
			#rpm -Uhv rpmforge-release-0.5.3-1.el5.rf.x86_64.rpm
			#yum -y install awstats httpd-tools
		#	echo "centos"
		#fi
	fi
	
}

configure_web()
{

	apache2 -v
	apache_v=$?
	nginx -v
	nginx_v=$?
	httpd -v
	httpd_v=$?
	
	if [[ "$nginx_v" == 0 ]]; then
			configure_web_nginx
	fi
	
	if [[ "$apache_v" == 0 || "$httpd_v" == 0 ]]; then
			configure_web_apache
	fi
}

configure_web_nginx()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
	
		echo " ----  Configure webalizer ----"
		echo " ----  Configure webalizer ----" >> $LOG
		
		
		log_sites="/var/log/nginx/"
		cd $log_sites
		
		num_logs=`ls *access*log | wc -l`
		i=0
		
		#Configuration for each access_log
		while  [ $i -lt $num_logs ]; do
				let i=i+1
				log=`ls -1 *access*log | sed -n $i'p'`
				sitio=`ls -1 *access*log | sed -n $i'p' | cut -d "." -f1`
						
				#----------- Configuracion Webalizer ---------
	
				cp /etc/webalizer/webalizer.conf /etc/webalizer/webalizer.$sitio.conf
				config_file=/etc/webalizer/webalizer.$sitio.conf
				mv /var/www/webalizer /var/www/html

				sed -i "s/apache\/access.log.1/nginx\/$log/g" $config_file
				sed -i "s,\/var\/www\/webalizer,\/var\/www\/html\/webalizer\/webalizer.$sitio,g" $config_file
				webalizer -c /etc/webalizer/webalizer.$sitio.conf -d
				
				mkdir /var/log/estadisticas/
				mkdir /var/www/html/webalizer/webalizer.$sitio
			
				cd /etc/nginx/sites-available/	
				echo "server{" >> webalizer.$sitio
				echo "	listen 80;" >>  webalizer.$sitio
				echo "		server_name webalizer."$sitio";" >>  webalizer.$sitio
				echo "	location / { " >>  webalizer.$sitio
				echo "		root	/var/www/webalizer/webalizer."$sitio";" >>  webalizer.$sitio
				echo "		index	index.html;" >>  webalizer.$sitio
				echo "		auth_basic	\"Basic Auth\";" >>  webalizer.$sitio
				echo "		auth_basic_user_file /etc/webalizer/webalizer."$sitio".htpasswd;" >>  webalizer.$sitio
				echo "		access_log /var/log/estadisticas/access.log;" >>  webalizer.$sitio
				echo "		error_log /var/log/estadisticas/error.log;" >>  webalizer.$sitio
				echo "	}" >>  webalizer.$sitio
				echo "	location /awstats-icon/ " >>  webalizer.$sitio
				echo "	{" >>  webalizer.$sitio
				echo "		alias /usr/share/awstats/icon/;" >>  webalizer.$sitio
				echo "	}" >>  webalizer.$sitio
				echo "}" >>  webalizer.$sitio
				echo "Usuario para acceder a estadisticas del sitio "$sitio" :"
				read us
				htpasswd -c /etc/webalizer/webalizer.$sitio.htpasswd $us
				
				ln -s /etc/nginx/sites-available/webalizer.$sitio /etc/nginx/sites-enabled/
				echo "* *	* * *	 root	webalizer -c /etc/webalizer/webalizer.$sitio.conf -d" >> /etc/crontab

				cd $log_sites
				echo "http://127.0.0.1/webalizer/webalizer."$sitio"/index.html"
		done
		
		service nginx restart
	fi
	
	if [[ "$DISTR" == *"CentOS"* ]]; then
		echo " ----  Configure webalizer for Centos ----"
		echo " ----  Configure webalizer for Centos ----" >> $LOG
	
		log_sites="/var/log/nginx/"
		cd $log_sites
		
		num_logs=`ls *access*log | wc -l`
		i=0
	
		while  [ $i -lt $num_logs ]; do
			let i=i+1
			log=`ls -1 *access*log | sed -n $i'p'`
			sitio=`ls -1 *access*log | sed -n $i'p' | cut -d "." -f1`
	

			cp /etc/webalizer.conf /etc/webalizer.$sitio.conf	

			sed -i "s,\/var\/log\/httpd\/access_log,\/var\/log\/nginx\/$log,g" /etc/webalizer.$sitio.conf
			sed -i "s,\/var\/www\/usage,\/var\/www\/webalizer.$sitio,g" /etc/webalizer.$sitio.conf
			mkdir /var/log/estadisticas/
			mkdir /etc/webalizer
			mkdir /var/www/webalizer.$sitio
			
			webalizer -c /etc/webalizer.$sitio.conf -d

			cd /etc/nginx/conf.d/	
			echo "server{" >> webalizer.$sitio.conf
			echo "	listen 80;" >> webalizer.$sitio.conf
			echo "		server_name webalizer."$sitio";" >> webalizer.$sitio.conf
			echo "	location / { " >> webalizer.$sitio.conf
			echo "		root	/var/www/webalizer."$sitio";" >> webalizer.$sitio.conf
			echo "		index	index.html;" >> webalizer.$sitio.conf
			echo "		auth_basic	\"Basic Auth\";" >> webalizer.$sitio.conf
			echo "		auth_basic_user_file /etc/webalizer/webalizer."$sitio".htpasswd;" >> webalizer.$sitio.conf
			echo "		access_log /var/log/estadisticas/access.log;" >> webalizer.$sitio.conf
			echo "		error_log /var/log/estadisticas/error.log;" >> webalizer.$sitio.conf
			echo "	}" >> webalizer.$sitio.conf		
			echo "}" >> webalizer.$sitio.conf
			echo "Usuario para acceder a estadisticas del sitio "$sitio" :"
			read us
			htpasswd -c /etc/webalizer/webalizer.$sitio.htpasswd $us

			echo "* * * * *	 root	webalizer -c /etc/webalizer."$sitio".conf -d" >> /etc/crontab
			echo "127.0.0.1	webalizer."$sitio >>  /etc/hosts

			cd $log_sites
			
			echo "http://webalizer."$sitio"/index.html" 
			
		done
		
		service nginx restart
		
		
	fi
	
}

configure_web_apache()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then


		echo " ----  Configure webalizer ----"
		echo " ----  Configure webalizer ----" >> $LOG
		
		log_sites="/var/log/apache2/"
		cd $log_sites
		
		num_logs=`ls *access*log | wc -l`
		i=0
		
		#Configuration for each access_log
		while  [ $i -lt $num_logs ]; do
			let i=i+1
			log=`ls -1 *access*log | sed -n $i'p'`
			sitio=`ls -1 *access*log | sed -n $i'p' | cut -d "." -f1`
			
			#----------- Configuracion Webalizer ---------
			echo "Configuration Webalizer for "$sitio
			echo "Configuration Webalizer for "$sitio >> $LOG
			mv /var/www/webalizer /var/www/html
			cp /etc/webalizer/webalizer.conf /etc/webalizer/webalizer.$sitio.conf
			config_file=/etc/webalizer/webalizer.$sitio.conf
			sed -i "s/access.log.1/$log/g" $config_file
			sed -i "s/\/var\/www\/webalizer/\/var\/www\/html\/webalizer/g" $config_file

			webalizer -c /etc/webalizer/webalizer.$sitio.conf -d
			
			#----------- Configuracion Apache2 ---------
			echo "Apache2 configuration "
			echo "Apache2 configuration " >> $LOG
			cd /etc/apache2/sites-available/
			nombre="000-default.conf"

			sed -i "/<\/VirtualHost>/i\		<Directory /var/www/html/webalizer>" $nombre
			sed -i "/<\/VirtualHost>/i\			AuthName \"Enter Your User Name and Password\"" $nombre
			sed -i "/<\/VirtualHost>/i\			AuthType Basic" $nombre
			sed -i "/<\/VirtualHost>/i\			AuthUserFile /etc/apache2/auth_users" $nombre
			sed -i "/<\/VirtualHost>/i\			Require valid-user" $nombre
			sed -i "/<\/VirtualHost>/i\		</Directory>" $nombre
							
			echo "* * * * *	root	/usr/bin/webalizer -c /etc/webalizer/webalizer."$sitio".conf -d" >> /etc/crontab
			echo "http://127.0.0.1/webalizer/index.html"
			
		done
		
		echo "Usuario para acceder a estadisticas de Webalizer: "
		read us
		htpasswd -c /etc/apache2/auth_users $us
		service apache2 restart
	fi
	if [[ "$DISTR" == *"CentOS"* ]]; then
	
		echo " ----  Configure webalizer CentOS ----"
		echo " ----  Configure webalizer CentOS ----" >> $LOG
			
		log_sites="/var/log/httpd/"
		cd $log_sites
		
		num_logs=`ls *access*log | wc -l`
		i=0
		
		#Configuration for each access_log
		while  [ $i -lt $num_logs ]; do
			let i=i+1
			log=`ls -1 *access*log | sed -n $i'p'`
			sitio=`ls -1 *access*log | sed -n $i'p' | cut -d "." -f1`
					
			#----------- Configuracion Webalizer --------
			cp /etc/webalizer.conf /etc/webalizer.$sitio.conf
			
			sed -i "s/access_log/$log/g" /etc/webalizer.$sitio.conf
			sed -i "s,\/var\/www\/usage,\/var\/www\/webalizer.$sitio,g" /etc/webalizer.$sitio.conf
			mkdir /var/log/estadisticas/
			mkdir /etc/webalizer
			mkdir /var/www/webalizer.$sitio
			
			webalizer -c /etc/webalizer.$sitio.conf -d

			cd /etc/httpd/conf.d/	
			echo "Alias /webalizer.$sitio /var/www/webalizer.$sitio" >> webalizer.$sitio.conf
			echo "<Location /webalizer.$sitio>" >> webalizer.$sitio.conf
			echo "		AuthName        \"Enter Your User Name and Password\"" >> webalizer.$sitio.conf
			echo "		AuthType Basic " >> webalizer.$sitio.conf
			echo "		AuthUserFile    /etc/webalizer/webalizer.$sitio.htpasswd" >> webalizer.$sitio.conf
			echo "		Require valid-user" >> webalizer.$sitio.conf
			echo "</Location>" >> webalizer.$sitio.conf
			echo "Usuario para acceder a estadisticas del sitio "$sitio" :"
			read us
			htpasswd -c /etc/webalizer/webalizer.$sitio.htpasswd $us

			echo "* * * * *	 root	webalizer -c /etc/webalizer."$sitio".conf -d" >> /etc/crontab
			echo "127.0.0.1	webalizer."$sitio >>  /etc/hosts

			cd $log_sites
			
			echo "http://127.0.0.1/webalizer."$sitio"/index.html"
			
		done 
		
		service httpd restart
	fi
	
}



banner_log
install_web
configure_web