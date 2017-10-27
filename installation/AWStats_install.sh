#!/bin/bash
LOG="`pwd`/../log/AWStats_install.log"
DISTR="`cat /etc/*release`"
UNAME="`uname -a`"

#Banner that inits log file
banner_log()
{
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo "######################################" >> $LOG
	echo "###     AWStats INSTALLATION      ####" >> $LOG
	echo "######################################" >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo
	echo
	echo "######################################"
	echo "###     AWStats INSTALLATION      ####"
	echo "######################################"
	echo
	echo
}

install_aws()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo " ----  Install awstats ----"
		echo " ----  Install awstats ----" >> $LOG
		apt-get install awstats apache2-utils -y
	fi
	if [[ "$DISTR" == *"CentOS"* ]]; then
		echo " ----  Install awstats ----"
		echo " ----  Install awstats ----" >> $LOG
		if [[ "$UNAME"=*"x86_64"* ]]; then
			cd `pwd`/../rpm
			rpm -Uhv rpmforge-release-0.5.3-1.el5.rf.x86_64.rpm
			yum -y install awstats httpd-tools
		fi
	fi
	
}

configure_aws()
{

	apache2 -v
	apache_v=$?
	nginx -v
	nginx_v=$?
	httpd -v
	httpd_v=$?
	
	if [[ "$nginx_v" == 0 ]]; then
			configure_aws_nginx
	fi
	
	if [[ "$apache_v" == 0 || "$httpd_v" == 0 ]]; then
			configure_aws_apache
	fi
}


configure_aws_nginx()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
	
		echo " ----  Configure awstats ----"
		echo " ----  Configure awstats ----" >> $LOG
		
		
		log_sites="/var/log/nginx/"
		cd $log_sites
		
		num_logs=`ls *access*log | wc -l`
		i=0
		
		#Configuration for each access_log
		while  [ $i -lt $num_logs ]; do
				let i=i+1
				log=`ls -1 *access*log | sed -n $i'p'`
				sitio=`ls -1 *access*log | sed -n $i'p' | cut -d "." -f1`
						
				#----------- Configuracion AWStats ---------
	
				cp /etc/awstats/awstats.conf /etc/awstats/awstats.$sitio.conf
				config_file=/etc/awstats/awstats.$sitio.conf
				

				sed -i "s/^LogFile=\"\/var\/log\/apache2\/access.log\"/LogFile=\"\/var\/log\/nginx\/$log\"/g" $config_file
				sed -i "s/SiteDomain=\"\"/SiteDomain=\"$sitio\"/g" $config_file
				sed -i "s/DirData=\"\/var\/lib\/awstats\"/DirData=\"\/var\/lib\/awstats\/$sitio\/\"/g" $config_file 
				sed -in "169 s/127\.0\.0\.1/127\.0\.0\.1 $sitio/g" $config_file
				mkdir /var/lib/awstats/$sitio/
				mkdir /var/www/estadisticas.$sitio/
				/usr/lib/cgi-bin/awstats.pl -config=$sitio -update -output > /var/www/estadisticas.$sitio/estadisticas.html
				mkdir /var/log/estadisticas/
				cd /etc/nginx/sites-available/	
				echo "server{" >> estadisticas.$sitio
				echo "	listen 80;" >> estadisticas.$sitio
				echo "		server_name estadisticas."$sitio";" >> estadisticas.$sitio
				echo "	location / { " >> estadisticas.$sitio
				echo "		root	/var/www/estadisticas."$sitio";" >> estadisticas.$sitio
				echo "		index	estadisticas.html;" >> estadisticas.$sitio
				echo "		auth_basic	\"Basic Auth\";" >> estadisticas.$sitio
				echo "		auth_basic_user_file /etc/awstats/estadisticas."$sitio".htpasswd;" >> estadisticas.$sitio
				echo "		access_log /var/log/estadisticas/access.log;" >> estadisticas.$sitio
				echo "		error_log /var/log/estadisticas/error.log;" >> estadisticas.$sitio
				echo "	}" >> estadisticas.$sitio
				echo "	location /awstats-icon/ " >> estadisticas.$sitio
				echo "	{" >> estadisticas.$sitio
				echo "		alias /usr/share/awstats/icon/;" >> estadisticas.$sitio
				echo "	}" >> estadisticas.$sitio
				echo "}" >> estadisticas.$sitio
				echo "Usuario para acceder a estadisticas del sitio "$sitio" :"
				read us
				htpasswd -c /etc/awstats/estadisticas.$sitio.htpasswd $us
				
				ln -s /etc/nginx/sites-available/estadisticas.$sitio /etc/nginx/sites-enabled/
				echo "* *	* * *	 root	/usr/lib/cgi-bin/awstats.pl -config="$sitio" -update -output > /var/www/estadisticas."$sitio"/estadisticas.html" >> /etc/crontab
				echo "127.0.1.1	estadisticas."$sitio >>  /etc/hosts

				cd $log_sites
				echo "http://estadisticas."$sitio"/estadisticas.html"
		done
			
		service nginx stop
		service nginx start

	fi
	
	if [[ "$DISTR" == *"CentOS"* ]]; then
		echo " ----  Configure awstats for Centos ----"
		echo " ----  Configure awstats for Centos ----" >> $LOG
	
		log_sites="/var/log/nginx/"
		cd $log_sites
		
		num_logs=`ls *access*log | wc -l`
		i=0
	
		while  [ $i -lt $num_logs ]; do
			let i=i+1
			log=`ls -1 *access*log | sed -n $i'p'`
			sitio=`ls -1 *access*log | sed -n $i'p' | cut -d "." -f1`
	

			cp /etc/awstats/awstats.localhost.localdomain.conf /etc/awstats/awstats.$sitio.conf	
			sed -i "s,SiteDomain=\"localhost.localdomain\",SiteDomain=\"$sitio\",g" /etc/awstats/awstats.$sitio.conf
			sed -in '168 s/127\.0\.0\.1/127\.0\.0\.1 $sitio/g' /etc/awstats/awstats.$sitio.conf
			sed -i "s,LogFile=\"/var/log/httpd/access_log\",LogFile=\"/var/log/nginx/$log\",g" /etc/awstats/awstats.$sitio.conf
			mkdir /usr/share/nginx/estadisticas
			mkdir /var/log/estadisticas/
			/var/www/awstats/awstats.pl -config=$sitio -update -output > /usr/share/nginx/estadisticas/estadisticas.$sitio.html
			cd /etc/nginx/conf.d/	
			echo "server{" >> estadisticas.$sitio.conf
			echo "	listen 80;" >> estadisticas.$sitio.conf
			echo "		server_name estadisticas;" >> estadisticas.$sitio.conf
			echo "	location / { " >> estadisticas.$sitio.conf
			echo "		root	/usr/share/nginx/estadisticas;" >> estadisticas.$sitio.conf
			echo "		index	estadisticas."$sitio".html;" >> estadisticas.$sitio.conf
			echo "		auth_basic	\"Basic Auth\";" >> estadisticas.$sitio.conf
			echo "		auth_basic_user_file /etc/awstats/estadisticas."$sitio".htpasswd;" >> estadisticas.$sitio.conf
			echo "		access_log /var/log/estadisticas/access.log;" >> estadisticas.$sitio.conf
			echo "		error_log /var/log/estadisticas/error.log;" >> estadisticas.$sitio.conf
			echo "	}" >> estadisticas.$sitio.conf		
			echo "	location /awstats-icon/ " >> estadisticas.$sitio.conf
			echo "	{" >> estadisticas.$sitio.conf
			echo "		alias /usr/share/awstats/icon/;" >> estadisticas.$sitio.conf
			echo "	}" >> estadisticas.$sitio.conf
			echo "}" >> estadisticas.$sitio.conf
			echo "Usuario para acceder a estadisticas del sitio "$sitio" :"
			read us
			htpasswd -c /etc/awstats/estadisticas.$sitio.htpasswd $us

			echo "* * * * *	 root	/var/www/awstats/awstats.pl -config=$sitio -update -output > /usr/share/nginx/estadisticas/estadisticas.$sitio.html" >> /etc/crontab
			echo "127.0.0.1	estadisticas" >>  /etc/hosts

			cd $log_sites
			echo "http://estadisticas/estadisticas."$sitio."html"
			
		done
		
		
	fi
}

configure_aws_apache()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then


		echo " ----  Configure awstats ----"
		echo " ----  Configure awstats ----" >> $LOG
		
		log_sites="/var/log/apache2/"
		cd $log_sites
		
		num_logs=`ls *access*log | wc -l`
		i=0
		
		#Configuration for each access_log
		while  [ $i -lt $num_logs ]; do
				let i=i+1
				log=`ls -1 *access*log | sed -n $i'p'`
				sitio=`ls -1 *access*log | sed -n $i'p' | cut -d "." -f1`
						
				#----------- Configuracion AWStats ---------
				echo "Configuration for "$sitio
				echo "Configuration for "$sitio >> $LOG
				cp /etc/awstats/awstats.conf /etc/awstats/awstats.$sitio.conf
				config_file=/etc/awstats/awstats.$sitio.conf
				sed -i "s/access.log/$log/g" $config_file
				sed -i "s/SiteDomain=\"\"/SiteDomain=\"$sitio\"/g" $config_file

				/usr/lib/cgi-bin/awstats.pl -config=$sitio -update

				#----------- Configuracion Apache2 ---------
				echo "Apache2 configuration "
				echo "Apache2 configuration " >> $LOG
				cd /etc/apache2/sites-available/
				nombre="000-default.conf"
				#nombre="estadisticas."$sitio".conf"
				#echo "<VirtualHost *:80>" >> $nombre
				#echo "	DocumentRoot /var/www/html" >> $nombre 
				#echo "	ErrorLog /var/www/html/error.log " >> $nombre
				#echo "	CustomLog	/var/www/html/access.log combined" >> $nombre
				#echo "	Alias /awstatsclasses \"/usr/share/awstats/lib\"" >> $nombre
				#echo "	Alias /awstats-icon \"/usr/share/awstats/icon/\"" >> $nombre
				#echo "	Alias /awstatscss \"/usr/share/doc/awstats/examples/css/\"" >> $nombre
				#echo "	ScriptAlias /awstats/ /usr/lib/cgi-bin/" >> $nombre
				#echo "	Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch" >> $nombre
				#echo "	<Directory /usr/lib/cgi-bin/>" >> $nombre
				#echo "		AuthName \"Enter Your User Name and Password\"" >> $nombre
				#echo "		AuthType Basic" >> $nombre
				#echo "		AuthUserFile /etc/apache2/auth_users" >> $nombre
				#echo "		Require valid-user" >> $nombre
				#echo "		</Directory>" >> $nombre
				#echo "<\/VirtualHost>" >> $nombre				
				sed -i "/<\/VirtualHost>/i		Alias /awstatsclasses \"\/usr\/share\/awstats\/lib/\"" $nombre
				sed -i "/<\/VirtualHost>/i\		Alias /awstats-icon \"/usr/share/awstats/icon/\"" $nombre
				sed -i "/<\/VirtualHost>/i\		Alias /awstatscss \"/usr/share/doc/awstats/examples/css/\"" $nombre
				sed -i "/<\/VirtualHost>/i\		ScriptAlias /awstats/ /usr/lib/cgi-bin/" $nombre
				sed -i "/<\/VirtualHost>/i\		Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch" $nombre
				sed -i "/<\/VirtualHost>/i\		<Directory /usr/lib/cgi-bin/>" $nombre
				sed -i "/<\/VirtualHost>/i\			AuthName \"Enter Your User Name and Password\"" $nombre
				sed -i "/<\/VirtualHost>/i\			AuthType Basic" $nombre
				sed -i "/<\/VirtualHost>/i\			AuthUserFile /etc/apache2/auth_users" $nombre
				sed -i "/<\/VirtualHost>/i\			Require valid-user" $nombre
				sed -i "/<\/VirtualHost>/i\		</Directory>" $nombre
				/etc/init.d/apache2 reload
				echo "* * * * *	root	/usr/lib/cgi-bin/awstats.pl -config="$sitio" -update > /dev/null" >> /etc/crontab
				cd $log_sites
				
				echo "http://127.0.0.1/awstats/awstats.pl?config="$sitio
				
		done
		a2enmod cgi
		echo "Usuario para acceder a estadisticas: "
		read us
		htpasswd -c /etc/apache2/auth_users $us
		/etc/init.d/apache2 reload
	fi 
	
	if [[ "$DISTR" == *"CentOS"* ]]; then
	
		echo " ----  Configure awstats ----"
		echo " ----  Configure awstats ----" >> $LOG
			
		log_sites="/var/log/httpd/"
		cd $log_sites
		
		num_logs=`ls *access*log | wc -l`
		i=0
		
		
		#Configuration for each access_log
		while  [ $i -lt $num_logs ]; do
			let i=i+1
			log=`ls -1 *access*log | sed -n $i'p'`
			sitio=`ls -1 *access*log | sed -n $i'p' | cut -d "." -f1`
					
			#----------- Configuracion AWStats --------

			echo " ----  Configure awstats for Centos ----"
			echo " ----  Configure awstats for Centos ----" >> $LOG
			
			cp /etc/awstats/awstats.localhost.localdomain.conf /etc/awstats/awstats.$sitio.conf	
			sed -i "s/^LogFormat=1/LogFormat=4/g" /etc/awstats/awstats.$sitio.conf
			sed -i "s/^LogFile=\"\/var\/log\/httpd\/access_log\"/LogFile=\"\/var\/log\/httpd\/$sitio\"/g" /etc/awstats/awstats.$sitio.conf
			sed -i "s,SiteDomain=\"localhost.localdomain\",SiteDomain=\"$sitio\",g" /etc/awstats/awstats.$sitio.conf
			sed -in "168 s/127\.0\.0\.1/127\.0\.0\.1 www.$sitio/g" /etc/awstats/awstats.$sitio.conf
			/var/www/awstats/awstats.pl -config=$sitio -update

			sed -i "/<\/Directory>/i		AuthName \"Enter Your User Name and Password\"" /etc/httpd/conf.d/awstats.conf
			sed -i "/<\/Directory>/i		AuthType Basic" /etc/httpd/conf.d/awstats.conf
			sed -i "/<\/Directory>/i		AuthUserFile /etc/awstats/estadisticas."$sitio".htpasswd" /etc/httpd/conf.d/awstats.conf
			sed -i "/<\/Directory>/i		Require valid-user" /etc/httpd/conf.d/awstats.conf

			echo "Usuario para acceder a estadisticas: "
			read us
			htpasswd -c /etc/awstats/estadisticas.$sitio.htpasswd $us
			echo "* * * * * root /var/www/awstats/awstats.pl -config="$sitio" -update" >> /etc/crontab
			
			echo "http://127.0.0.1/awstats/awstats.pl?config="$sitio
			cd $log_sites
		done
		service httpd restart
		
	fi
	
}


banner_log
install_aws
configure_aws
