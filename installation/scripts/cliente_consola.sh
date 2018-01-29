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
#######################################################
######      Envio de LOGS a CONSOLA              ######
#######################################################

#==========================================#

DISTR="`cat /etc/*release`"
LOG="`pwd`/../log/consola.log"
templates="`pwd`/../templates"

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
	echo "[`date +"%F %X"`] - [cliente_consola_install | EXIT_INSTALL]   The installation script has been terminated with some errors" >> $LOG
	echo "[`date +"%F %X"`] - [cliente_consola_install | EXIT_INSTALL]   The installation script has been terminated with some errors"
	echo
	echo
	exit 1
}
#####################################################################################################
exec_install()
{
	if [ $1 -ne 0 ]; then
		echo "[`date +"%F %X"`] - [cliente_consola_install | EXEC_INSTALL]   ERROR - Installation of $2" >> $LOG
		exit_install
	else
		echo "[`date +"%F %X"`] - [cliente_consola_install | EXEC_INSTALL]   $2 has been installed OK"  >> $LOG	
	fi
}
#####################################################################################################
exec_cmd()
{
        if [ $1 -ne 0 ]; then
                echo "[`date +"%F %X"`] - [cliente_consola_install | EXEC_CMD]  ERROR - $2" >> $LOG
                exit_install
        else
                echo "[`date +"%F %X"`] - [cliente_consola_install | EXEC_CMD]  The command $2 has been executed OK" >> $LOG
        fi
}
#####################################################################################################
install_()
{
	if [[ "$DISTR" == *"Ubuntu"* || "$DISTR" == *"Debian"* ]]; then
		echo "[`date +"%F %X"`] - [cliente_consola_install | INSTALL_CLIENTE_CONSOLA]   Installing cliente_consola " >> $LOG
		cmd="apt-get install openssh-client sshpass lftp -y"
		$cmd
		exec_cmd $? "cliente_consola $cmd"
	fi
	if [[ "$DISTR" == *"CentOS"* ]]; then
		echo "[`date +"%F %X"`] - [cliente_consola_install | INSTALL_CLIENTE_CONSOLA]   Installing cliente_consola " >> $LOG
		cmd="yum install openssh-clients sshpass lftp -y"
		$cmd
		exec_cmd $? "cliente_consola $cmd"
	fi
}
config()
{
	mkdir -p /tmp/logs_consola/ /tmp/cliente_sftp /tmp/key_consola
	cd $templates
	chmod 755 /tmp/cliente_sftp/*
	
	echo "IP DEL SERVIDOR: "
	cmd="read IP_SERVER"
	$cmd
	exec_cmd $? "CONFIGURE $cmd"

	apache2 -v 2> /dev/null
	apache=$?
	nginx -v 2> /dev/null
	nginx=$?
	httpd -v 2> /dev/null
	httpd=$?
	
	if [[ "$httpd" == 0 ]]; then
		cp -f cliente_sftp_httpd.sh /tmp/cliente_sftp/
		sed -i "s/IP_SERVER/$IP_SERVER/g" /tmp/cliente_sftp/cliente_sftp_httpd.sh	
		echo "1,31 * * * * root bash /tmp/cliente_sftp/cliente_sftp_httpd.sh > /dev/null 2>&1" >> /etc/crontab
	fi
	if [[ "$nginx" == 0 ]]; then
		cp -f cliente_sftp_nginx.sh /tmp/cliente_sftp/
		sed -i "s/IP_SERVER/$IP_SERVER/g" /tmp/cliente_sftp/cliente_sftp_nginx.sh
		echo "1,31 * * * * root bash /tmp/cliente_sftp/cliente_sftp_nginx.sh > /dev/null 2>&1" >> /etc/crontab	
	elif [[ "$apache" == 0 ]]; then
		cp -f cliente_sftp_apache2.sh /tmp/cliente_sftp/
		sed -i "s/IP_SERVER/$IP_SERVER/g" /tmp/cliente_sftp/cliente_sftp_apache2.sh
		echo "1,31 * * * * root bash /tmp/cliente_sftp/cliente_sftp_apache2.sh > /dev/null 2>&1" >> /etc/crontab
	fi	
	
	chmod 700 /tmp/key_consola/
	IP="`hostname -I | cut -d " " -f1`"
	IP="${IP// /-}"
	ssh-keygen -f /tmp/key_consola/$IP-id_rsa -N ""
	chmod 600 /tmp/key_consola/$IP-id_rsa
	
	lftp sftp://userftp:"hola123.,"@$IP_SERVER:/home/userftp -e "put /tmp/key_consola/$IP-id_rsa.pub ; bye"
	sshpass -p 'hola123.,' ssh userftp@$IP_SERVER 'cat /home/userftp/'$IP'-id_rsa.pub >> ~/.ssh/authorized_keys;rm /home/userftp/'$IP'-id_rsa.pub'
}

#####################################################################################################
banner_log()
{
	echo "######################################" >  $LOG
	echo "###   cliente_consola_install     ####" >> $LOG
	echo "######################################" >> $LOG
	echo "______________________________________" >> $LOG
	echo "Started @ [`date`]"                     >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo "######################################" 
	echo "###   cliente_consola_install     ####"
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
        echo "The installation of cliente_consola has been completed"
        echo "############################################"
        echo ""
        echo "############################################" >> $LOG
        echo "[`date +"%F %X"`] - [cliente_consola_install | END_INSTALL]  The installation of AWStats has been completed" >> $LOG
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
	install_
	config
	end_install
