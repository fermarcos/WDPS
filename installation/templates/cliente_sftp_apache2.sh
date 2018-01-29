IP="`hostname -I | cut -d " " -f1`"
IP="${IP// /-}"

cd /var/log/apache2
num_logs=`ls *access*log | wc -l`
count=0
	
while  [ $count -lt $num_logs ]; do
	let count=count+1
	log=`ls -1 *access*log | sed -n $count'p'`		
	cp -f /var/log/apache2/$log /tmp/logs_consola/$IP$log
done
	
cp -f /var/log/auth.log /tmp/logs_consola/$IP-auth.log
cp -f /var/log/maillog /tmp/logs_consola/$IP-maillog
cp -f /var/log/mysql/error.log /tmp/logs_consola/$IP-mysql_error.log
	
sftp -i /tmp/key_consola/$IP-id_rsa userftp@IP_SERVER:/var/log/apache2 <<EOF
put /tmp/logs_consola/*access*
cd /var/log/analisis
put /tmp/logs_consola/*
bye
EOF