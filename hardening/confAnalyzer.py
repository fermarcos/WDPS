#!/usr/bin/python
import re
import sys
import os
import itertools
import commands
import ConfigParser
from optparse import OptionParser
#Funcion para cargar la configuracion
def loadConfig(configFile): 

    global sshFile ,webFile ,phpFile, mysqlFile,psqlFile
    #Cargando configuraciones
    config = ConfigParser.ConfigParser()
    config.read(configFile)
    #Path de los logs
    webFile = config.get("ServicesFiles", "web")
    sshFile = config.get("ServicesFiles", "ssh")
    phpFile = config.get("ServicesFiles", "php")
    psqlFile = config.get("ServicesFiles", "postgresql")
    mysqlFile = config.get("ServicesFiles", "mysql")

#Funcion para imprimir mensaje de eror y salir
def printError(message):
    sys.stderr.write("Error: %s" % message)
    sys.exit(1)

def checkOptions(opts):
    for f in opts.service.split(','):
        if f not in ['web','ssh','php','mysql','postgresql','all']: printError("Error: Servicio no disponible:\t%s\n" % f)
    if opts.out is None: printError("Please enter the name of the report\n")
    if opts.config is None: printError("Please enter the name of the configuration file\n")

def addOptions():
    parser = OptionParser()
    parser.add_option("-s", "--service", dest="service", default="all", help="Select the service")
    parser.add_option("-o", "--out", dest="out", default=None, help="Name for the report")
    parser.add_option("-c", "--config", dest="config", default=None, help="Config File")
    return parser

def checkingSSH(sshFile, reportFile):
    print "Analizando "+sshFile
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+sshFile+"\n")
    reportFile.write("_____________________________________________________________________\n")
    permisos = commands.getoutput("stat "+sshFile+" | grep -i access | head -1       | cut -d' ' -f2")
    owner = commands.getoutput("stat "+sshFile+" | grep -i access | head -1  |  sed 's/ //g'")
    reportFile.write("\nPermisos y propietario \n")
    if "Uid:(0/root)Gid:(0/root)" in owner:
        reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
    else: reportFile.write("\tEjecute  chown root:root "+sshFile+ "para cambiar el propietario\n")
    if "(0600/-rw-------)" in permisos:
        reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
    else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod og-rwx /etc/ssh/sshd_config para cambiarlos\n")
    reportFile.write("\nProtocolo SSH \n")
    protocolo = commands.getoutput("grep \"^Protocol\" "+sshFile+" | cut -d\" \" -f2")
    if protocolo == "2":
        reportFile.write("\tVersion 2 - correcto\n")
    else: reportFile.write("\tSSH v1 sufre de inseguridades que no afectan a SSH v2. \n\tEdite su archivo de configuracion a Protocol 2 \n")
    reportFile.write("\nLogLevel SSH \n")
    logLevel = commands.getoutput("grep \"^LogLevel\" "+sshFile+" | cut -d\" \" -f2")
    if logLevel == "INFO":
        reportFile.write("\tLogLevel INFO - correcto\n")
    else: reportFile.write("\tRegistra la actividad de inicio de sesion de los usuarios de SSH. \n\tEdite su archivo de configuracion con LogLevel INFO \n")
    reportFile.write("\nX11Forwarding \n")
    X11 = commands.getoutput("grep \"^X11Forwarding\" "+sshFile+" | cut -d\" \" -f2")
    if X11 == "no":
        reportFile.write("\X11Forwarding no - correcto\n")
    else: reportFile.write("\tDeshabilite el reenvio de X11 a menos que exista un requisito operacional para usar las aplicaciones X11 directamente. \n\tEdite su archivo de configuracion con X11Forwarding no \n")
    reportFile.write("\nMaxAuthTries \n")
    auth = commands.getoutput("grep \"^MaxAuthTries\" "+sshFile+" | cut -d\" \" -f2")
    try:
        num = int(auth)
    except Exception as e:
        auth = 100000
    if auth <= 4:
        reportFile.write("\tMaxAuthTries 4 o menos - correcto\n")
    else: reportFile.write("\tSe recomienda un establecer un limite de intentos minimo de 4 \n\tEdite su archivo de configuracion con MaxAuthTries 4 \n")
    reportFile.write("\nIgnoreRhosts \n")
    ignore = commands.getoutput("grep \"^IgnoreRhosts\" "+sshFile+" | cut -d\" \" -f2")
    if ignore == "yes":
        reportFile.write("\tIgnoreRhosts yes - correcto\n")
    else: reportFile.write("\tLa configuracion de este parametro obliga a los usuarios a introducir una contrasena al autenticar con ssh. \n\tEdite su archivo de configuracion con IgnoreRhosts yes \n")
    reportFile.write("\nHostbasedAuthentication \n")
    hostBased = commands.getoutput("grep \"^HostbasedAuthentication\" "+sshFile+" | cut -d\" \" -f2")
    if hostBased == "no":
        reportFile.write("\tHostbasedAuthentication no - correcto\n")
    else: reportFile.write("\tEl parametro HostbasedAuthentication especifica si se permite la autenticacion a traves de hosts de confianza \n\tEdite su archivo de configuracion con HostbasedAuthentication no \n")
    reportFile.write("\nRootLogin \n")
    root = commands.getoutput("grep \"^PermitRootLogin\" "+sshFile+" | cut -d\" \" -f2")
    if root == "no":
        reportFile.write("\tPermitRootLogin no - correcto\n")
    else: reportFile.write("\tSe recomienda administradores del servidor se autenticen utilizando su propia cuenta individual, y luego se escalen a raiz a traves de sudo o su. \n\tEdite su archivo de configuracion con PermitRootLogin no \n")
    reportFile.write("\nPermitEmptyPasswords \n")
    empty = commands.getoutput("grep \"^PermitEmptyPasswords\" "+sshFile+" | cut -d\" \" -f2")
    if empty == "no":
        reportFile.write("\tPermitEmptyPasswords no - correcto\n")
    else: reportFile.write("\tReduce la probabilidad de acceso no autorizado al sistema. \n\tEdite su archivo de configuracion con PermitEmptyPasswords no \n")
    reportFile.write("\nEnvironment Options \n")
    empty = commands.getoutput("grep \"PermitUserEnvironment\" "+sshFile+" | cut -d\" \" -f2")
    if empty == "no":
        reportFile.write("\PermitUserEnvironment no - correcto\n")
    else: reportFile.write("\tDeshabilitar ya que le permite a los usuarios presentar opciones de entorno al daemon ssh. \n\tEdite su archivo de configuracion con PermitUserEnvironment no \n")

def checkingWEB(webFile, reportFile):
    apache = commands.getoutput("ls /etc/apache2/apache2.conf")
    apaches="/etc/apache2/apache2.conf"
    httpd = commands.getoutput("ls "+webFile)
    
    if httpd=="/etc/httpd/conf/httpd.conf":
        print "Analizando "+ webFile
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+webFile+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+webFile+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+webFile+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+webFile+ "para cambiar el propietario\n")
        if "(0644/-rw-r--r--)" in permisos:
            reportFile.write("\tPermisos correctos (0644/-rw-r--r--)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 644 /etc/httpd/conf/httpd.conf para cambiarlos\n")
        signature = commands.getoutput("grep \"^ServerSignature\" "+webFile+" | cut -d\" \" -f2")
        token = commands.getoutput("grep \"^ServerTokens\" "+webFile+" | cut -d\" \" -f2")
        reportFile.write("\nServer Signature \nServerTokens \n")
        if signature == "Off" and token == "Prod":
            reportFile.write("\tServerSignature Off - correcto\n")
            reportFile.write("\tServerTokens Prod - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite ver la version del servicio web que tiene. \n\tEdite su archivo de configuracion con ServerSignature Off y ServerTokens Prod\n")
        indexes = commands.getoutput("grep \"    Options Indexes FollowSymLinks\" "+webFile+" | cut -d" " -f 6")
        reportFile.write("\nOptions Indexes \n")
        if indexes == "-Indexes":
            reportFile.write("\tOptions -Indexes - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite ver listar lo que contiene el directorio. \n\tEdite su archivo de configuracion con Options -Indexes \n")
        symlinks = commands.getoutput("grep \"    Options Indexes FollowSymLinks\" "+webFile+" | cut -d" " -f 7")
        reportFile.write("\nOptions FollowSymLinks \n")
        if symlinks == "-FollowSymLinks":
            reportFile.write("\tOptions -FollowSymLinks - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite los enlace simbolicos. \n\tEdite su archivo de configuracion con Options -FollowSymLinks, puede habilitarlo mediante el archivo .htaccess  \n")    
        alive = commands.getoutput("grep \"^KeepAlive [On|Off]\" "+webFile+" | cut -d" " -f 2")
        reportFile.write("\nKeepAlive \n")
        if alive == "On":
            reportFile.write("\tKeepAlive On - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite habilitar el tiempo de peticiones al servidor. \n\tEdite su archivo de configuracion con KeepAlive On\n")
        time = commands.getoutput("grep \"^KeepAliveTimeout\" "+webFile+" | cut -d" " -f 2")
        reportFile.write("\nKeepAliveTimeout \n")
        if time <= 4:
            reportFile.write("\tKeepAlive 4 - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite limitar el numero de segundos que se puede tardar una pagina en cargar. \n\tEdite su archivo de configuracion con KeepAliveTimeout de 2 a 4\n")
        directorio = "/etc/httpd/conf.d/"
        files = commands.getoutput("ls "+directorio+" | grep .conf$").split("\n")
        for f in files:
            reportFile.write("_____________________________________________________________________\n")
            reportFile.write("Analizando "+directorio+f+"\n")
            reportFile.write("_____________________________________________________________________\n")
            reportFile.write("\nDirectory \n")
            reportFile.write("\n\tOptions None \n")
            opn = commands.getoutput("grep \"Options None\" "+directorio+f)
            if opn=="Options None":
                reportFile.write("\t\tOptions None -correct \n")
            else: reportFile.write("\t\tEsta opcion no permitira a los usuarios activar ninguna caracteristica opcional\n\t\tEdite su archivo y en la etiqueta de Directory agregue Options None\n")
            order = commands.getoutput("grep \"Order deny,allow\" "+directorio+f)
            reportFile.write("\n\tOrder deny,allow \n")
            if order=="Order deny,allow":
                reportFile.write("\t\tOrder deny,allow -correct \n")
            else: reportFile.write("\t\tEste es el orden en que se procesaran las directivas \"Denegar\" y \"Permitir\". Aqui va a \"negar\" primero y \"permitir\" a continuacion.\n\t\tEdite su archivo y en la etiqueta de Directory agregue Order deny,allow\n")
            denf = commands.getoutput("grep \"Deny from all\" "+directorio+f)
            reportFile.write("\n\tDeny from all\n")
            if denf=="Deny from all":
                reportFile.write("\t\tDeny from all -correct \n")
            else: reportFile.write("\t\tEsto denegara la solicitud de todo el mundo al directorio en cuestion, nadie podra acceder a tal directorio.\n\t\tEdite su archivo y en la etiqueta de Directory agregue Deny from all\n")
            index = commands.getoutput("grep \"\-Indexes\" "+directorio+f)
            reportFile.write("\nOptions Indexes \n")
            if index == "Options -Indexes":
                reportFile.write("\tOptions -Indexes - correcto\n")
            else: reportFile.write("\tLa configuracion de este parametro permite listar lo que contiene el directorio. \n\tPara evitar esto, edite su archivo de configuracion con Options -Indexes \n")
            limit = commands.getoutput("grep \"\LimitRequestBody\" "+directorio+f)
            reportFile.write("\nLimitRequestBody \n")
            if limit == "LimitRequestBody":
                reportFile.write("\tLimitRequestBody - correcto\n")
            else: reportFile.write("\tLa configuracion de este parametro permite limitar las peticiones que se puedan realizar. \n\tEdite su archivo de configuracion con LimitRequestBody 512000 [Este numero es de acuerdo a tus necesidades]\n")
    elif apache=="/etc/apache2/apache2.conf":
        print "Analizando "+ apaches
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+apaches+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+apaches+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+apaches+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+apaches+ "para cambiar el propietario\n")
        if "(0644/-rw-r--r--)" in permisos:
            reportFile.write("\tPermisos correctos (0644/-rw-r--r--)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 644 /etc/httpd/conf/httpd.conf para cambiarlos\n")
        signature = commands.getoutput("grep \"^ServerSignature\" "+apaches+" | cut -d\" \" -f2")
        token = commands.getoutput("grep \"^ServerTokens\" "+apaches+" | cut -d\" \" -f2")
        reportFile.write("\nServer Signature \nServerTokens \n")
        if signature == "Off" and token == "Prod":
            reportFile.write("\tServerSignature Off - correcto\n")
            reportFile.write("\tServerTokens Prod - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite ver la version del servicio web que tiene. \n\tEdite su archivo de configuracion con ServerSignature Off y ServerTokens Prod\n")
        indexes = commands.getoutput("grep \"    Options Indexes FollowSymLinks\" "+apaches+" | cut -d" " -f 6")
        reportFile.write("\nOptions Indexes \n")
        if indexes == "-Indexes":
            reportFile.write("\tOptions -Indexes - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite ver listar lo que contiene el directorio. \n\tEdite su archivo de configuracion con Options -Indexes \n")
        symlinks = commands.getoutput("grep \"    Options Indexes FollowSymLinks\" "+apaches+" | cut -d" " -f 7")
        reportFile.write("\nOptions FollowSymLinks \n")
        if symlinks == "-FollowSymLinks":
            reportFile.write("\tOptions -FollowSymLinks - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite los enlace simbolicos. \n\tEdite su archivo de configuracion con Options -FollowSymLinks, puede habilitarlo mediante el archivo .htaccess  \n")    
        alive = commands.getoutput("grep \"^KeepAlive [On|Off]\" "+apaches+" | cut -d" " -f 2")
        reportFile.write("\nKeepAlive \n")
        if alive == "On":
            reportFile.write("\tKeepAlive On - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite habilitar el tiempo de peticiones al servidor. \n\tEdite su archivo de configuracion con KeepAlive On\n")
        time = commands.getoutput("grep \"^KeepAliveTimeout\" "+apaches+" | cut -d" " -f 2")
        reportFile.write("\nKeepAliveTimeout \n")
        if time <= 4:
            reportFile.write("\tKeepAlive 4 - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite limitar el numero de segundos que se puede tardar una pagina en cargar. \n\tEdite su archivo de configuracion con KeepAliveTimeout de 2 a 4\n")
        di = "/etc/apache2/sites-enabled/"
        fil = commands.getoutput("ls "+di+" | grep .conf$").split("\n")
        for fa in files:
            reportFile.write("_____________________________________________________________________\n")
            reportFile.write("Analizando "+directorio+fa+"\n")
            reportFile.write("_____________________________________________________________________\n")
            reportFile.write("\nDirectory \n")
            reportFile.write("\n\tOptions None \n")
            opn = commands.getoutput("grep \"Options None\" "+directorio+fa)
            if opn=="Options None":
                reportFile.write("\t\tOptions None -correct \n")
            else: reportFile.write("\t\tEsta opcion no permitira a los usuarios activar ninguna caracteristica opcional\n\t\tEdite su archivo y en la etiqueta de Directory agregue Options None\n")
            order = commands.getoutput("grep \"Order deny,allow\" "+directorio+fa)
            reportFile.write("\n\tOrder deny,allow \n")
            if order=="Order deny,allow":
                reportFile.write("\t\tOrder deny,allow -correct \n")
            else: reportFile.write("\t\tEste es el orden en que se procesaran las directivas \"Denegar\" y \"Permitir\". Aqui va a \"negar\" primero y \"permitir\" a continuacion.\n\t\tEdite su archivo y en la etiqueta de Directory agregue Order deny,allow\n")
            denf = commands.getoutput("grep \"Deny from all\" "+directorio+fa)
            reportFile.write("\n\tDeny from all\n")
            if denf=="Deny from all":
                reportFile.write("\t\tDeny from all -correct \n")
            else: reportFile.write("\t\tEsto denegara la solicitud de todo el mundo al directorio en cuestion, nadie podra acceder a tal directorio.\n\t\tEdite su archivo y en la etiqueta de Directory agregue Deny from all\n")
            index = commands.getoutput("grep \"\-Indexes\" "+directorio+fa)
            reportFile.write("\nOptions Indexes \n")
            if index == "Options -Indexes":
                reportFile.write("\tOptions -Indexes - correcto\n")
            else: reportFile.write("\tLa configuracion de este parametro permite listar lo que contiene el directorio. \n\tPara evitar esto, edite su archivo de configuracion con Options -Indexes \n")
            limit = commands.getoutput("grep \"\LimitRequestBody\" "+directorio+fa)
            reportFile.write("\nLimitRequestBody \n")
            if limit == "LimitRequestBody":
                reportFile.write("\tLimitRequestBody - correcto\n")
            else: reportFile.write("\tLa configuracion de este parametro permite limitar las peticiones que se puedan realizar. \n\tEdite su archivo de configuracion con LimitRequestBody 512000 [Este numero es de acuerdo a tus necesidades]\n")

    nginx = commands.getoutput("ls /etc/nginx/nginx.conf")
    nginxs="/etc/nginx/nginx.conf"
    if nginx == "/etc/nginx/nginx.conf":
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+nginxs+"\n")
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("\nControlling Buffer Overflow Attacks\n")
        reportFile.write("\nclient_body_buffer_size\n")
        bz = commands.getoutput("grep \"client_body_buffer_size\" "+nginxs+" | cut -d" " -f 3")
        if bz <= "4k;":
            reportFile.write("\tclient_body_buffer_size - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite limitar el tamanio del buffer del cuerpo de la peticion. \n\tEdite su archivo de configuracion con client_body_buffer_size de 1K a 4K\n")
        reportFile.write("\nclient_header_buffer_size\n")
        hz = commands.getoutput("grep \"client_header_buffer_size\" "+nginxs+" | cut -d" " -f 3")
        if hz <= "4k;":
            reportFile.write("\tclient_header_buffer_size - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite limitar el tamanio del header de la peticion. \n\tEdite su archivo de configuracion con client_header_buffer_size de 1K a 4K\n")
        reportFile.write("\nclient_max_body_size\n")
        mbz = commands.getoutput("grep \"client_body_size\" "+nginxs+" | cut -d" " -f 3")
        if mbz <= "4k;":
            reportFile.write("\tclient_max_body_size - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite limitar el tamanio maximo del cuerpo de la peticion. \n\tEdite su archivo de configuracion con client_body_buffer_size de 1K a 4K\n")
        reportFile.write("\nclient_body_timeout\n")
        bt = commands.getoutput("grep \"client_body_timeout\" "+nginxs+" | cut -d" " -f 8")
        if bt <= "15;":
            reportFile.write("\tclient_body_timeout - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite limitar el tiempo de interaccion con el usuario, sino manda nada, lo redirige Request Time Out. \n\tEdite su archivo de configuracion con client_body_timeout 10\n")
        reportFile.write("\nclient_header_timeout\n")
        bh = commands.getoutput("grep \"client_header_timeout\" "+nginxs+" | cut -d" " -f 6")
        if bh <= "15;":
            reportFile.write("\tclient_header_timeout - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite limitar el tiempo de lectura de peticion del cliente, despues de este tiempo lo redirige Request Time Out. \n\tEdite su archivo de configuracion con client_header_timeout 10\n")
        reportFile.write("\nkeepalive_timeout\n")
        kt = commands.getoutput("grep \"keepalive_timeout\" "+nginxs+" | cut -d" " -f 8")
        if kt <= "8;":
            reportFile.write("\tkeepalive_timeout - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite limitar el tiempo de vida con el cliente \n\tEdite su archivo de configuracion con keepalive_timeout 5\n")
        reportFile.write("\nsend_timeout\n")
        st = commands.getoutput("grep \"send_timeout\" "+nginxs+" | cut -d" " -f 6-20")
        if st <= "12;":
            reportFile.write("\tsend_timeout - correcto\n")
        else: reportFile.write("\tLa configuracion de este parametro permite asignar el tiempo de respuesta al cliente \n\tEdite su archivo de configuracion con send_timeout 5\n")
        direc = "/etc/nginx/conf.d/"
        filesn = commands.getoutput("ls "+direc+" | grep .conf$").split("\n")
        for fn in filesn:
            reportFile.write("_____________________________________________________________________\n")
            reportFile.write("Analizando "+direc+fn+"\n")
            reportFile.write("_____________________________________________________________________\n")
            reportFile.write("\nrequest_method \n")
            req = commands.getoutput("grep \"\$request_method \!\~ \" "+direc+fn)
            if req=="$request_method !~":
                reportFile.write("\trequest_method -correct \n")
            else: reportFile.write("\tEsta opcion permitira permitir las peticiones seleccionadas\n\tEdite su archivo y en una sentencia condicional agregue los metodos que requiera $request_method\n")
            httpreq = commands.getoutput("grep \"\$http_user_agent \~\* \" "+direc+fn)
            reportFile.write("\nhttp_user_agent \n")
            if httpreq=="$http_user_agent ~*":
                reportFile.write("\thttp_user_agent -correct \n")
            else: reportFile.write("\tEsta opcion permitira permitira bloquear los user_agent y robots seleccionados\n\tEdite su archivo y en una sentencia condicional agregue los user_agents que quiere bloquear $http_user_agent\n")
            ssl = commands.getoutput("grep -i \"listen 443\" "+direc+fn+" | awk '{print $2}' ")
            reportFile.write("\nSSL\n")
            if ssl=="443":
                reportFile.write("\tssl -correct \n")
            else: reportFile.write("\tEsta opcion permite usar una conexion web segura\n\tEdite su archivo y agregue listen 443 ssl, ademas de sus certificados\n")
    else: print "No tienes nginx"
    #wordpress
    wordpress = commands.getoutput("grep \"-q PATTERN /var/www/html/wordpress/wp-config.php\" ")
    wpconfing ="/var/www/html/wordpress/wp-config.php"
    if wordpress:
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+wpconfing+"\n")
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("\nreadme.html \n")
        read="/var/www/html/wordpress/readme.html"
        if read: reportFile.write("\tEl tener este archivo te expone a que puedan observar la version de tu wordpress\n\tElimina el archivo readme.html\n")
        else: reportFile.write("\tNo readme.html -correcto\n")
        reportFile.write("\nauto_updates \n")
        upd=commands.getoutput("grep -i \"auto_update_core\" "+wpconfing+" | awk '{print $2}'")
        if upd=="\'auto_update_core\',": 
            reportFile.write("\tauto_update_core -correct\n")
        else: reportFile.write("\tEste parametro permite tener actualizacaciones automaticas del core de wordpress\n\tEdita tu archuivo y agrega add_filter( 'auto_update_core', '__return_true' );")
        upp=commands.getoutput("grep -i \"auto_update_plugin\" "+wpconfing+" | awk '{print $2}'")
        if upp=="\'auto_update_plugin\',": 
            reportFile.write("\tauto_update_plugin -correct\n")
        else: reportFile.write("\tEste parametro permite tener actualizacaciones automaticas del core de wordpress\n\tEdita tu archuivo y agrega add_filter( 'auto_update_plugin', '__return_true' );")
        upt=commands.getoutput("grep -i \"auto_update_theme\" "+wpconfing+" | awk '{print $2}'")
        if upt=="\'auto_update_theme\',": 
            reportFile.write("\tauto_update_theme -correct\n")
        else: reportFile.write("\tEste parametro permite tener actualizacaciones automaticas del core de wordpress\n\tEdita tu archuivo y agrega add_filter( 'auto_update_theme', '__return_true' );")
    else: print "No tienes archivo de configuracion de wordpress"

def checkingMYSQL(mysqlFile, reportFile):
    my="/etc/my.cnf"
    com = commands.getoutput("ls "+my)
    sql="/etc/mysql/my.cnf"
    sqls=commands.getoutput("ls "+sql)
    if com=="/etc/my.cnf":
        print "Analizando "+ mysqlFile
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+mysqlFile+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+mysqlFile+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+mysqlFile+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+mysqlFile+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n")
        bind = commands.getoutput("grep \"^bind-address\" "+mysqlFile+" | cut -d" " -f 3")
        reportFile.write("\nbind-address \n")
        if bind == "127.0.0.1":
            reportFile.write("\tbind-address - correct\n")
        else: reportFile.write("\tLa configuracion de este parametro asegura que no se acepten conexiones remotas, si se necesita hacer una conexion remota, configure para hacer ssh tunel\n\tColoce bind-address = 127.0.0.1\n")
        infile = commands.getoutput("grep \"^local-infile\" "+mysqlFile+" | cut -d" " -f 3")
        reportFile.write("\nlocal-infile \n")
        if infile == "0":
            reportFile.write("\tbind-address - correct\n")
        else: reportFile.write("\tMediante estos permisos se pueden leer ficheros del sistema operativo desde la base de datos, algo comun cuando se explota una inyeccion de codigo SQL.\n\t Para deshabilitar esta funcion se configura la variable local-infile a 0\n")
        glogfile = commands.getoutput("grep \"general_log_file\" "+mysqlFile+"")
        logfile = commands.getoutput("grep \"general_log\" "+mysqlFile+" | cut -d" " -f 3")
        reportFile.write("\ngeneral_log_file\n")
        if glogfile:
            reportFile.write("\tgeneral_log_file - correct\n")
            if logfile=="1":
                reportFile.write("\tgeneral_log - correct\n")
            else: reportFile.write("\tHabilita eneral query log \n\t Para habilitar esta funcion se configura la variable general_log a 1\n")
        else: reportFile.write("\tEspecifica la direccion del archivo donde contendra el log\n\tEspecifica la ruta a log general_log_file = /var/log/mysql/mysql.log\n")
    elif sqls=="/etc/mysql/my.cnf":
        print "Analizando "+ sql
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+sql+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+sql+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+sql+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+sql+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n")
        bind = commands.getoutput("grep \"^bind-address\" "+sql+" | cut -d" " -f 3")
        reportFile.write("\nbind-address \n")
        if bind == "127.0.0.1":
            reportFile.write("\tbind-address - correct\n")
        else: reportFile.write("\tLa configuracion de este parametro asegura que no se acepten conexiones remotas, si se necesita hacer una conexion remota, configure para hacer ssh tunel\n\tColoce bind-address = 127.0.0.1\n")
        infile = commands.getoutput("grep \"^local-infile\" "+sql+" | cut -d" " -f 3")
        reportFile.write("\nlocal-infile \n")
        if infile == "0":
            reportFile.write("\tbind-address - correct\n")
        else: reportFile.write("\tMediante estos permisos se pueden leer ficheros del sistema operativo desde la base de datos, algo comun cuando se explota una inyeccion de codigo SQL.\n\t Para deshabilitar esta funcion se configura la variable local-infile a 0\n")
        glogfile = commands.getoutput("grep \"general_log_file\" "+sql+"")
        logfile = commands.getoutput("grep \"general_log\" "+sql+" | cut -d" " -f 3")
        reportFile.write("\ngeneral_log_file\n")
        if glogfile:
            reportFile.write("\tgeneral_log_file - correct\n")
            if logfile=="1":
                reportFile.write("\tgeneral_log - correct\n")
            else: reportFile.write("\tHabilita eneral query log \n\t Para habilitar esta funcion se configura la variable general_log a 1\n")
        else: reportFile.write("\tEspecifica la direccion del archivo donde contendra el log\n\t Especifica la ruta a log general_log_file = \/var\/log\/mysql\/mysql.log\n")
    else: print "No tienes mysql"


def checkingPOSTGRESQL(psqlFile, reportFile):
    psql = commands.getoutput("ls /etc/postgresql/9.4/main/pg_hba.conf ")
    pgsql="/var/lib/pgsql/data/pg_hba.conf"
    psqls = commands.getoutput("ls /var/lib/pgsql/data/pg_hba.conf")
    confpsql="/var/lib/pgsql/data/postgresql.conf"
    cmconfpsql = commands.getoutput("ls "+confpsql)
    ubupostgres = "/etc/postgresql/9.5/main/postgresql.conf"
    ubucm = commands.getoutput("ls "+ubupostgres)
    if psql=="/etc/postgresql/9.4/main/pg_hba.conf":
        print "Analizando "+ psqlFile
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+psqlFile+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+psqlFile+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+psqlFile+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+psqlFile+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n")    
    elif psqls=="/var/lib/pgsql/data/pg_hba.conf":
        print "Analizando "+ pgsql
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+pgsql+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+pgsql+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+pgsql+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+pgsql+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n") 
        reportFile.write("\nAutenticacion\n")  
        ipv4 = commands.getoutput("grep -i \"^host\" "+pgsql+" | awk '{print $5}'")
        if ipv4!="trust\ntrust":
            reportFile.write("\tAutenticacion -correcto\n")
        else: reportFile.write("\tCambiar el parametro trust por otro medio de autenticacion\n")
        reportFile.write("\nBases de datos y Usuario\n")  
        db = commands.getoutput("grep \"^host\" "+pgsql+" | awk '{print $2}'")
        us = commands.getoutput("grep \"^host\" "+pgsql+" | awk '{print $3}'")
        if db == "all" or us == "all":
            reportFile.write("\tPuedes especificar el nombre de la base de datos que podra ecceder un usuario especifico\n")
        else:
            reportFile.write("\tBD y users - correcto\n")
    else: print "No tienes postgresql-9.4 o esta en otro directorio"
    if cmconfpsql=="/var/lib/pgsql/data/postgresql.conf":
        print "Analizando "+ confpsql
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+confpsql+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+confpsql+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+confpsql+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+confpsql+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n")
        port=commands.getoutput("grep \"^port\" "+confpsql+" | awk '{print $3}' ")
        reportFile.write("\nPuerto \n")
        if port == "5432":
            reportFile.write("\tPuerto por defecto port=5432\n\tPuedes editar tu archivo para cambiar el puerto por defecto\n")
        else:
            reportFile.write("\tport!=5432 -correcto\n")
        lis=commands.getoutput("grep \"listen_addresses\" "+confpsql+" | awk '{print $1}' ")
        lisc=commands.getoutput("grep \"listen_addresses\" "+confpsql+" | awk '{print $3}' ")
        reportFile.write("\nlisten_addresses \n")
        if lis == "#listen_addresses":
            reportFile.write("\tlisten_addresses se encuentra comentado\n\tEdita el archivo para descomentar la linea de listen_addresses\n")
        else:
            reportFile.write("\tlisten_addresses - correcto\n")
        com="\'*\'"
        if lisc == com:
            reportFile.write("\tlisten_addresses = '*' \n\tEdita el archivo para que solo determinandas ips puedan acceder a la base de datos\n")
        else: 
            reportFile.write("\tlisten_addresses - correcto\n")
    elif ubucm == "/etc/postgresql/9.5/main/postgresql.conf":
        print "Analizando "+ ubupostgres
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+ubupostgres+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+ubupostgres+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+ubupostgres+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+ubupostgres+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n")
        port=commands.getoutput("grep \"^port\" "+ubupostgres+" | awk '{print $3}' ")
        reportFile.write("\nPuerto \n")
        if port == "5432":
            reportFile.write("\tPuerto por defecto port=5432\n\tPuedes editar tu archivo para cambiar el puerto por defecto\n")
        else:
            reportFile.write("\tport!=5432 -correcto\n")
        lis=commands.getoutput("grep \"listen_addresses\" "+ubupostgres+" | awk '{print $1}' ")
        lisc=commands.getoutput("grep \"listen_addresses\" "+ubupostgres+" | awk '{print $3}' ")
        reportFile.write("\nlisten_addresses \n")
        if lis == "#listen_addresses":
            reportFile.write("\tlisten_addresses se encuentra comentado\n\tEdita el archivo para descomentar la linea de listen_addresses\n")
        else:
            reportFile.write("\tlisten_addresses - correcto\n")
        com="\'*\'"
        if lisc == com:
            reportFile.write("\tlisten_addresses = '*' \n\tEdita el archivo para que solo determinandas ips puedan acceder a la base de datos\n")
        else: 
            reportFile.write("\tlisten_addresses - correcto\n")

    else: print "No se encuentra el archivo de configuracion postgresql.conf"
def checkingPHP(phpFile, reportFile):
    phpc="/etc/php.ini"
    cphp=commands.getoutput("ls "+phpc)
    ub16="/etc/php/7.0/cli/php.ini"
    ub16c = commands.getoutput("ls "+ub16)
    ubu14 = commands.getoutput("ls "+phpFile)
    if ubu14 == "/etc/php5/cli/php.ini":
        print "Analizando "+ phpFile
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+phpFile+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+phpFile+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+phpFile+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+phpFile+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n") 
        reportFile.write("\nallow_fopen_url \n")  
        alw = commands.getoutput("grep -i \"allow_url_fopen\" "+phpFile+" | awk '{print $3}'")
        if alw=="Off":
            reportFile.write("\tallow_url_fopen -correcto\n")
        else: reportFile.write("\tCon este paramtro habilitado, permite url remotas\n\tEdite su archivo allow_url_fopen=Off\n")
        reportFile.write("\nmax_input_time\n")  
        maxi = commands.getoutput("grep -i \"^max_input_time\" "+phpFile+" | awk '{print $3}'")
        if maxi<='30':
            reportFile.write("\tmax_input_time -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tiempo para procesar entradas que un script PHP pueda ejecutar\n\tEdite su archivo max_input_time = 30\n")
        reportFile.write("\nmax_execution_time\n")  
        maxc = commands.getoutput("grep -i \"^max_execution_time\" "+phpFile+" | awk '{print $3}'")
        if maxc<='30':
            reportFile.write("\tmax_execution_time -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tiempo para procesar entradas que un script PHP pueda ejecutar\n\tEdite su archivo max_execution_time = 30\n")
        reportFile.write("\nmemory_limit\n")  
        meml = commands.getoutput("grep -i \"^memory_limit\" "+phpFile+" | awk '{print $3}'")
        if meml == '8M':
            reportFile.write("\tmemory_limit = 8M -correcto\n")
        else: reportFile.write("\tCon este parametro se limita la memoria que puede ocupar un script\n\tEdite su archivo memory_limit = 8M\n")
        reportFile.write("\nexpose_php\n")  
        ephp = commands.getoutput("grep -i \"^expose_php\" "+phpFile+" | awk '{print $3}'")
        if ephp == 'Off':
            reportFile.write("\texpose_php -correcto\n")
        else: reportFile.write("\tCon este parametro habilitado se da a conocer la version de php que se tiene\n\tEdite su archivo expose_php = Off\n")
        reportFile.write("\npost_max_size\n")  
        postm = commands.getoutput("grep -i \"^post_max_size\" "+phpFile+" | awk '{print $3}'")
        if postm == '256K':
            reportFile.write("\tpost_max_size = 256K -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tamanio de las peticiones que se hagan, tome en cuenta el parametro upload_max_filesize\n\tEdite su archivo post_max_size = 256K\n")
        reportFile.write("\nmax_input_vars\n") 
        maxinv = commands.getoutput("grep -i \"max_input_vars\" "+phpFile+" | awk '{print $1}'")
        if maxinv == ';':
            reportFile.write("\tEste parametro limita el numero de variables de los metodos http que aceptara\n\tEdite su archivo descomentado la linea max_input_vars = 1000\n")
        else: reportFile.write("\tEste parametro limita el numero de variables de los metodos http que aceptara\n\tEdite su archivo descomentado la linea max_input_vars = 1000\n")
        reportFile.write("\ndisplay_errors\n")  
        de = commands.getoutput("grep -i \"^display_errors\" "+phpFile+" | awk '{print $3}'")
        if de == 'Off':
            reportFile.write("\tdisplay_errors -correcto\n")
        else: reportFile.write("\tCon este parametro evita que se muestren los errores\n\tEdite su archivo display_errors = Off\n")
        reportFile.write("\ndisplay_startup_errors\n")  
        dise = commands.getoutput("grep -i \"^display_startup_errors\" "+phpFile+" | awk '{print $3}'")
        if dise == 'Off':
            reportFile.write("\tdisplay_errors -correcto\n")
        else: reportFile.write("\tCon este parametro evita que se muestren los errores\n\tEdite su archivo display_startup_errors = Off\n")
        reportFile.write("\nlog_errors \n")  
        log = commands.getoutput("grep -i \"^log_errors\" "+phpFile+" | awk '{print $3}'")
        if log == 'On':
            reportFile.write("\tlog_errors  -correcto\n")
        else: reportFile.write("\tCon este parametro habilita el log\n\tEdite su archivo log_errors = On\n")
        reportFile.write("\nerror_log \n")  
        erl = commands.getoutput("grep -i \"error_log\" "+phpFile+" | awk '{print $1}'")
        if erl == ';':
            reportFile.write("\tEste parametro se especifica la ruta del log\n\tEdite su archivo descomentado la linea error_log\n")
        else: reportFile.write("\terror_log -correcto\n")
        reportFile.write("\nsession.cookie_httponly\n")  
        ck = commands.getoutput("grep -i \"^session.cookie_httponly\" "+phpFile+" | awk '{print $3}'")
        if ck == '1':
            reportFile.write("\tsession.cookie_httponly -correcto\n")
        else: reportFile.write("\tEste parametro ayuda a prevenir XSS\n\tEdite su archivo session.cookie_httponly = 1\n")
        
    elif cphp=="/etc/php.ini":
        print "\nAnalizando "+ phpc
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+phpc+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+phpc+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+phpc+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+phpc+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n") 
        reportFile.write("\nallow_fopen_url \n")  
        alw = commands.getoutput("grep -i \"allow_url_fopen\" "+phpc+" | awk '{print $3}'")
        if alw=="Off":
            reportFile.write("\tallow_url_fopen -correcto\n")
        else: reportFile.write("\tCon este paramtro habilitado, permite url remotas\n\tEdite su archivo allow_url_fopen=Off\n")
        reportFile.write("\nmax_input_time\n")  
        maxi = commands.getoutput("grep -i \"^max_input_time\" "+phpc+" | awk '{print $3}'")
        if maxi<='30':
            reportFile.write("\tmax_input_time -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tiempo para procesar entradas que un script PHP pueda ejecutar\n\tEdite su archivo max_input_time = 30\n")
        reportFile.write("\nmax_execution_time\n")  
        maxc = commands.getoutput("grep -i \"^max_execution_time\" "+phpc+" | awk '{print $3}'")
        if maxc<='30':
            reportFile.write("\tmax_execution_time -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tiempo para procesar entradas que un script PHP pueda ejecutar\n\tEdite su archivo max_execution_time = 30\n")
        reportFile.write("\nmemory_limit\n")  
        meml = commands.getoutput("grep -i \"^memory_limit\" "+phpc+" | awk '{print $3}'")
        if meml == '8M':
            reportFile.write("\tmemory_limit = 8M -correcto\n")
        else: reportFile.write("\tCon este parametro se limita la memoria que puede ocupar un script\n\tEdite su archivo memory_limit = 8M\n")
        reportFile.write("\nexpose_php\n")  
        ephp = commands.getoutput("grep -i \"^expose_php\" "+phpc+" | awk '{print $3}'")
        if ephp == 'Off':
            reportFile.write("\texpose_php -correcto\n")
        else: reportFile.write("\tCon este parametro habilitado se da a conocer la version de php que se tiene\n\tEdite su archivo expose_php = Off\n")
        reportFile.write("\npost_max_size\n")  
        postm = commands.getoutput("grep -i \"^post_max_size\" "+phpc+" | awk '{print $3}'")
        if postm == '256K':
            reportFile.write("\tpost_max_size = 256K -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tamanio de las peticiones que se hagan, tome en cuenta el parametro upload_max_filesize\n\tEdite su archivo post_max_size = 256K\n")
        reportFile.write("\nmax_input_vars\n") 
        maxinv = commands.getoutput("grep -i \"max_input_vars\" "+phpc+" | awk '{print $1}'")
        if maxinv == ';':
            reportFile.write("\tEste parametro limita el numero de variables de los metodos http que aceptara\n\tEdite su archivo descomentado la linea max_input_vars = 1000\n")
        else: reportFile.write("\tEste parametro limita el numero de variables de los metodos http que aceptara\n\tEdite su archivo descomentado la linea max_input_vars = 1000\n")
        reportFile.write("\ndisplay_errors\n")  
        de = commands.getoutput("grep -i \"^display_errors\" "+phpc+" | awk '{print $3}'")
        if de == 'Off':
            reportFile.write("\tdisplay_errors -correcto\n")
        else: reportFile.write("\tCon este parametro evita que se muestren los errores\n\tEdite su archivo display_errors = Off\n")
        reportFile.write("\ndisplay_startup_errors\n")  
        dise = commands.getoutput("grep -i \"^display_startup_errors\" "+phpc+" | awk '{print $3}'")
        if dise == 'Off':
            reportFile.write("\tdisplay_errors -correcto\n")
        else: reportFile.write("\tCon este parametro evita que se muestren los errores\n\tEdite su archivo display_startup_errors = Off\n")
        reportFile.write("\nlog_errors \n")  
        log = commands.getoutput("grep -i \"^log_errors\" "+phpc+" | awk '{print $3}'")
        if log == 'On':
            reportFile.write("\tlog_errors  -correcto\n")
        else: reportFile.write("\tCon este parametro habilita el log\n\tEdite su archivo log_errors = On\n")
        reportFile.write("\nerror_log \n")  
        erl = commands.getoutput("grep -i \"error_log\" "+phpc+" | awk '{print $1}'")
        if erl == ';':
            reportFile.write("\tEste parametro se especifica la ruta del log\n\tEdite su archivo descomentado la linea error_log\n")
        else: reportFile.write("\terror_log -correcto\n")
        reportFile.write("\nsession.cookie_httponly\n")  
        ck = commands.getoutput("grep -i \"^session.cookie_httponly\" "+phpc+" | awk '{print $3}'")
        if ck == '1':
            reportFile.write("\tsession.cookie_httponly -correcto\n")
        else: reportFile.write("\tEste parametro ayuda a prevenir XSS\n\tEdite su archivo session.cookie_httponly = 1\n")
        
    elif ub16c == "/etc/php/7.0/cli/php.ini":
        print "Analizando "+ ub16
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+ub16+"\n")
        reportFile.write("_____________________________________________________________________\n")
        permisos = commands.getoutput("stat "+ub16+" | grep -i access | head -1       | cut -d' ' -f2")
        owner = commands.getoutput("stat "+ub16+" | grep -i access | head -1  |  sed 's/ //g'")
        reportFile.write("\nPermisos y propietario \n")
        if "Uid:(0/root)Gid:(0/root)" in owner:
            reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
        else: reportFile.write("\tEjecute  chown root:root "+ub16+ "para cambiar el propietario\n")
        if "(0600/-rw-------)" in permisos:
            reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
        else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n") 
        reportFile.write("\nallow_fopen_url \n")  
        alw = commands.getoutput("grep -i \"allow_url_fopen\" "+ub16+" | awk '{print $3}'")
        if alw=="Off":
            reportFile.write("\tallow_url_fopen -correcto\n")
        else: reportFile.write("\tCon este paramtro habilitado, permite url remotas\n\tEdite su archivo allow_url_fopen=Off\n")
        reportFile.write("\nmax_input_time\n")  
        maxi = commands.getoutput("grep -i \"^max_input_time\" "+ub16+" | awk '{print $3}'")
        if maxi<='30':
            reportFile.write("\tmax_input_time -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tiempo para procesar entradas que un script PHP pueda ejecutar\n\tEdite su archivo max_input_time = 30\n")
        reportFile.write("\nmax_execution_time\n")  
        maxc = commands.getoutput("grep -i \"^max_execution_time\" "+ub16+" | awk '{print $3}'")
        if maxc<='30':
            reportFile.write("\tmax_execution_time -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tiempo para procesar entradas que un script PHP pueda ejecutar\n\tEdite su archivo max_execution_time = 30\n")
        reportFile.write("\nmemory_limit\n")  
        meml = commands.getoutput("grep -i \"^memory_limit\" "+ub16+" | awk '{print $3}'")
        if meml == '8M':
            reportFile.write("\tmemory_limit = 8M -correcto\n")
        else: reportFile.write("\tCon este parametro se limita la memoria que puede ocupar un script\n\tEdite su archivo memory_limit = 8M\n")
        reportFile.write("\nexpose_php\n")  
        ephp = commands.getoutput("grep -i \"^expose_php\" "+ub16+" | awk '{print $3}'")
        if ephp == 'Off':
            reportFile.write("\texpose_php -correcto\n")
        else: reportFile.write("\tCon este parametro habilitado se da a conocer la version de php que se tiene\n\tEdite su archivo expose_php = Off\n")
        reportFile.write("\npost_max_size\n")  
        postm = commands.getoutput("grep -i \"^post_max_size\" "+ub16+" | awk '{print $3}'")
        if postm == '256K':
            reportFile.write("\tpost_max_size = 256K -correcto\n")
        else: reportFile.write("\tCon este parametro se limita el tamanio de las peticiones que se hagan, tome en cuenta el parametro upload_max_filesize\n\tEdite su archivo post_max_size = 256K\n")
        reportFile.write("\nmax_input_vars\n") 
        maxinv = commands.getoutput("grep -i \"max_input_vars\" "+ub16+" | awk '{print $1}'")
        if maxinv == ';':
            reportFile.write("\tEste parametro limita el numero de variables de los metodos http que aceptara\n\tEdite su archivo descomentado la linea max_input_vars = 1000\n")
        else: reportFile.write("\tEste parametro limita el numero de variables de los metodos http que aceptara\n\tEdite su archivo descomentado la linea max_input_vars = 1000\n")
        reportFile.write("\ndisplay_errors\n")  
        de = commands.getoutput("grep -i \"^display_errors\" "+ub16+" | awk '{print $3}'")
        if de == 'Off':
            reportFile.write("\tdisplay_errors -correcto\n")
        else: reportFile.write("\tCon este parametro evita que se muestren los errores\n\tEdite su archivo display_errors = Off\n")
        reportFile.write("\ndisplay_startup_errors\n")  
        dise = commands.getoutput("grep -i \"^display_startup_errors\" "+ub16+" | awk '{print $3}'")
        if dise == 'Off':
            reportFile.write("\tdisplay_errors -correcto\n")
        else: reportFile.write("\tCon este parametro evita que se muestren los errores\n\tEdite su archivo display_startup_errors = Off\n")
        reportFile.write("\nlog_errors \n")  
        log = commands.getoutput("grep -i \"^log_errors\" "+ub16+" | awk '{print $3}'")
        if log == 'On':
            reportFile.write("\tlog_errors  -correcto\n")
        else: reportFile.write("\tCon este parametro habilita el log\n\tEdite su archivo log_errors = On\n")
        reportFile.write("\nerror_log \n")  
        erl = commands.getoutput("grep -i \"error_log\" "+ub16+" | awk '{print $1}'")
        if erl == ';':
            reportFile.write("\tEste parametro se especifica la ruta del log\n\tEdite su archivo descomentado la linea error_log")
        else: reportFile.write("\terror_log -correcto\n")
        reportFile.write("\nsession.cookie_httponly\n")  
        ck = commands.getoutput("grep -i \"^session.cookie_httponly\" "+ub16+" | awk '{print $3}'")
        if ck == '1':
            reportFile.write("\tsession.cookie_httponly -correcto\n")
        else: reportFile.write("\tEste parametro ayuda a prevenir XSS\n\tEdite su archivo session.cookie_httponly = 1")
    else: print "no tienes php o esta en otro directorio"

if __name__ == '__main__':
    reload(sys)
    sys.setdefaultencoding("utf8")
    parser = addOptions()
    opts, args = parser.parse_args()
    checkOptions(opts)
    reportFile = opts.out
    configFile = opts.config

    try:
        report = open(opts.out,'w')
        loadConfig(configFile)
        if opts.service == "all":
            checkingSSH(sshFile, report)
        else:
            for s in opts.service.split(','):
                if s == "ssh":
                    checkingSSH(sshFile, report)
                if s == "web":
                    checkingWEB(webFile, report)
                if s == "php":
                    checkingPHP(phpFile, report)
                if s == "mysql":
                    checkingMYSQL(mysqlFile, report)
                if s == "postgresql":
                    checkingPOSTGRESQL(psqlFile, report)
        report.close()
    except Exception as e:
        print(e)
