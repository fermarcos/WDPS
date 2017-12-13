#!/usr/bin/python
# -*- coding: utf-8 -*-

import optparse
import sys
import os.path
import re
import commands
report_file = ''


#Class to manage the color for printing.
class color:
    Red='\033[0;31m'          # Red
    Green='\033[0;32m'        # Green
    Yellow='\033[0;33m'       # Yellow
    Purple='\033[0;35m'       # Purple
    Cyan='\033[0;36m'         # Cyan
    Color_off = '\033[0m'
    Bold = '\033[1m'
    Underline = '\033[4m'

#Print the banner on the screen
def banner():                                                  
    print color.Cyan+"""\n\n             MMMMMMMMMMMMMMMMMMMMMMMMM                  
       MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM            
     MMMMMMMMMMMMMMM           MMMMMMMMMMMMMMM        
     MMMMMM       MMMM       MMMM       MMMMMM         
     M         MMMMMMMM    MMMMMMMMM                    
      MMMMM      MMMMMM    MMMMM        MMMMM           
    MMMMMMMM       MMMM   MMMMMM       MMMMMMMM         
    MMMMMMMM      MMMMMM  MMMMMMMM     MMMMMMMM         
    MMMMMMMMMMMMMMMMM         MMMMMMMMMMMMMMMMM         
    MMMMMMMMMMMMMMM             MMMMMMMMMMMMMMM         
    MMMMMMMMMMMMM   MMMMMMMMMMM   MMMMMMMMMMMMM         
    MMMMMMMMMMMM   MMM MMMMM MMM   MMMMMMMMMMMM         
    MMMMMMMMMMM  MMM       MM  MMM  MMMMMMMMMMM         
    MMMMMMMMMM   MMM       MMM MMM   MMMMMMMMMM         
    MMMMMMMMMM  MMMMM         MMMMM  MMMMMMMMMM         
    MMMMMMMMMM  MMMMMM          MMM  MMMMMMMMMM         
    MMMMMMMMMM  MMMMM  MM       MMM  MMMMMMMMMM         
    MMMMMMMMMM   MMM  MM  MM    MM   MMMMMMMMMM         
    MMMMMMMMMMM  MMM MM MMMMMMMMM   MMMMMMMMMMM         
    MMMMMMMMMMMM   MMMMMMMMMMMMM   MMMMMMMMMMMM         
                     MMMMMMMMM                          
                                                        
    M       M  MM      M     MM      M       M          
    M       M  M M     M     MM     MMM     MM          
    M       M  M  MM   M    M  M    M M    M M          
    M       M  M    M  M   MMMMMM   M  M  M  M          
     M     M   M     MMM  M     MM  M   MM   M         
      M M M    M       M  M      M  M        M         
                                                        
       MMMM      MMMMM      MMMM       MMMMMMMM        
    MM           M          M    M        MM           
    M            M          M    M        MM           
   MM            MMMM       M M           MM           
    M            M          M  MM         MM           
      MMMMMM     MMMMM      M    M        MM


                confAnalyCERT v1.0\n\n\n\n"""+color.Color_off



#Writes in standard error a message. By default, the script will be ended
def printError(message, exit = True):
    sys.stderr.write(color.Red+color.Bold+"Error: %s\n" % message+color.Color_off)
    if exit:
        sys.exit(1)

#This function can add "n" options to parse from command line
def addOptions():
    parser = optparse.OptionParser()
    parser.add_option('-c','--config-file', dest='config', default=None, help='Configuration file for the script.')
    parser.add_option('-o','--output', dest='output', default='report.txt', help='Name for the report file.')
    opts,args = parser.parse_args()
    return opts

#Checks if the file exists. It can end the script by the "printError" function
def fileExists(f, exit = True):
    if not os.path.isfile(f):
        printError('The file %s does not exist.' % f, exit)
        return False
    return True
    
#Reads from the configuration file all the keys that are in the dictionary.
def readConfigFile(config_file):
    if config_file is not None:
        fileExists(config_file)
        paths = {'ssh_server':'', 
                'apache_conf': '',
                'apache_security':'',
                'apache_ssl':'',
                'php':'',
                'mysql_server':'',
                'nginx_conf':'',
                'psql_server':'',
                'psql_hba':'',
                'web_sites':''}
        with open(config_file, 'r') as conf:
            for line in conf.readlines():
                line = line.strip()
                if re.match(r'^\s*$', line): continue #Ignores empty lines
                if line[0] == '#': continue #Ignores commented lines
                option = map(lambda x: x.strip(), line.split('=', 1)) #Splits the line using '=' as separator
                if option[0] in paths.keys():
                    paths[option[0]] = option[1]
                else:
                    printError('Wrong option in configuration file (%s).' % option[0])
            return paths
    else:
        printError('You must specify a configuration file to run the script.')



#Gets the dictionary of the files that DO exist
def getExistingFiles(paths):
    return filter(lambda x: fileExists(paths[x], False), paths)



def parseApacheConf(apaches,reportFile,sitesPath):
    contentFile = commands.getoutput("grep -v  '^#\|^$' " + apaches)
    print color.Cyan+"Analizando "+ apaches +color.Color_off
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+apaches+"\n")
    reportFile.write("_____________________________________________________________________\n")
    permisos = commands.getoutput("stat "+apaches+" | grep -i access | head -1       | cut -d' ' -f2")
    owner = commands.getoutput("stat "+apaches+" | grep -i access | head -1  |  sed 's/ //g'")
    #Revision permisos y propietarios
    reportFile.write("\nPermisos y propietario \n")
    if "Uid:(0/root)Gid:(0/root)" in owner:
        reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
    else: reportFile.write("\tEjecute  chown root:root "+apaches+ "para cambiar el propietario\n")
    if "(0644/-rw-r--r--)" in permisos:
        reportFile.write("\tPermisos correctos (0644/-rw-r--r--)\n")
    else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 644 /etc/httpd/conf/httpd.conf para cambiarlos\n")
    #Revision server signature
    reportFile.write("\nServer Signature \n")
    signature = re.search("(ServerSignature)\s+(\w+)", contentFile)
    if signature is not None and signature.group(2) == "Off":
        reportFile.write("\tServerSignature Off - correcto\n")
    else:
        reportFile.write("\tLa configuracion de este parametro permite ver la version del servicio web que tiene. \n\tEdite su archivo de configuracion con ServerSignature Off y ServerTokens Prod\n")
    #Revision de ServerTokens
    reportFile.write("\nServer Tokens\n")
    token = re.search("(ServerTokens)\s+(\w+)", contentFile)
    if token is not None and token.group(2) == "Prod":
        reportFile.write("\tServerTokens Prod - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite ver la version del servicio web que tiene. \n\tEdite su archivo de configuracion con ServerSignature Off y ServerTokens Prod\n")
    

    directory = commands.getoutput("awk '/^<Directory*/,/^<\/Directory>/{if(!/^($|\t*#)/) print $_}' "+apaches)
    d = "Directory>"
    s =  [e+d for e in directory.split(d) if e]
    for i in s: 
        for line in i.split("\n"):
            if re.match("<Directory", line): 
                print color.Cyan+"Analizando: "+line+color.Color_off
                reportFile.write("\nAnalizando: "+line+'\n'+'-'*20)
        #print i+"____________________"
        indexes = re.search("(.*Options)\s+(\w+.*)", i)

        if indexes is not None : 
            #Revision de options Indexes
            reportFile.write("\nOptions Indexes \n")
            print indexes.group(2)
            if "-Indexes" in indexes.group(2):
                reportFile.write("\tOptions -Indexes - correcto\n")
            else: 
                reportFile.write("\tLa configuracion de este parametro permite ver listar lo que contiene el directorio. \n\tEdite su archivo de configuracion con Options -Indexes \n")
            #Revision Options FollowSymlinks
            reportFile.write("\nOptions FollowSymLinks \n")
            if "-FollowSymLinks" in indexes.group(2):
                reportFile.write("\tOptions -FollowSymLinks - correcto\n")
            else: 
                reportFile.write("\tLa configuracion de este parametro permite los enlace simbolicos. \n\tEdite su archivo de configuracion con Options -FollowSymLinks, puede habilitarlo mediante el archivo .htaccess  \n")    

    #Revision KeepAlive
    reportFile.write("\nKeepAlive \n")
    alive = re.search("(KeepAlive)\s+(\w+)", contentFile)
    if alive is not None and alive.group(2) == "On":
        reportFile.write("\tKeepAlive On - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite habilitar el tiempo de peticiones al servidor. \n\tEdite su archivo de configuracion con KeepAlive On\n")
    #Revision time out
    reportFile.write("\nKeepAliveTimeout \n")
    time = re.search("(KeepAliveTimeout)\s+(\d+)", contentFile)
    if time is not None and int(time.group(2)) <= 4:
        reportFile.write("\tKeepAlive 4 - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite limitar el numero de segundos que se puede tardar una pagina en cargar. \n\tEdite su archivo de configuracion con KeepAliveTimeout de 2 a 4\n")
    
    #Se comprueba la ecistencia del directorio de sitios habilitados
    if os.path.isdir(sitesPath):
        directorio = "/etc/apache2/sites-enabled/"
        #Se obtienen los archivos de configuracion de cada sitio    
        sitesFiles = [f for f in os.listdir(directorio) if os.path.isfile(os.path.join(directorio, f))]
        for fa in sitesFiles:
            reportFile.write("_____________________________________________________________________\n")
            reportFile.write("Analizando "+directorio+fa+"\n")
            reportFile.write("_____________________________________________________________________\n")
            reportFile.write("\nDirectory \n")
            virtual_hosts = commands.getoutput("awk '/^<VirtualHost*/,/^<\/VirtualHost>/{if(!/^($|\t*#)/) print $_}' "+directorio+fa)
            d = "VirtualHost>"
            s =  [e+d for e in virtual_hosts.split(d) if e]
            for i in s: 
                for line in i.split("\n"):
                    if re.match("<VirtualHost", line): print color.Cyan+"Analizando: "+line+color.Color_off
                #print i+"____________________"
                indexes = re.search("(.*Options)\s+(\w+.*)", i)
                if indexes is not None:
                    #Revision Options
                    reportFile.write("\nOptions None \n")
                    if "None" in indexes.group(2):
                        print "\t\tOptions None -correct \n"
                    else:
                        print "\t\tEsta opcion no permitira a los usuarios activar ninguna caracteristica opcional\n\t\tEdite su archivo y en la etiqueta de Directory agregue Options None\n"

                    #Revision indexes
                    reportFile.write("\nOptions Indexes \n")
                    if "-Indexes" in indexes.group(2):
                        reportFile.write("\tOptions -Indexes - correcto\n")
                    else: 
                        reportFile.write("\tLa configuracion de este parametro permite listar lo que contiene el directorio. \n\tPara evitar esto, edite su archivo de configuracion con Options -Indexes \n")

                #Revision Order deny,allow
                reportFile.write("\n\tOrder deny,allow \n")
                order =  re.search("(.*Order)\s+(\w+.*)", i)
                if order is not None and  "deny,allow" in order.group(2):    
                    reportFile.write("\t\tOrder deny,allow -correct \n")
                else: 
                    reportFile.write("\t\tEste es el orden en que se procesaran las directivas \"Denegar\" y \"Permitir\". Aqui va a \"negar\" primero y \"permitir\" a continuacion.\n\t\tEdite su archivo y en la etiqueta de Directory agregue Order deny,allow\n")
                
                #Revision Deny from all
                reportFile.write("\n\tDeny from all\n")
                denf = re.search("(.*Deny from all.*)", i)
                #denf = commands.getoutput("grep \"Deny from all\" "+directorio+fa)
                if denf is not None:
                    reportFile.write("\t\tDeny from all -correct \n")
                else: 
                    reportFile.write("\t\tEsto denegara la solicitud de todo el mundo al directorio en cuestion, nadie podra acceder a tal directorio.\n\t\tEdite su archivo y en la etiqueta de Directory agregue Deny from all\n")
            
                #Revision LimitRequestBody
                reportFile.write("\nLimitRequestBody \n")
                limit = re.search("(.*LimitRequestBody)\s+(\d+.*)", i)
                #limit = commands.getoutput("grep \"\LimitRequestBody\" "+directorio+fa)
                if limit is not None:
                    reportFile.write("\tLimitRequestBody - correcto\n")
                else: 
                    reportFile.write("\tLa configuracion de este parametro permite limitar las peticiones que se puedan realizar. \n\tEdite su archivo de configuracion con LimitRequestBody 512000 [Este numero es de acuerdo a tus necesidades]\n")

def parseApacheSecurity(apache_file):
    print "ANALIZYNG APACHE SECURITY"
                       
def parseApacheSsl(apache_ssl,reportFile):
    contentFile = commands.getoutput("grep -v  '^#\|^$' " + apache_ssl)
    print color.Cyan+"Analizando "+ apache_ssl +color.Color_off
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+apache_ssl+"\n")
    reportFile.write("_____________________________________________________________________\n")
    permisos = commands.getoutput("stat "+apache_ssl+" | grep -i access | head -1       | cut -d' ' -f2")
    owner = commands.getoutput("stat "+apache_ssl+" | grep -i access | head -1  |  sed 's/ //g'")
    #Revision permisos y propietarios
    reportFile.write("\nPermisos y propietario \n")
    if "Uid:(0/root)Gid:(0/root)" in owner:
        reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
    else: reportFile.write("\tEjecute  chown root:root "+apache_ssl+ "para cambiar el propietario\n")
    if "(0644/-rw-r--r--)" in permisos:
        reportFile.write("\tPermisos correctos (0644/-rw-r--r--)\n")
    else: reportFile.write("\tPermisos: "+apache_ssl+ " Incorrectos\n\tEjecute:  chmod 644 /etc/httpd/conf/httpd.conf para cambiarlos\n")
    print contentFile



def parseSshServer(sshFile, reportFile):
    print color.Cyan+"Analizando "+sshFile+color.Color_off
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+sshFile+"\n")
    reportFile.write("_____________________________________________________________________\n")
    contentFile = commands.getoutput("grep -v  '^#\|^$' " + sshFile)
    permisos = commands.getoutput("stat "+sshFile+" | grep -i access | head -1       | cut -d' ' -f2")
    owner = commands.getoutput("stat "+sshFile+" | grep -i access | head -1  |  sed 's/ //g'")
    #Revision de permisos y propietario
    reportFile.write("\nPermisos y propietario \n")
    if "Uid:(0/root)Gid:(0/root)" in owner:
        reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
    else: reportFile.write("\tEjecute  chown root:root "+sshFile+ "para cambiar el propietario\n")
    if "(0600/-rw-------)" in permisos:
        reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
    else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod og-rwx /etc/ssh/sshd_config para cambiarlos\n")
    #Revision de protocolos
    reportFile.write("\nProtocolo SSH \n")
    proto = re.search("(Protocol)\s+(\d)", contentFile)
    if proto is not None and proto.group(2) == '2':
        reportFile.write("\tVersion 2 - correcto\n")
    else: 
        reportFile.write("\tSSH v1 sufre de inseguridades que no afectan a SSH v2. \n\tEdite su archivo de configuracion a Protocol 2 \n")
    #Revision de loglevel
    reportFile.write("\nLogLevel SSH \n")
    logLevel = re.search("(LogLevel)\s+(\w+)", contentFile)
    if logLevel is not None and logLevel.group(2) == "INFO":
        reportFile.write("\tLogLevel INFO - correcto\n")
    else: 
        reportFile.write("\tRegistra la actividad de inicio de sesion de los usuarios de SSH. \n\tEdite su archivo de configuracion con LogLevel INFO \n")
    #Revision X11 Forwarding
    reportFile.write("\nX11Forwarding \n")
    X11 = re.search("(X11Forwarding)\s+(\w+)", contentFile)
    if X11 is not None and X11.group(2) == "no":
        reportFile.write("\X11Forwarding no - correcto\n")
    else: 
        reportFile.write("\tDeshabilite el reenvio de X11 a menos que exista un requisito operacional para usar las aplicaciones X11 directamente. \n\tEdite su archivo de configuracion con X11Forwarding no \n")
    #Revision maximos intentos fallidos
    reportFile.write("\nMaxAuthTries \n")
    auth = re.search("(MaxAuthTries)\s+(\d+)", contentFile)
    if auth is not None and int(auth.group(2)) <= 4:
        reportFile.write("\tMaxAuthTries 4 o menos - correcto\n")
    else: 
        reportFile.write("\tSe recomienda un establecer un limite de intentos minimo de 4 \n\tEdite su archivo de configuracion con MaxAuthTries 4 \n")
    #Revision ignore Rhosts
    reportFile.write("\nIgnoreRhosts \n")
    ignore = re.search("(IgnoreRhosts)\s+(\w+)", contentFile)
    if ignore is not None and ignore.group(2) == "yes":
        reportFile.write("\tIgnoreRhosts yes - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro obliga a los usuarios a introducir una contrasena al autenticar con ssh. \n\tEdite su archivo de configuracion con IgnoreRhosts yes \n")
    #Revision hostbased authentication
    reportFile.write("\nHostbasedAuthentication \n")
    hostBased = re.search("(HostbasedAuthentication)\s+(\w+)", contentFile)
    if hostBased is not None and hostBased.group(2) == "no":
        reportFile.write("\tHostbasedAuthentication no - correcto\n")
    else: 
        reportFile.write("\tEl parametro HostbasedAuthentication especifica si se permite la autenticacion a traves de hosts de confianza \n\tEdite su archivo de configuracion con HostbasedAuthentication no \n")
    #Revision de RootLogin
    reportFile.write("\nRootLogin \n")
    root = re.search("(PermitRootLogin)\s+(\w+)", contentFile)
    if root is not None and root.group(2) == "no":
        reportFile.write("\tPermitRootLogin no - correcto\n")
    else: 
        reportFile.write("\tSe recomienda administradores del servidor se autenticen utilizando su propia cuenta individual, y luego se escalen a raiz a traves de sudo o su. \n\tEdite su archivo de configuracion con PermitRootLogin no \n")
    #Revision permit empty password
    reportFile.write("\nPermitEmptyPasswords \n")
    empty = re.search("(PermitEmptyPasswords)\s+(\w+)", contentFile)
    if empty is not None and empty.group(2) == "no":
        reportFile.write("\tPermitEmptyPasswords no - correcto\n")
    else: 
        reportFile.write("\tReduce la probabilidad de acceso no autorizado al sistema. \n\tEdite su archivo de configuracion con PermitEmptyPasswords no \n")
    #Revision opciones de entorno
    reportFile.write("\nEnvironment Options \n")
    userEnv = re.search("(PermitUserEnvironment)\s+(\w+)", contentFile)
    if userEnv is not None and userEnv.group(2) == "no":
        reportFile.write("\tPermitUserEnvironment no - correcto\n")
    else: 
        reportFile.write("\tDeshabilitar ya que le permite a los usuarios presentar opciones de entorno al daemon ssh. \n\tEdite su archivo de configuracion con PermitUserEnvironment no \n")

def parsePhp(phpFile,reportFile):
    print "Analizando "+ phpFile
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+phpFile+"\n")
    reportFile.write("_____________________________________________________________________\n")
    contentFile = commands.getoutput("grep -v  '^;\|^$' " + phpFile)
    #Revision de permisos y propietario
    reportFile.write("\nPermisos y propietario \n")
    permisos = commands.getoutput("stat "+phpFile+" | grep -i access | head -1       | cut -d' ' -f2")
    owner = commands.getoutput("stat "+phpFile+" | grep -i access | head -1  |  sed 's/ //g'")
    if "Uid:(0/root)Gid:(0/root)" in owner:
        reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
    else: 
        reportFile.write("\tEjecute  chown root:root "+phpFile+ "para cambiar el propietario\n")
    if "(0600/-rw-------)" in permisos:
        reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
    else: 
        reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n") 
    #Revision allow from URL
    reportFile.write("\nallow_fopen_url \n") 
    alw = re.search("(allow_url_fopen)\s+=\s(\w+)", contentFile)     
    if alw is not None and alw.group(2)=="Off":
        reportFile.write("\tallow_url_fopen -correcto\n")
    else: 
        reportFile.write("\tCon este paramtro habilitado, permite url remotas\n\tEdite su archivo allow_url_fopen=Off\n")
    #Revision max input time
    reportFile.write("\nmax_input_time\n")  
    maxi = re.search("(max_input_time)\s+=\s(\d+)", contentFile)  
    if  maxi is not None and int(maxi.group(2)) <= 30:
        reportFile.write("\tmax_input_time -correcto\n")
    else: 
        reportFile.write("\tCon este parametro se limita el tiempo para procesar entradas que un script PHP pueda ejecutar\n\tEdite su archivo max_input_time = 30\n")
    #Revision max execution time
    reportFile.write("\nmax_execution_time\n")  
    maxc = re.search("(max_execution_time)\s+=\s(\d+)", contentFile)  
    if maxc is not None and int(maxc.group(2)) <= 30:
        reportFile.write("\tmax_execution_time -correcto\n")
    else: 
        reportFile.write("\tCon este parametro se limita el tiempo para procesar entradas que un script PHP pueda ejecutar\n\tEdite su archivo max_execution_time = 30\n")
    #Revision memory limit
    reportFile.write("\nmemory_limit\n")  
    meml = re.search("(memory_limit)\s+=\s+(-?\d+\w+)", contentFile)
    if meml is not None and meml.group(2) == '8M':
        reportFile.write("\tmemory_limit = 8M -correcto\n")
    else: 
        reportFile.write("\tCon este parametro se limita la memoria que puede ocupar un script\n\tEdite su archivo memory_limit = 8M\n")
    #Revision expose php
    reportFile.write("\nexpose_php\n")  
    ephp = re.search("(expose_php)\s+=\s+(\w+)", contentFile) 
    if ephp is not None and ephp.group(2) == 'Off':
        reportFile.write("\texpose_php -correcto\n")
    else: 
        reportFile.write("\tCon este parametro habilitado se da a conocer la version de php que se tiene\n\tEdite su archivo expose_php = Off\n")
    #Revision mx post
    reportFile.write("\npost_max_size\n")  
    postm = re.search("(post_max_size)\s+=\s+(\w+)", contentFile)
    if postm is not None and  postm.group(2) == '256K':
        reportFile.write("\tpost_max_size = 256K -correcto\n")
    else: 
        reportFile.write("\tCon este parametro se limita el tamanio de las peticiones que se hagan, tome en cuenta el parametro upload_max_filesize\n\tEdite su archivo post_max_size = 256K\n")
    #Revision max input vars
    reportFile.write("\nmax_input_vars\n") 
    maxinv = re.search("(max_input_vars)\s+=\s+(\w+)", contentFile)
    if maxinv is not None and  (maxinv.group(2) == '1K' or maxinv.group(2) == "1000"):
        reportFile.write("\tmax_input_vars = 1000 -correcto\n")
    else: 
        reportFile.write("\tEste parametro limita el numero de variables de los metodos http que aceptara\n\tEdite su archivo descomentado la linea max_input_vars = 1000\n")
    #Revision display errors
    reportFile.write("\ndisplay_errors\n")  
    de = re.search("(display_errors)\s+=\s+(\w+)", contentFile)
    if de is not None and  de == 'Off':
        reportFile.write("\tdisplay_errors -correcto\n")
    else: 
        reportFile.write("\tCon este parametro evita que se muestren los errores\n\tEdite su archivo display_errors = Off\n")
    #Revision display startup errors
    reportFile.write("\ndisplay_startup_errors\n")  
    dise = re.search("(display_startup_errors)\s+=\s+(\w+)", contentFile)
    if dise is not None and dise.group(2) == 'Off':
        reportFile.write("\tdisplay_errors -correcto\n")
    else: 
        reportFile.write("\tCon este parametro evita que se muestren los errores\n\tEdite su archivo display_startup_errors = Off\n")
    #Revision log errors
    reportFile.write("\nlog_errors \n")  
    log = re.search("(log_errors)\s+=\s+(\w+)", contentFile)
    if log is not None and log.group(2) == 'On':
        reportFile.write("\tlog_errors  -correcto\n")
    else: 
        reportFile.write("\tCon este parametro habilita el log\n\tEdite su archivo log_errors = On\n")
    #Revision errorlog
    reportFile.write("\nerror_log \n")  
    erl = re.search("(error_log)\s+=\s+(\w+).*", contentFile)
    if erl is not None:
        reportFile.write("\terror_log -correcto\n")
    else: 
        reportFile.write("\tEste parametro se especifica la ruta del log\n\tEdite su archivo descomentado la linea error_log\n")
    #Revision session cookie
    reportFile.write("\nsession.cookie_httponly\n")  
    ck = re.search("(session\.cookie_httponly)\s+=\s+(\d+)?", contentFile)
    #ck = commands.getoutput("grep -i \"^session.cookie_httponly\" "+phpFile+" | awk '{print $3}'")
    print ck.group()
    if ck.group(2) is not None and ck.group(2) == '1':
        reportFile.write("\tsession.cookie_httponly -correcto\n")
    else: 
        reportFile.write("\tEste parametro ayuda a prevenir XSS\n\tEdite su archivo session.cookie_httponly = 1\n")


def parseMysqlServer(mysqlFile,reportFile):
    print color.Cyan+ "Analizando "+ mysqlFile + color.Color_off
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+mysqlFile+"\n")
    reportFile.write("_____________________________________________________________________\n")
    #Obtener contenido del archivo 
    contentFile = commands.getoutput("grep -v  '^#\|^$' " + mysqlFile)
    #Revision de permisos y propietario
    permisos = commands.getoutput("stat "+mysqlFile+" | grep -i access | head -1       | cut -d' ' -f2")
    owner = commands.getoutput("stat "+mysqlFile+" | grep -i access | head -1  |  sed 's/ //g'")
    reportFile.write("\nPermisos y propietario \n")
    if "Uid:(0/root)Gid:(0/root)" in owner:
        reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
    else: reportFile.write("\tEjecute  chown root:root "+mysqlFile+ "para cambiar el propietario\n")
    if "(0600/-rw-------)" in permisos:
        reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
    else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n")
    #Revision de bind address
    bind = re.search("(bind-address)\s+=\s(.*)", contentFile)
    reportFile.write("\nbind-address \n")
    if bind is not None and bind.group(2) == "127.0.0.1":
        reportFile.write("\tbind-address - correct\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro asegura que no se acepten conexiones remotas, si se necesita hacer una conexion remota, configure para hacer ssh tunel\n\tColoce bind-address = 127.0.0.1\n")
    #Revision de max_connect_errors
    max_con = re.search("(max_connect_errors)\s+=\s+(\d+)", contentFile)
    if max_con is not None and int(max_con.group(2)) <= 5:
        reportFile.write("\tbind-address - correct\n")
    else:
        reportFile.write("\tSe sugiere aplicar el bloquep de host a clientes con muchas autenticaciones fallidas.\n\tConfigure la varuable max_connect_errors con un valor menos o igual a 5. max_connect_errors = 5\n")
    #Revision de skip show-database
    skip_sh = re.search("skip-show-database", contentFile)
    if skip_sh is not None:
        reportFile.write("\tskip-show-database - correct\n")
    else:
        reportFile.write("\tCualquiera que tenga acceso al prompt de MySQL puede usar el comando \"SHOW DATABASES\". \n\tPara desactivar el uso de este comando, agregue lo siguiente a su archivo de configuración.\nskip-show-database\n")
    #Revision de local infile
    reportFile.write("\nlocal-infile \n")
    infile = re.search("(local-infile)\s+=\s(\d+)", contentFile)
    if infile is not None and  infile.group(2) == "0":
        reportFile.write("\tbind-address - correct\n")        
    else: 
        reportFile.write("\tMediante estos permisos se pueden leer ficheros del sistema operativo desde la base de datos, algo comun cuando se explota una inyeccion de codigo SQL.\n\t Para deshabilitar esta funcion se configura la variable local-infile a 0\n")
    #Revision de archivos de bitacora
    glogfile = re.search("(local-infile)\s+=\s(.+)", contentFile)
    logfile = re.search("(general_log)\s+=\s(\d+)", contentFile)
    reportFile.write("\ngeneral_log_file\n")
    if glogfile is not None:
        reportFile.write("\tgeneral_log_file - correct\n")
        if logfile is not None and logfile.group(2)=="1":
            reportFile.write("\tgeneral_log - correct\n")
        else: 
            reportFile.write("\tHabilita eneral query log \n\t Para habilitar esta funcion se configura la variable general_log a 1\n")
    else: 
        reportFile.write("\tEspecifica la direccion del archivo donde contendra el log\n\tEspecifica la ruta a log general_log_file = /var/log/mysql/mysql.log\n")



def parseNginxConf(nginxs,reportFile):
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+nginxs+"\n")
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("\nControlling Buffer Overflow Attacks\n")
    #Revision tamano de buffer de cuerpo
    reportFile.write("\nclient_body_buffer_size\n")
    bz = commands.getoutput("grep \"client_body_buffer_size\" "+nginxs+" | cut -d" " -f 3")
    if bz <= "4k;":
        reportFile.write("\tclient_body_buffer_size - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite limitar el tamanio del buffer del cuerpo de la peticion. \n\tEdite su archivo de configuracion con client_body_buffer_size de 1K a 4K\n")
    #Revision tamano buffer cabeceras
    reportFile.write("\nclient_header_buffer_size\n")
    hz = commands.getoutput("grep \"client_header_buffer_size\" "+nginxs+" | cut -d" " -f 3")
    if hz <= "4k;":
        reportFile.write("\tclient_header_buffer_size - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite limitar el tamanio del header de la peticion. \n\tEdite su archivo de configuracion con client_header_buffer_size de 1K a 4K\n")
    #Revision maximo tamano cuerpo
    reportFile.write("\nclient_max_body_size\n")
    mbz = commands.getoutput("grep \"client_body_size\" "+nginxs+" | cut -d" " -f 3")
    if mbz <= "4k;":
        reportFile.write("\tclient_max_body_size - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite limitar el tamanio maximo del cuerpo de la peticion. \n\tEdite su archivo de configuracion con client_body_buffer_size de 1K a 4K\n")
    #Revision timeout
    reportFile.write("\nclient_body_timeout\n")
    bt = commands.getoutput("grep \"client_body_timeout\" "+nginxs+" | cut -d" " -f 8")
    if bt <= "15;":
        reportFile.write("\tclient_body_timeout - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite limitar el tiempo de interaccion con el usuario, sino manda nada, lo redirige Request Time Out. \n\tEdite su archivo de configuracion con client_body_timeout 10\n")
    #Revision header timeout
    reportFile.write("\nclient_header_timeout\n")
    bh = commands.getoutput("grep \"client_header_timeout\" "+nginxs+" | cut -d" " -f 6")
    if bh <= "15;":
        reportFile.write("\tclient_header_timeout - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite limitar el tiempo de lectura de peticion del cliente, despues de este tiempo lo redirige Request Time Out. \n\tEdite su archivo de configuracion con client_header_timeout 10\n")
    #Revision keepalive timeout
    reportFile.write("\nkeepalive_timeout\n")
    kt = commands.getoutput("grep \"keepalive_timeout\" "+nginxs+" | cut -d" " -f 8")
    if kt <= "8;":
        reportFile.write("\tkeepalive_timeout - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite limitar el tiempo de vida con el cliente \n\tEdite su archivo de configuracion con keepalive_timeout 5\n")
    #Revision send timeout
    reportFile.write("\nsend_timeout\n")
    st = commands.getoutput("grep \"send_timeout\" "+nginxs+" | cut -d" " -f 6-20")
    if st <= "12;":
        reportFile.write("\tsend_timeout - correcto\n")
    else: 
        reportFile.write("\tLa configuracion de este parametro permite asignar el tiempo de respuesta al cliente \n\tEdite su archivo de configuracion con send_timeout 5\n")
    #Revision de sitios habilitados
    direc = "/etc/nginx/conf.d/"
    filesn = commands.getoutput("ls "+direc+" | grep .conf$").split("\n")
    for fn in filesn:
        reportFile.write("_____________________________________________________________________\n")
        reportFile.write("Analizando "+direc+fn+"\n")
        reportFile.write("_____________________________________________________________________\n")
        #Revision request methor
        reportFile.write("\nrequest_method \n")
        req = commands.getoutput("grep \"\$request_method \!\~ \" "+direc+fn)
        if req=="$request_method !~":
            reportFile.write("\trequest_method -correct \n")
        else: 
            reportFile.write("\tEsta opcion permitira permitir las peticiones seleccionadas\n\tEdite su archivo y en una sentencia condicional agregue los metodos que requiera $request_method\n")
        #Revision user agent
        reportFile.write("\nhttp_user_agent \n")
        httpreq = commands.getoutput("grep \"\$http_user_agent \~\* \" "+direc+fn)
        if httpreq=="$http_user_agent ~*":
            reportFile.write("\thttp_user_agent -correct \n")
        else: 
            reportFile.write("\tEsta opcion permitira permitira bloquear los user_agent y robots seleccionados\n\tEdite su archivo y en una sentencia condicional agregue los user_agents que quiere bloquear $http_user_agent\n")
        #Revision SSL
        reportFile.write("\nSSL\n")
        ssl = commands.getoutput("grep -i \"listen 443\" "+direc+fn+" | awk '{print $2}' ")
        if ssl=="443":
            reportFile.write("\tssl -correct \n")
        else: 
            reportFile.write("\tEsta opcion permite usar una conexion web segura\n\tEdite su archivo y agregue listen 443 ssl, ademas de sus certificados\n")


def parsePsqlServer(confpsql,reportFile):
    print "Analizando "+ confpsql
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+confpsql+"\n")
    reportFile.write("_____________________________________________________________________\n")
    #Obtener contenido del archivo 
    contentFile = commands.getoutput("grep -v  '^#\|^$' " + confpsql)
    #Revision permisos y propietario
    permisos = commands.getoutput("stat "+confpsql+" | grep -i access | head -1       | cut -d' ' -f2")
    owner = commands.getoutput("stat "+confpsql+" | grep -i access | head -1  |  sed 's/ //g'")
    reportFile.write("\nPermisos y propietario \n")
    if "Uid:(0/root)Gid:(0/root)" in owner:
        reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
    else: reportFile.write("\tEjecute  chown root:root "+confpsql+ "para cambiar el propietario\n")
    if "(0600/-rw-------)" in permisos:
        reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
    else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n")
    #Revision puerto
    reportFile.write("\nPuerto \n")
    port = re.search("(port)\s+=\s+(\d+).*", contentFile)
    if port is not None and port.group(2) == "5432":
        reportFile.write("\tPuerto por defecto port=5432\n\tPuedes editar tu archivo para cambiar el puerto por defecto\n")
    else:
        reportFile.write("\tport!=5432 -correcto\n")
    #Revision listen address
    reportFile.write("\nlisten_addresses \n")
    lis = re.search("(listen_addresses)\s+=\s+(.*)", contentFile)
    com="\'*\'"
    if lis is not None and  lis.group(2) == com:
        reportFile.write("\tlisten_addresses = '*' \n\tEdita el archivo para que solo determinandas ips puedan acceder a la base de datos\n")
    else: 
        reportFile.write("\tlisten_addresses - correcto\n")

def parsePsqlHba(pgsql,reportFile):
    print "Analizando "+ pgsql
    reportFile.write("_____________________________________________________________________\n")
    reportFile.write("Analizando "+pgsql+"\n")
    reportFile.write("_____________________________________________________________________\n")
    #Revision de permisos y propietario
    permisos = commands.getoutput("stat "+pgsql+" | grep -i access | head -1       | cut -d' ' -f2")
    owner = commands.getoutput("stat "+pgsql+" | grep -i access | head -1  |  sed 's/ //g'")
    reportFile.write("\nPermisos y propietario \n")
    if "Uid:(0/root)Gid:(0/root)" in owner:
        reportFile.write("\tPropietario correcto Uid:(0/root)Gid:(0/root)\n")
    else: reportFile.write("\tEjecute  chown root:root "+pgsql+ "para cambiar el propietario\n")
    if "(0600/-rw-------)" in permisos:
        reportFile.write("\tPermisos correctos (0600/-rw-------)\n")
    else: reportFile.write("\tPermisos: "+permisos+ " Incorrectos\n\tEjecute:  chmod 600 /etc/my.cnf para cambiarlos\n") 
    #Revision de autenticacion
    reportFile.write("\nAutenticacion\n")  
    ipv4 = commands.getoutput("grep -i \"^host\" "+pgsql+" | awk '{print $5}'")
    if ipv4!="trust\ntrust":
        reportFile.write("\tAutenticacion -correcto\n")
    else: reportFile.write("\tCambiar el parametro trust por otro medio de autenticacion\n")
    #Revision de base de datos y usuario
    reportFile.write("\nBases de datos y Usuario\n")  
    db = commands.getoutput("grep \"^host\" "+pgsql+" | awk '{print $2}'")
    us = commands.getoutput("grep \"^host\" "+pgsql+" | awk '{print $3}'")
    if db == "all" or us == "all":
        reportFile.write("\tPuedes especificar el nombre de la base de datos que podra ecceder un usuario especifico\n")
    else:
        reportFile.write("\tBD y users - correcto\n")

if __name__ == '__main__':
    try:
        cmd_opts = addOptions() #Adds the options to use   
        banner()
        paths_dict = readConfigFile(cmd_opts.config) # Gets the dictionary generated byt the readConfigFile function
        paths = getExistingFiles(paths_dict)
        report = open(cmd_opts.output,'w')
        for p in paths:
            if p == 'apache_conf':      parseApacheConf(paths_dict[p],report,paths_dict["web_sites"])
            if p == 'apache_security':  parseApacheSecurity(paths_dict[p])
            if p == 'apache_ssl':       parseApacheSsl(paths_dict[p],report)
            if p == 'ssh_server':       parseSshServer(paths_dict[p],report)
            if p == 'php':              parsePhp(paths_dict[p],report)
            if p == 'mysql_server':     parseMysqlServer(paths_dict[p],report)
            if p == 'nginx_conf':       parseNginxConf(paths_dict[p],report)
            if p == 'psql_server':      parsePsqlServer(paths_dict[p],report)
            if p == 'psql_hba':         parsePsqlHba(paths_dict[p])
        report.close() 
    except Exception as e:
        printError('Unkown error: %s ' % e, True)