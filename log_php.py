import re
import sys
import os

filesLogPhp = []
filesLogPhp.append('error.log')
#filesLogPhp.append('moodle-respaldo-error.log')


class prueba(object):
	def _init_(self):
		self.c_error
		self.ip_client
		self.desc
		self.fecha

r_php = prueba()

def analyzePhpLogs(logs):
	for l in logs: 
	
		#file_error = open ("codigo_error-"+l+".txt","w")
		#file_line_error = open ("line_error-"+l+".txt","w")
		#file_ip_client = open ("ip_client-"+l+".txt","w")
		print "\nAnalizando error y funciones obsoletas PHP para " + l 
		with open(l) as f:
			lines = f.readlines()
			for line in lines:	
				if re.search("error",line) is not None:
					err = re.search('PHP ([a-zA-Z]+)( [a-zA-Z]+)?', line)
					if err is not None:
						r_php.c_error = err.group(0)
						#print r_php.c_error
						#file_error.write(err.group(0)+"\n")
						#file_line_error.write(line+"\n")
						client = re.search(r'(\d{1,3}\.){3}\d{1,3}',line)
						if client is not None:
							r_php.ip_client = client.group(0)
							
							#print r_php.ip_client
							#file_ip_client.write(client.group(0)+"\n")
							r_php.fecha = ' '.join(line.split()[0:5]).strip("]").strip("[")
							r_php.fecha = re.sub(r'\.[0-9]+ ',' ',r_php.fecha)		 
							r_php.desc =re.search(r'(PHP ([a-zA-Z]+)( [a-zA-Z]+)?:  )(.+)( in .+)',line)
							print r_php.c_error + "\t"  + r_php.ip_client + "\t" + r_php.fecha + "\t" + r_php.desc.group(4)
					
						

		#file_line_error.close
		#file_error.close
		#file_ip_client.close

analyzePhpLogs(filesLogPhp)
