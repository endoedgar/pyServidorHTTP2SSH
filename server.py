from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import parse_qs
import paramiko
from paramiko import SSHClient
from paramiko import SSHException
import SocketServer
import json
import cgi
import hmac
import hashlib
import urllib
import base64

listenea = None
chaveHMAC = None

with open('config.json') as arquivo_json:
				dados = json.load(arquivo_json)
				listenea = dados['roteadores']
				chaveHMAC = dados['chaveHMAC']

class SSH:
	def __init__(self, hostname, username, password):
		self.ssh = SSHClient()
		self.ssh.load_system_host_keys()
		self.hostname = hostname
		self.username = username
		self.password = password
		self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		self.conectar()
		
	def conectar(self):
		self.ssh.connect(hostname=self.hostname,username=self.username,password=self.password)
		print 'Tive que conectar'
	
	def real_exec(self,cmd):
		stdin,stdout,stderr = self.ssh.exec_command(cmd)
		if stderr.channel.recv_exit_status() != 0:
			return stderr.read()
		else:
			return stdout.read()
				
	def exec_cmd(self,cmd):
		try:
			return self.real_exec(cmd)
		except SSHException:
			self.conectar()
			return self.real_exec(cmd);
			
class Server(BaseHTTPRequestHandler):
	def _set_headers(self):
		self.send_response(200)
		self.send_header('Content-type', 'application/json')
		self.end_headers()
		
	def _setar_erros(self, erroMsg):
		self.send_response(500)
		self.send_header('Content-type', 'application/json')
		self.end_headers()
		retorno = {
			"sucesso": 0,
			"mensagem": erroMsg
		}
		self.wfile.write(json.dumps(retorno))
        
	def do_HEAD(self):
		self._set_headers()
        
	def do_GET(self):
		try:
			s = self.path

			getParams = parse_qs(s[2:])

			if 'hmac' in getParams.keys():
				print chaveHMAC
				hmacInformado = getParams.pop('hmac')[0]
				mensagemParaHmac = self.headers['user-agent'] + urllib.urlencode(getParams, True)
				hmacGerado = base64.b64encode(hmac.new(str(chaveHMAC), mensagemParaHmac, hashlib.sha256).digest())
				if(hmacInformado == hmacGerado):
					if 'server' in getParams.keys() and 'cmd' in getParams.keys():
						server = getParams.get('server')[0]
						if server in listenea.keys():
							objAtual = listenea[server]

							username = 'root'
							if('username' in objAtual): 
								username= objAtual['username']

							password = ''
							if('password' in objAtual): 
								password= objAtual['password']

							if('ssh' not in objAtual or objAtual['ssh'] == None):
								objAtual['ssh'] = SSH(hostname=objAtual['hostname'], username=username, password=password)

							shellretorno = objAtual['ssh'].exec_cmd(getParams.get('cmd')[0])

							retorno = {
								"sucesso": 1,
								"retorno": shellretorno,
								"seuHost": objAtual['lado_lan']
							}
					
							self._set_headers()
							self.wfile.write(json.dumps(retorno))
						else:
							self._setar_erros('Nunca nem vi')
					else:
						self._setar_erros('Requisicao mal formada.')
				else:
					self._setar_erros('Falha de HMAC')
			else:
				self._setar_erros('Sem HMAC, sem chance.')
			
		except Exception as exception:
			print repr(exception)
			self._setar_erros('Houve uma excecao: ' + repr(exception))
        
def run(server_class=HTTPServer, handler_class=Server, port=8008):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    
    print 'Iniciando servidor na porta %d...' % port
    httpd.serve_forever()
    
if __name__ == "__main__":
    from sys import argv
    
    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
