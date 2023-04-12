from itertools import product
from posixpath import split
import nmap
import os
import socket
import ipaddress
"""
scan = nmap.PortScanner()
scan.scan('127.0.0.1')
#print(scan.scaninfo()) #affiche les infos du scan
print(scan['127.0.0.1'].hostname()) #résout le nom de l'hote
print(scan['127.0.0.1'].state()) #retourne l'état de la machine (UP, DOWN)
print(scan['127.0.0.1']['tcp']) #retournes touts les ports utilisant tcp
print(scan['127.0.0.1'].all_protocols()) #retourne les protocoles utilisés par tout les ports
print(scan['127.0.0.1'].has_tcp(80)) #verifie si le port 80 tourne sous tcp
print(scan['127.0.0.1'].has_tcp(135))
print(scan['127.0.0.1'].tcp(135)) #donne les infos du port 135 sous tcp
scan2 = nmap.PortScanner()
print(scan2.scan('172.20.10.12', '1-100', arguments='-sU')) #arguments permet de préciser les paramètres du scan nmap
print(scan2.csv()) #affiche les resultats du scan

chaine = '1, 2, 3, 4, 56, 564, 5, 67'
new = chaine.split(',')
print(new)

a = 'azerty'
#print(int(a))
b = 'aze345'
print(int(b))

print(os.getenv("USERNAME"))
user = os.getenv("USERNAME")
doc = open("C:/Users/" + user + "/Desktop/scan.txt", 'w')
doc.write('AAAAAAAA')
doc.close()

host = '127.0.0.1'
nscan = nmap.PortScanner()
nscan.scan(host)
print(nscan[host].all_protocols())
print(nscan[host]['tcp'].keys())
print(nscan[host]['tcp'])
liste = nscan[host]['tcp'].keys()
dictio = nscan[host]['tcp']
print(dictio.get('state'))

for port in liste:
    print('PORT : {}    STATE : {}   NAME : {}   PRODUCT : {}'.format(port, dictio[port]['state'], dictio[port]['name'], dictio[port]['product']))


ns = nmap.PortScanner()
ns.scan('192.168.1.20', arguments='-sT')
#print(ns['192.168.1.20']['udp'].keys())
print(ns.csv())
def again(liste):
    indices = []
    print(len(liste))
    new = []
    for i in range(0, len(liste)):
        new.append(list(liste[i]))
        print(new)

    for w in range(0, len(new)):
        if new[i][0] == "\r":
            print('okay')
            indices.append(w)
    print(indices)


print((ns.csv()).split(';'))
again(ns.csv().split(';'))
"""

add = socket.gethostbyname(socket.gethostname())
print(add)
np = nmap.PortScanner()
np.scan(hosts='192.168.1.0/25', arguments='-sL')
host_list = [(x, np[x]['status']['state']) for x in np.all_hosts()]
print('NETWORK : ' + np['192.168.1.1'].hostname())
print('----------')
for host, status in host_list:
    print('HOST : ' + host + '      STATE : ' + status + '      RESOLVED AS : ' + np[host].hostname())

test = nmap.PortScanner()
test.scan('192.168.1.22')
print(test.csv())