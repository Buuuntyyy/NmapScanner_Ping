from ast import Pass
from cProfile import label
from cgitb import text
from concurrent.futures import thread
from ctypes import alignment
from distutils.cmd import Command
from glob import glob
from ipaddress import collapse_addresses
from math import trunc
from msilib.schema import CheckBox, tables
from tabnanny import check
from tkinter import *
from tkinter import messagebox
from tkinter.simpledialog import askstring
from tkinter.tix import COLUMN, ButtonBox
from tkinter.ttk import Labelframe
from tracemalloc import start
from turtle import left, onclick, title
from urllib.robotparser import RobotFileParser
import sys
import webbrowser
from xmlrpc.client import boolean
import nmap
import os
import threading
import time


fenetre = Tk()


menubar = Menu(fenetre)
fenetre.geometry('500x720')
fenetre.config(bg='#c8c8c8', menu=menubar)
fenetre.title('Scan and Ping')
"""
p = PanedWindow(fenetre, orient=VERTICAL)
p.pack(side=TOP, expand=Y, fill=BOTH, pady=2, padx=2)
p.add(Label(p, text='This is a test', background='gray', anchor=CENTER))
p.pack()
"""

radio_value = IntVar()
radio_value_ping = IntVar()
checkbox_button1 = BooleanVar()
checkbox_button2 = BooleanVar()
checkbox_button3 = BooleanVar()
checkbox_button4 = BooleanVar()
checkbox_button5 = BooleanVar()
checkbox_button6 = BooleanVar()
ping_check = IntVar()
ip_ping1 = BooleanVar()
ip_ping2 = BooleanVar()
HowMany = BooleanVar()
WhatIp = BooleanVar()
sortie_scan1 = BooleanVar()
sortie_scan2 = BooleanVar()
value_access = -1

def stoping():
    raise KeyboardInterrupt

def get_radiovalue(radio_value):
    value = radio_value.get()
    return value

def get_pingValue(radio_value):
    value = radio_value.get()
    return value

def custom_query():
    query = askstring('Custom Query', 'Enter the query you want ')
    custom_target = askstring('Custom Query', 'Enter the IP target ')
    print(query)
    print(custom_target)

    execute = messagebox.askyesno('Validate execution', 'Do you wish to proceed the following query ? ')
    if execute:
        return scan_thread(ip=custom_target, commande=query, custom=True)
    else:
        print('Aborted')


menuOptions = Menu(menubar, tearoff=0, bg='#c8c8c8')
menuOptions.add_command(label='Stop Scanning', command=stoping)
menuOptions.add_command(label='Customed Query', command=custom_query)
menubar.add_cascade(label='Options', menu=menuOptions)

menuInfo = Menu(menubar)
menuInfo.add_command(label='doc', command=lambda: webbrowser.open('https://nmap.org/man/fr/man-briefoptions.html'))
menubar.add_cascade(label='More...', menu=menuInfo)

l = LabelFrame(fenetre, text="Scan's Type", padx=75, bg='#c8c8c8')
l.grid(column=0, row=0, padx=10, pady=30)
radio1 = Radiobutton(l, text='TCP Scan', variable=radio_value, value=0, command=get_radiovalue(radio_value), anchor='w', bg='#c8c8c8')
radio2 = Radiobutton(l, text='UDP Scan', variable=radio_value, value=1, command=get_radiovalue(radio_value), anchor='w', bg='#c8c8c8')
radio3 = Radiobutton(l, text='X-mas Scan', variable=radio_value, value=2, command=get_radiovalue(radio_value), anchor='w', bg='#c8c8c8')
radio1.grid(column=0, row=0, sticky='w')
radio2.grid(column=0, row=1, sticky='w')
radio3.grid(column=0, row=2, sticky='w')


m = LabelFrame(fenetre, text="Ping's Type", padx=30, bg='#c8c8c8')
m.grid(column=1, row=0, pady=20, sticky='e')
radioP1 = Radiobutton(m, text='Host Resolving (passive) ', variable=radio_value_ping, value=0, command=get_pingValue(radio_value_ping), anchor='e', bg='#c8c8c8')
radioP1.grid(column=0, row=0, sticky='e')
radioP2 = Radiobutton(m, text='Host Discovering (active)', variable= radio_value_ping, value=1, command=get_pingValue(radio_value_ping),bg='#c8c8c8')
radioP2.grid(column=0, row=1)

def ListIP():
    if ip_ping1.get():
        pingList_entry.grid(column=0, row=1)
    else:
        pingList_entry.grid_remove()

def IP():
    if ip_ping2.get():
        pingList_entry2.grid(column=0, row=3)
    else:
        pingList_entry2.grid_remove()

v = LabelFrame(fenetre, text="Ping's Options", bg='#c8c8c8')
v.grid(column=1, row=1, pady=20)
pPara1 = Radiobutton(v, text='TCP SYN(typical)', variable=ping_check, value=0, bg='#c8c8c8')
pPara1.grid(column=0, row=0)
pPara2 = Radiobutton(v, text='TCP ACK(treater)', variable=ping_check, value=1, bg='#c8c8c8')
pPara2.grid(column=0, row=1)
pPara3 = Radiobutton(v, text='UDP', variable=ping_check, value=2, bg='#c8c8c8')
pPara3.grid(column=0, row=2)
pPara4 = Radiobutton(v, text='ICMP', variable=ping_check, value=3, bg='#c8c8c8')
pPara4.grid(column=1, row=0)
pPara5 = Radiobutton(v, text='Timestamp', variable=ping_check, value=4, bg='#c8c8c8')
pPara5.grid(column=1, row=1)
pPara6 = Radiobutton(v, text='Netmask', variable=ping_check, value=5, bg='#c8c8c8')
pPara6.grid(column=1, row=2)

w = LabelFrame(fenetre, text='IPS list', bg='#c8c8c8')
w.grid(column=1, row=2)
liste = Checkbutton(w, text='IP List (enter PATH)', variable=ip_ping1, command=ListIP, onvalue=True, offvalue=False, bg='#c8c8c8')
liste.grid(column=0, row=0)
ip = Checkbutton(w, text='IP (enter 1 IP)', variable=ip_ping2, command=IP, onvalue=True, offvalue=False, bg='#c8c8c8')
ip.grid(column=0, row=2)

o = LabelFrame(fenetre, text="Scan's Parameters", bg='#c8c8c8', )
o.grid(column=0, row=1, padx=10, pady=0, sticky='w')
para1 = Checkbutton(o, text="OPEN's services", variable=checkbox_button1, onvalue=True, offvalue=False, bg='#c8c8c8')
para1.grid(column=0, row=0)
para2 = Checkbutton(o, text='OS', variable=checkbox_button2, onvalue=True, offvalue=False, bg='#c8c8c8')
para2.grid(column=0, row=1)
para3 = Checkbutton(o, text='ALL Ports ', variable=checkbox_button3, onvalue=True, offvalue=False, bg='#c8c8c8')
para3.grid(column=0, row=2)
para4 = Checkbutton(o, text='IPV6 Scan', variable=checkbox_button4, onvalue=True, offvalue=False, bg='#c8c8c8')
para4.grid(column=1, row=0)
para5 = Checkbutton(o, text='OS/Versions', variable=checkbox_button5, onvalue=True, offvalue=False, bg='#c8c8c8')
para5.grid(column=1, row=1)
para6 = Checkbutton(o, text="IP's Scan(only)", variable=checkbox_button6, onvalue=True, offvalue=False, bg='#c8c8c8')
para6.grid(column=1, row=2)

def inputPorts():
    if HowMany.get():
        entry.grid(column=1, row=0)
    else:
        entry.grid_remove()

def inputIp():
    if WhatIp.get():
        entry2.grid(column=1, row=0)
    else:
        entry2.grid_remove()



q = LabelFrame(fenetre, text="Scan some ports", padx = 5, pady=5, bg='#c8c8c8')
q.grid(column=0, row=2, padx=10, pady=10, sticky='w')
portsNumber = Checkbutton(q, text='Ports to Scan : ', variable=HowMany, command=inputPorts, onvalue=True, offvalue=False, bg='#c8c8c8')
portsNumber.grid(column=0, row=0)

target = LabelFrame(fenetre, text="Target IP", bg='#c8c8c8')
target.grid(column=0, row=3, padx=10, pady=10, sticky='w')
targetCheck = Checkbutton(target, text="IP's Target : ", variable=WhatIp, command=inputIp, onvalue=True, offvalue=False, bg='#c8c8c8')
targetCheck.grid(column=0, row=0)


global entry
entry = Entry(q, bg='#c8c8c8')

global entry2
entry2 = Entry(target, bg='#c8c8c8') #il existe, mais on décide de le faire apparaître ou non

global pingList_entry
pingList_entry = Entry(w, bg='#c8c8c8')

global pingList_entry2
pingList_entry2 = Entry(w, bg='#c8c8c8')


p = LabelFrame(fenetre, text="Scan's Output", padx = 5, pady=5, bg='#c8c8c8')
p.grid(column=0, row=4, padx=10, pady=10, sticky='w')
sortie1 = Checkbutton(p, text='.TXT', variable=sortie_scan1, onvalue=True, offvalue=False, bg='#c8c8c8')
sortie1.grid(column=0, row=0)

def output(to_write):
    user = os.getenv("USERNAME")
    if sortie_scan1.get():
        doc = open("C:/Users/" + user + "/Desktop/scan_results.txt", 'w')
        doc.write(to_write)
        doc.close()
    else:
        pass

def verifIP():
    ip_target = entry2.get()
    print(f'IP : {ip_target}')
    return ip_target

def verifPorts(liste):
    print('taille entrée')
    print(len(liste))
    if len(liste) == 0:
        return ''
    else:
        portsListe = ' -p'
        ports = liste.split(',')
        print(f'ports scann : {ports}')
        for caracter in ports:
            try:
                verif = int(caracter)
                portsListe += str(caracter) + ','
            except ValueError:
                messagebox.showerror(message='Vous avez mal saisis les ports à scanner, voici un exemple : 1,23,3,234,34567')
            
    return portsListe[:-1]

def options(commande='', checkbox1=False, checkbox2=False, checkbox3=False, checkbox4=False, portsChoice=''):
    commande += portsChoice
    tab_comp = [' -sV', ' -O', ' -p-', ' -6', ' -A', ' -sO']
    tab = [checkbox_button1.get(), checkbox_button2.get(), checkbox_button3.get(), checkbox_button4.get(), checkbox_button5.get(), checkbox_button6.get()]
    if tab[5]:
        return tab[5]
    else:
        for i in range(0, 6):
            if tab[i]:
                print(f'tableau : {tab[i]}')
                commande += tab_comp[i]
        print(f'commande nmap : {commande}')
    return commande
        
def pinging(ping_commande='', target_ip='127.0.0.1'):
    if ip_ping1.get():
        target_ping = pingList_entry.get()
    elif ip_ping2.get():
        target_ping = pingList_entry2.get()
        print(f'target : {target_ping}')
        print(f'target range : {target_ping}' + '/30')
        
    else:
        target_ping = '127.0.0.1'
    if get_pingValue(radio_value_ping) == 0:
        ping_commande += '-sL'

        np = nmap.PortScanner()
        np.scan(hosts=target_ping, arguments='-sL')
        host_list = [(x, np[x]['status']['state']) for x in np.all_hosts()]
        print('NETWORK : ' + np[target_ping].hostname())
        print('----------------------')
        print('=====HOSTS LIST=====')
        for host, status in host_list:
            print('HOST : ' + host)
    elif get_pingValue(radio_value_ping) == 1:
        ping_commande += '-sP'

        ping_opt = [' -PS', ' -PA', '-PU', ' -PE', ' -PP', ' -PM']
        ping_commande += ping_opt[ping_check.get()]
        print(ping_commande)
        nmPing = nmap.PortScanner()
        nmPing.scan(hosts='192.168.1.0/25', arguments=ping_commande)
        host_list = [(x, nmPing[x]['status']['state']) for x in nmPing.all_hosts()]
        print('NETWORK : ' + nmPing['192.168.1.1'].hostname())
        print('----------')
        for host, status in host_list:
            print('HOST : ' + host + '      STATE : ' + status + '      RESOLVED AS : ' + nmPing[host].hostname())
    else:
        ping_commande += '-sL'


def ping_thread():
    t2 = threading.Thread(target=lambda: pinging(target_ip='192.168.1.1'))
    t2.start()

def scanning(nmap_commande='', target_ip='192.168.1.20', custom=False):
    if custom:
        """
        print('test')
        test = nmap.PortScanner()
        test.scan('192.168.1.20', '-sS -p-')
        print(f'test : {test.csv()}')
        """
        if len(nmap_commande) < 2:
            nmap_commande = '-sS -p-'
            print(len(nmap_commande))
        else:
            pass
        print(nmap_commande)
        print(len(nmap_commande))
        start = time.time()
        nm = nmap.PortScanner()
        nm.scan(target_ip, arguments=nmap_commande)
        end = time.time()
        elapsed = end - start
        print(f'exécuté en {elapsed}ms')
        print('real')
        print(nm.csv())
    else:
        start = time.time()
        print(f'ip debut : {target_ip}')
        if get_radiovalue(radio_value) == 0:
            nmap_commande += '-sS'
            protocol = 'tcp'
            print(f'nmap : {nmap_commande}')
        elif get_radiovalue(radio_value) == 1:
            nmap_commande += '-sU'
            protocol = 'udp'
            print(f'nmap : {nmap_commande}')
        elif get_radiovalue(radio_value) == 2:
            nmap_commande += '-sX'
            protocol = 'xmas'
            print(f'nmap : {nmap_commande}')

        else:
            print('nothing')
        nmScan = nmap.PortScanner()
        try:
            if len(target_ip) > 0 and target_ip != ' ':
                print(f'Ip visé : {target_ip}')
                nmScan.scan(target_ip, arguments=options(commande=nmap_commande, portsChoice=verifPorts(entry.get())))
            else:
                target_ip = '127.0.0.1'
                print(f'Ip visé par défaut : {target_ip}')
                nmScan.scan('127.0.0.1', arguments=options(commande=nmap_commande, portsChoice=verifPorts(entry.get())))
        except NameError:
            print('NAME ERROR')
            print(f'Ip visé : {target_ip}')
            nmScan.scan(target_ip, arguments=options(commande=nmap_commande))
        end = time.time()
        elapsed = end - start
        print(nmScan.scaninfo())
        print(nmScan.csv())
        output(nmScan.csv())
        print(f'HOST : {target_ip} (RESOLVED AS : {nmScan[target_ip].hostname()})')
        print(f'STATE : {nmScan[target_ip].state()}     Scanned in : {trunc(elapsed)}s')
        print('----------')
        print("Protocol : " + protocol + "\n")
        liste = nmScan[target_ip]['tcp'].keys()
        for port in liste:
            print('PORT : {}    NAME : {}    STATE : {}    REASON : {}   PRODUCT : {}'.format(port, nmScan[target_ip]['tcp'][port]['name'],
            nmScan[target_ip]['tcp'][port]['state'], nmScan[target_ip]['tcp'][port]['reason'], nmScan[target_ip]['tcp'][port]['product']))


def scan_thread(ip='127.0.0.1', commande='-sS -p-', custom=False):
    if custom:
        t1 = threading.Thread(target=lambda: scanning(target_ip=ip, nmap_commande=commande, custom=True))
    else:
        t1 = threading.Thread(target=lambda: scanning(target_ip=entry2.get()))
    t1.start()

def stoping():
    raise KeyboardInterrupt

end = LabelFrame(fenetre, text='Launch', bg='#c8c8c8', padx=25, pady=15)
end.grid(columnspan=2, row=7, padx=75, pady=10)

start_scan = Button(end, text='Start Scanning !', bg='#c8c8c8', command= scan_thread)
start_scan.grid(column=0, row=0)

start_ping = Button(end, text='Start Pinging !', bg='#c8c8c8', command=ping_thread)
start_ping.grid(column=1, row=0, padx=10)

texte = Label(fenetre, text='Scans and ping')
texte.configure(bg='#c8c8c8', font='Arial', height=1, relief=GROOVE, padx=5, pady=5)
texte.grid(row=0, column=0, columnspan=2, sticky='n')

fenetre.mainloop()