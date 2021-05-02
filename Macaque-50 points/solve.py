import socket
from time import sleep

host = 'challenges1.france-cybersecurity-challenge.fr'
port = 6000
y = 0x61616161616161616161616161616101
m = b"616161616161616161616161616161"
message = b"61616161616161616161616161616101"

sock = socket.socket()
sock.connect((host,port))
sock.recv(4096)

# On envoie notre message initial
sock.send(b"t\n")
sleep(0.1)
sock.recv(1024)
sock.send(message+b"\n")
sleep(0.1)
# On récupère la première partie de notre tag
tag2 = sock.recv(4096).decode().split(' ')
tag2 = tag2[2][:32]

# On envoie notre message initial modifié pour connaitre le bloc chiffré #1
sock.send(b"t\n")
sleep(0.1)
sock.recv(4096)
sock.send(m+b"\n")
sleep(0.1)
tag1 = sock.recv(4096).decode().split(' ')
tag1 = tag1[2][:64]

# On calcule x qui sera concaténé à notre message initial 
x = int(y)^int(tag1[0:32],16)
x = hex(x)[2:]
if len(x)%2 == 1:
	x = "0"+x

# On calule z qui est le message qu'on va envoyer pour connaitre notre deuxième partie de tag
z = hex(int(tag1[32:],16)^int(x,16))[2:]
if len(z)%2 == 1:
	z = "0"+z

# On envoie z
sock.send(b"t\n")
sleep(0.1)
sock.recv(1024)
sock.send(z.encode()+b"\n")
sleep(0.1)
tag3 = sock.recv(4096).decode().split(' ')
tag3 = tag3[2][32:]
print("Message final : ", message+x.encode())
print("tag final : ",tag2+tag3)

# On envoie notre vérification pour avoir le flag
sock.send(b"v\n")
sleep(0.1)
sock.recv(4096)
sock.send(message+x.encode()+b"\n")
sleep(0.1)
sock.recv(1024)
sock.send((tag2+tag3).encode()+b"\n")
print(sock.recv(4096).decode().split('\n')[0])
