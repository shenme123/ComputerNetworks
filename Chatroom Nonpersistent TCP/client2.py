import sys
import socket
import time
from thread import *
import random
import signal

def create_socket(ser_name):
    # create a socket
    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ip = server_ip
    except:
        #could not resolve
        print 'Hostname could not be resolved. Exiting'
        sys.exit(1)
    return new_socket, ip

def send_message(message):
    # send a message to server
    new_socket, ip= create_socket(serverName)
    new_socket.connect((ip, serverPort))
    new_socket.send(header+message)
    new_socket.close()

def send_message_peer(user_mess):
    # send a message to peer
    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = private_info[user_mess[1]][0]
    port = int(private_info[user_mess[1]][1])
    new_socket.connect((ip, port))
    mess = username+": "+ " ".join(user_mess[2:len(user_mess)])
    new_socket.send(mess)
    new_socket.close()

def thread_keyboard(serverPort, serverName):
    # thread that is used for the input detection and message sending
    while flag_thread:
        # get input
        try:
            message = raw_input()
        except:
            break
        while not message.strip():
            message = raw_input()
        # parse input
        tokens = message.strip().split()
        # if it is a private message, send to peer directly
        if tokens[0] == "private":
            # tokens[0]:private  tokens[1]:user   tokens[2]:message
            if tokens[1] in private_info:
                try:
                    send_message_peer(tokens)
                except:
                    print "The user information is no longer active. You may try sending offline message."
        # if it is a response to the private information request, send response to server with specific format
        elif tokens[0] == 'Y' and pinfo_req[1] == True:
            mess = "PRIVATE_INFO_RESPONSE YES "+pinfo_req[0]
            send_message(mess)
            pinfo_req[0] = ''
            pinfo_req[1] = False
        elif tokens[0] == 'N' and pinfo_req[1] == True:
            mess = "PRIVATE_INFO_RESPONSE NO "+pinfo_req[0]
            send_message(mess)
            pinfo_req[0] = ''
            pinfo_req[1] = False
        # otherwise, just send message to server
        else:
            send_message(message)

def thread_heartbeat(serverPort, serverName):
    # thread that is used to send heartbeat to server every heartbeat_time
    while 1:
        message = "HEART_BEAT"
        send_message(message)
        time.sleep(heartbeat_time)

def thread_receiving(serverPort, serverName):
    # thread that is used to listen and receive to income messages
    global flag_main
    while flag_thread:
        conn, addr = socket_listen.accept()
        reply = conn.recv(2048)
        # if receive the LOG_OUT command from server, break and change main thread flag
        if reply=="LOG_OUT":
            flag_main = False
            break
        # if receive the "DOUBLE_LOG_ERROR" from server (login somewhere else), break and change main thread flag
        elif reply=="DOUBLE_LOG_ERROR":
            print "Your account has been logged off since it is logging somewhere else."
            flag_main = False
            break
        # if receive the request from server of the private information, ask user for response
        elif reply.startswith("PRIVATE_INFO_REQUEST"):
            pinfo_req[0] = reply.strip().split()[1]
            pinfo_req[1] = True
            print "Would you like to provide information to the following user? (Y/N)"
            print reply.strip().split()[1]
        # if receive the request from server to clear the private info of certain user, clear the info
        elif reply.startswith("CLEAR_INFO"):
            if reply.strip().split()[1] in private_info:
                private_info.pop(reply.strip().split()[1], None)
                print "You are blocked by and can no longer send private message to "+reply.strip().split()[1]
        # other cases
        else:
            tokens = reply.strip().split("$$")
            # if it is the response from server the private information of peer
            if tokens[0]=="USER_INFO":
                info = tokens[1].split()
                # [ip, port]
                private_info[info[0]] = [info[1],info[2]]
                print "Information acquired."
            # else, just print the message
            else:
                print reply

def validate():
    # validate the identity of user
    # connect to server
    while 1:
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            #ip = socket.gethostbyname( serverName )
            ip = server_ip
        except socket.gaierror:
            #could not resolve
            print 'Hostname could not be resolved. Exiting'
            sys.exit()
        # ask to input the user name and password
        user = raw_input("Username: ")
        global username
        username = user
        pw = raw_input("Password: ")
        # send user name and password to server
        cred = user+'\n'+pw
        socket_client.connect((ip, serverPort))
        socket_client.send(cred)
        reply = socket_client.recv(2048)
        # parse the response from server for the sent username and password
        if reply == "USER_NOT_EXIST":
            print "User does not exist!"
        elif reply == "INVALID_PASSWORD":
            print "Invalid Password. Please try again."
        elif reply == "INVALID_PASSWORD_3":
            print "Invalid Password. Your account has been blocked. Please try again after sometime."
        elif reply == "USER_LOCKED":
            print "Due to multiple login failures, your account has been blocked.Please try again after sometime."
        elif reply == "RE_LOG_ERROR":
            print "You're already logged in!"
            sys.exit(1)
        elif reply == "SUCCESS_REPLACE":
            print "Welcome to simple chat server! Your account has been logged off somewhere else."
            break
        elif reply == "SUCCESS":
            print "Welcome to simple chat server!"
            break
        socket_client.close()
    # if succeeded logging in, receive a header used for identification for later message, and send port for receiving meesage
    header = socket_client.recv(2048)
    socket_client.send(str(listenPort))
    socket_client.close()
    return header

# entrance of program, initialization of parameters
serverName = "localhost"
serverPort = 12000
listenPort = random.randint(20000, 30000)
listenHost = ''
flag_main = True
flag_thread = True
private_info = {}
pinfo_req = ['', False]
username = ''
server_ip = sys.argv[1]
heartbeat_time = 29

# user credential verification
header = validate()
# start socket
socket_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    socket_listen.bind((listenHost, listenPort))
except socket.error , msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
# socket start listen
socket_listen.listen(10)

# start thread for input detection
start_new_thread(thread_keyboard, (serverPort, serverName))
# start thread for heart beat sending
start_new_thread(thread_heartbeat, (serverPort, serverName))
# start thread for receiving messages
start_new_thread(thread_receiving, (serverPort, serverName))

# main thread used for the detection of ctrl+c
try:
    while flag_main:
        a=1
except KeyboardInterrupt:
    flag_thread = False
    print "Exiting"
    sys.exit(1)

# exit
print "Exiting"
