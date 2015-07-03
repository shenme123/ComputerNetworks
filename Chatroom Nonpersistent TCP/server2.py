import socket
from thread import *
import sys
import time

def client_thread(conn, addr):
    # thread generated for each connection from clients
    message = conn.recv(2048)
    # check the online status on server side of the client
    is_online, command, user = online_checker(message)
    # if client is not "online" at server side
    if not is_online:
        # try to login client
        flag, user, pw = login(conn, addr, message)
        # if not valid username and password, close connection
        if not flag:
            conn.close()
            return
        # if successfully logged in, start heartbeat, add to online user list, send header, save client port
        user2data[user]['last_beat'] = time.time()
        online_users.add(user)
        header = gen_header(user, pw, addr)
        conn.send(header)
        client_port = int(conn.recv(2048))
        user2data[user]['clientport'] = client_port
        print client_port
        # close conneciton
        conn.close()
        # send offline messages and clear cache of offline messages
        off_mess = ''
        for mess in user2data[user]['message']:
            off_mess = off_mess + mess+'\n'
        send_message(off_mess, user)
        user2data[user]['message']=[]
    else:
        # if message from online user, process command
        proc_command(command, user)
        conn.close()

def heart_beat_check_thread(a, b):
    # check for heart beat every heartbeat_time
    while 1:
        for user in user2data:
            if user in online_users:
                t = time.time()-user2data[user]['last_beat']
                if t>30:
                    print "logout: " + user
                    logout(user)
        time.sleep(heartbeat_time)

def create_socket(user):
    # create new socket to connect to client
    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = user2data[user]['IP'][0]
    port = user2data[user]['clientport']
    return new_socket, ip, port

def send_message(message, user):
    # send message to client
    new_socket, ip, port= create_socket(user)
    new_socket.connect((ip, port))
    new_socket.send(message)
    new_socket.close()

def proc_command(command, user):
    # process command from client
    tokens = command.strip().split()
    # if it is a message, send it to specific unblocked user or save to offline message
    if tokens[0] == "message" :
        if len(tokens) >= 3:
            # user exist or not
            if tokens[1] in user2data:
                if tokens[1] not in user2data[user]['blockedby']:
                    message = user+": "+" ".join(tokens[2:len(tokens)])
                    if tokens[1] in online_users:
                        send_message(message, tokens[1])
                    else:
                        user2data[tokens[1]]['message'].append(message)
                else:
                    send_message("Your message could not be delivered as the recipient has blocked you", user)
    # if it is a broadcast, send to all other online user who didn't block this user
    elif tokens[0] == "broadcast":
        if len(tokens) >= 2:
            message = user+": "+" ".join(tokens[1:len(tokens)])
            blocked = False
            for onl_user in online_users:
                if onl_user in user2data[user]['blockedby']:
                    blocked = True
                else:
                    if onl_user!=user:
                        send_message(message, onl_user)
            if blocked:
                send_message("Your message could not be delivered to some recipients", user)
    # if it is online command, return online list of users
    elif tokens[0] == "online" and len(tokens)==1:
        mes = ""
        for onl_user in online_users:
            if onl_user != user:
                mes = mes+onl_user+"\n"
        send_message(mes.strip(), user)
    # if it is a block command, block the user and add to block lists
    elif tokens[0] == "block":
        if tokens[1] in user2data:
            user2data[user]['block'].add(tokens[1])
            mess = "User %s has been blocked" % tokens[1]
            send_message(mess, user)
            user2data[tokens[1]]['blockedby'].add(user)
            if tokens[1] in user2data[user]['trusted_peer']:
                user2data[user]['trusted_peer'].remove(tokens[1])
                mess = "CLEAR_INFO "+user
                send_message(mess, tokens[1])
    # if it is a unblock command, unblock the user and remove from block lists
    elif tokens[0] == "unblock":
        if tokens[1] in user2data:
            user2data[user]['block'].remove(tokens[1])
            mess = "User %s is unblocked" % tokens[1]
            send_message(mess, user)
            user2data[tokens[1]]['blockedby'].remove(user)
    # if it is a heart beat message, update latest heartbeat time in table
    elif tokens[0] == "HEART_BEAT":
        user2data[user]['last_beat'] = time.time()
    # if it is logout message, logout the user
    elif tokens[0] == "logout":
        send_message("LOG_OUT", user)
        logout(user)
    # if it is private information response, send or not the private information based on the responce to peer
    elif tokens[0] == "PRIVATE_INFO_RESPONSE":
        print tokens
        if tokens[1] == 'YES':
            mess = "USER_INFO"+"$$"+user+" "+user2data[user]['IP'][0]+ " "+str(user2data[user]['clientport'])
            send_message(mess, tokens[2])
            user2data[user]['trusted_peer'].add(tokens[2])
        else:
            mess = user+" declined the information request."
            send_message(mess, tokens[2])
    # if it is a request for getting the private information, send consent request to aim peer if not blocked
    elif tokens[0] == "getaddress" and len(tokens)==2:
        if tokens[1] in user2data:
            if tokens[1] in user2data[user]['blockedby']:
                mess = "You're blocked by %s. Information can not be retrieved" % tokens[1]
                send_message(mess, user)
            else:
                if tokens[1] in online_users:
                    m = "Request sent out to "+tokens[1]
                    send_message(m, user)
                    mess = "PRIVATE_INFO_REQUEST "+user
                    send_message(mess,tokens[1])
                else:
                    mess = tokens[1]+" is offline."
                    send_message(mess, user)

def logout(user):
    # used to log out user and clear user data at server side
    online_users.remove(user)
    for onuser in online_users:
        if onuser not in user2data[user]['block']:
            mess = user+" has logged out."
            send_message(mess, onuser)
    user2data[user]['IP'] = None
    user2data[user]['conn'] = None
    user2data[user]['clientport'] = None
    user2data[user]['last_beat'] = None

#def send_message(user, message):

def online_checker(message):
    # check if a user is already online when receiving a message
    # return true if online
    tokens = message.split("$$")
    if len(tokens)>=3 and tokens[0] in online_users and tokens[1]==user2data[tokens[0]]['password'] and tokens[2]==user2data[tokens[0]]['IP'][0]:
        command = tokens[3]
        if len(tokens)>4:
            for i in range(4,len(tokens)):
                command = command+"$$"+tokens[i]
        return True, command, tokens[0]
    else:
        return False, '', ''

def gen_header(user, pw, addr):
    # generate a header for user containing: username, password, IP separated by $$
    return user+"$$"+pw+"$$"+addr[0]+"$$"

def login(conn, addr, message):
    # try to login the user with given username and password
    # get credential
    flag, user, pw = get_cred(user2data, conn, message)
    if not flag:
        return flag, user, pw
    # check if user is locked
    locktime = user2data[user]['locktime']
    if locktime != None:
        cur_time = time.time()
        # if locked, say locked, continue next loop
        if cur_time - locktime<lock_window:
            conn.send("USER_LOCKED")
            return False, user, pw
        # if passed locked window, clear locktime
        else:
            user2data[user]['locktime'] = None
    # check if the pass is correct
    if pw != user2data[user]['password']:
        if user2data[user]['counter'] < 2:
            conn.send("INVALID_PASSWORD")
            user2data[user]['counter'] += 1
            return False, user, pw
        # check if 3 consecutive failures
        elif user2data[user]['counter'] == 2:
            user2data[user]['counter'] = 0
            user2data[user]['locktime'] = time.time()
            conn.send("INVALID_PASSWORD_3")
            return False, user, pw
    # check if user is already logged in
    if user2data[user]['IP'] is not None:
        # if same IP, exit the client
        if addr[0] == user2data[user]['IP'][0]:
            conn.send("RE_LOG_ERROR")
            return False, user, pw
        # if diff IP, exit the other client and log in this client
        else:
            send_message("DOUBLE_LOG_ERROR", user)
            conn.send("SUCCESS_REPLACE")
            for peer in user2data[user]['trusted_peer']:
                if peer in online_users:
                    mess = "PRIVATE_INFO_REQUEST "+user
                    send_message(mess,peer)
    # else, successfully logged in and update user information
    else:
        conn.send("SUCCESS")
    # pass login, clear counter,
    user2data[user]['conn'] = conn
    user2data[user]['IP'] = addr
    user2data[user]['counter'] = 0
    # notify other online users the login of this user
    for onuser in online_users:
        if onuser not in user2data[user]['block']:
            mess = user+" is online now."
            send_message(mess, onuser)
    return True, user, pw

def get_cred(user2data, conn, message):
    # collect input of username and password
    # message = conn.recv(2048)
    tokens = message.split("\n")   # token[0]: username   token[1]: password
    if tokens[0] not in user2data:
        error = "USER_NOT_EXIST"
        conn.send(error)
        return False, tokens[0], tokens[1]
    return True, tokens[0], tokens[1]

def read_cred(cred_file):
    # read in all user credentials from file and generate a table for user information
    user2data = {}
    line = cred_file.readline()
    while line:
        tokens = line.strip().split()
    # user2data:{user:{'password':, 'locktime':, 'counter':, 'message':[ message, ], 'conn':, 'IP':, 'online':, 'clientport':, 'block':, 'blockedby':, 'last beat':, 'trusted_peer': }
        user2data[tokens[0]] = {'password':tokens[1], 'locktime':None, 'counter':0, 'message':[], 'conn':None, 'IP':None, 'online':False, 'clientport':None, 'block':set(), 'blockedby':set(), 'last_beat':None, 'trusted_peer':set()}
        line = cred_file.readline()
    return user2data

# read in credentials and initialize user information
cred_file = open("./credentials.txt", "r")
user2data = read_cred(cred_file)
# setup a set to hold online users
online_users = set()
# initialize server parameters
# generate a server socket
HOST = ''
PORT = 12000
heartbeat_time = 30
lock_window = 60
# start listening and wait for incoming client
sk_ser = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sk_ser.bind((HOST, PORT))
except socket.error , msg:
    print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
sk_ser.listen(10)
print 'Socket now listening'
# start thread to check heartbeat
start_new_thread(heart_beat_check_thread, (HOST, PORT))

# keep accept connections from clients
while 1:
    conn, addr = sk_ser.accept()
    print 'Connect with ' + addr[0]
    start_new_thread(client_thread,(conn, addr))
