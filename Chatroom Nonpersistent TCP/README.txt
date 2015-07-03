1. General discription of programming design and data structure

Client side: When a client starts, it first collect the username and passord from keyboard and send to server, if login is not succesful, return diffent error message and display to user corresponding to it. If three consecutive fail happens for specific username, the account is locked for a certain time that is configurable by changing the value of global variable. If the user has login in the same IP, the new client will be close. If user has login a diffent IP, the new client logs in and the old client logs out. If the username and password pass the validation, then the user is logged in on the server side. During the validation process, after each sending of message at both client and server sides, the connection and sockets are closed. After login, the client will receive a header with username, password and IP separated by "$$" as a special simple protocal format. After login, each message send from client to server is headed with the header. 3 threads are started, for detecting input from keyboard, listening and receiving messages and heart beat respectively. The main thread is used to capture the ctrl+c loging out. Client can then start to send commands to the server. The program implement all required commands as the sample format. For the listening thread, it starts a socket listening, sends the port randomed to server, and can receive message from both server and other peers who has got the private information. 

Server side: When a server starts, it first read in all credentials from file and generate a dict with username as key and a sub-dict with bunch of feathers as keys and corresponding values. The values are updated for each operation that has been done by users. Then it starts to listen from clients, before which a thread is started to detect heart beat of all online users. For each clients connecting in, server first check the username and password. If it is valid and not logged in yet on the same IP, it will be logged in, and corresponding message will be sent to user to confirm the logging in. After successful log in, server generate a header mentioned before and send it to the server. After each message sent and received, the sockets on both sidse are closed. The server will keep listening from users and process the commands from users accordingly, at the same time updating the user data. 

Note: 
(1)Both bonus iterms has been implemented, including the privacy consent and guarenteed message delivery. 
(2)If the commands sent by client to server is of wrong format, there may not be notification of error at both sides, which may seems like nothing happened.
(3)The listening port in server has been specified in both client and server to be 12000



2. Explanation of source code.

Fuctions in Server:
In main function, server is started and initialized, after which it keeps accepting connections from clients and start a new thread to deal with each message receiced and quit the thread and close socket afterwards.
client_thread(conn, addr):
    # thread generated for each connection from clients
heart_beat_check_thread(a, b):
    # check for heart beat every heartbeat_time
create_socket(user):
    # create new socket to connect to client
send_message(message, user):
    # send message to client
proc_command(command, user):
    # process command from logged client
logout(user):
    # used to log out user and clear user data at server side
online_checker(message):
    # check if a user is already online when receiving a message
gen_header(user, pw, addr):
    # generate a header for user containing: username, password, IP separated by $$
login(conn, addr, message):
    # try to login the user with given username and password
get_cred(user2data, conn, message):
    # collect input of username and password
read_cred(cred_file):
    # read in all user credentials from file and generate a table for user information

Functions in Client:
In the client it starts the three threads mentioned in 1, and keep detecting input, receiving messages, sending heart beat and check ctrl+c in main thread.
create_socket(ser_name):
    # create a socket
send_message(message):
    # send a message to server
send_message_peer(user_mess):
    # send a message to peer
thread_keyboard(serverPort, serverName):
    # thread that is used for the input detection and message sending
thread_heartbeat(serverPort, serverName):
    # thread that is used to send heartbeat to server every heartbeat_time
thread_receiving(serverPort, serverName):
    # thread that is used to listen and receive to income messages
validate():
    # validate the identity of user



3. Since it is in python, you can just start the scripts of server, then the client.



4. Sample commands to run the program:
start server:
python server2.py

start client:
python client2.py [IP of server]

send message:
message <user> <message>

broadcast:
broadcast <message>

get online list:
online

block user:
block <user>

unblock user:
unblock <user>

logout:
logout

get private user information for peer-peer connection:
getaddress <user>

send private message to peer:
private <user> <message>

keyboard exit:
ctrl+c



5. The additional feathers are as described in PA1 requiremnts: 
(1) P2P Privacy and Consent
When A requests for B¡¯s IP address, the message centre should notify B that A wants to talk it. If B agrees to the conversation, the server should provide A with B¡¯s IP address. Else, A cannot initiate a conversation with B.
When A requests for B¡¯s IP address, the message centre should check B¡¯s
blacklist preferences. If B¡¯s blacklist includes A, the message centre should not
provide B¡¯s IP address to A.
(2) Guaranteed Message Delivery
By the problem definition, the server maintains a database of the clients and their IP addresses. Sometimes, this database might be outdated and the client might actually be offline. For e.g. if the client has been disconnected abruptly, and the message centre is still waiting for timeout. In this case, the sending client will attempt to connect to the last known IP of the receiving client and the connection will fail. Such failure should be handled and the sender can recontact the server to leave an offline message. Also, if the receiving client logs in with a new IP, the sending client should also be aware of this and not sending message to the old IP any more.

sample run for (1):

peer 1:
getaddress columbia
Request sent out to columbia

peer 2:
Would you like to provide information to the following user? (Y/N)
seas
Y

peer 1:
Information acquired.


sample run for (2):

peer 1:
private columbia abc
The user information is no longer active. You may try sending offline message.