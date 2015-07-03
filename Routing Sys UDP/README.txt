1. General discription of programming design and data structure

The program implement Bellman-Ford algorithm to build a distributed distance vector routing system. Host is represented as a class.
When host starts up, it first initialize the configuration from file, then according to the file set a routing table and vector. The routing table is of the format(dict in python): 
{node1:{node2: dist form node1 to node2, }, } 
where node1 can be self or neighbors, and the vector is of the format:
{node1:[dist to node1, ip of last hop, port of last hop],} 
where node1 can be any node that is ever reachable
Then the host send inital vector to neighbors. header contains source and destination information. Data contains the distance from host itself to other ever reachable nodes, and if the distance has any via nodes. Host starts thread timing for timeout events, and thread for receiving and processing packets. The main thread is waiting for keyboard input.
Every timeout the host send out vector to active neighbors. Every 3*timeout if neighbors has no responce, it is taken to be closed and recorded. When vector received from neighbors, the routing table and vector is revised accordingly. When file transfer packet is received, if the destination is current host, write data to local file. If not, forward to next hop. Proper user input can be handled. 


2. Explanation of source code

Functions members of Host class:
__init__(self, con_file):
        # constructor, initialize class parameters and start the host.
read_config(self, con_file):
        # read initial configuration from file and initialize class parameters
start_host(self):
        # start the host:
        # 1. start thread to listen and process packet
        # 2. start thread to time items
thread_timing(self):
        # thread for timing timeout events
        # check if timeout is reached to send vector to neighbours, then send
        # check if any neighbors are offline, then update route_tab and vector accordingly
thread_recv(self):
        # thread for listening to self.port and process incoming packets
data_proc(self, packet, addr):
        # process packets according to header and data
        # unpack first and check for corruptions
        # if no corruptions, process (vector from neighbor/ACK/file packet); if yes, discard
forward(self, packet, dstip, dstp, srcip, srcp,  flags):
        # forward file transfer packet to next hop
update_table(self, data, length, sender):
        # update route_tab based on received vector from neighbors
send_ack(self, sender):
        # send ack to sender
send_vector(self):
        # send vector to all active neighbours. also indicating if the distance is via other nodes or direct link
send_packet(self, address, data):
        # send a packet with size 2048
gen_packet(self, srcip, dstip, srcp, dstp, seqn, ackn, flags, data):
        # generate packet with header
        # source ip(32), dest ip(32), source port(16), dest port(16), seqn(32), ackn(32), datalength(16), checksum(16), flags(16)
        # header->26 Bytes          data->2048 Bytes
        # flags(1)(most right) -> 0:routing update        1:file transfer
        # flags(2)             -> 0:packet                1:ACK
        # flags(3)             -> 0:file transferring     1:file done transfer
ip_str_to_num(self, ip):
        # convert ip to 32bits number
ip_num_to_str(self, ip_num):
        #convert 32bits number to ip
checksum(self, data):
        # calculate checksum
update_vector(self):
        # update vector according to routing table
comm_proc(self, comm):
        # process user commands
transfer(self, filename, addr ):
        # transfer file to next hop in chunks.
print_vector(self):
        # print current vector if user call showrt


3. Detailed instructions on how to run/compile your source code
Since it is in python, to run the host one can simply start the python script with line argument of config file.


4. Sample commands to run program
start host:
command: python client.py client0.txt

linkdown:
command: LINKDOWN 127.0.0.1 10004
result: link to 127.0.0.1:10004 is down

linkup:
command: LINKUP 127.0.0.1 10004
result: link to 127.0.0.1:10004 is up

change cost of link:
command: CHANGECOST 127.0.0.1 10004 20
result: link to 127.0.0.1:10004 is changed to 20

show routing table:
command: SHOWRT
result: 
<Fri May 08 13:13:23 2015> Distance vector list is:
Destination = 127.0.0.1:10002, Cost = 5.0, Link = (127.0.0.1:10002)
Destination = 127.0.0.1:10004, Cost = 30.0, Link = (127.0.0.1:10004)

close the host:
command: CLOSE
result: host closed, program exits.

transfer file:
command: TRANSFER abc.jpg 127.0.0.1 10004
result: file transfered, nodes on path print next hop if not final destination. File saved locally on final host.


5. Additional features (reliable file transfer) not implemented.




