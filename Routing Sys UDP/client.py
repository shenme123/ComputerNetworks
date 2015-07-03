import socket
import sys
import re
import threading
import struct
import time
import datetime

class Host(object):
    def __init__(self, con_file):
        # constructor, initialize class parameters and start the host.
        # class parameters: ip, port, timeout, route table, neighbors, distance vector,transfered file,
        # nodes unreachable (timeout*3 nodes), time of sending last vector, socket used for sending
        self.ip = socket.gethostbyname(socket.gethostname())
        #self.ip = '127.0.0.1'
        # route_tab: {node1:{node2: dist form node1 to node2, }}
        self.port, self.timeout, self.route_tab, self.neighbors, self.vector = self.read_config(con_file)
        self.file_trans = None
        self.unreachables = set()
        self.time_last_update = 0
        self.start_host()
        self.skt_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def read_config(self, con_file):
        # read initial configuration from file and initialize class parameters
        con = open(con_file, 'r')
        tokens = con.readline().strip().split()
        port = int(tokens[0])
        timeout = int(tokens[1])
        route_tab = {}
        tab = {}
        vector = {}
        neighbors = {}
        # add self to vector
        tab[(self.ip, port)] = 0
        vector[(self.ip, port)] = [0, '0', 0]
        cur_time = time.time()
        # add neighbours to neighbours, vector and route table
        for line in con:
            if line.strip():
                tokens = re.split(' |:', line.strip())
                tab[(tokens[0], int(tokens[1]))] = float(tokens[2])
                neighbors[(tokens[0], int(tokens[1]))] = {"ACTIVE":True, "LASTHEARD":cur_time, "ORIGDIST":float(tokens[2])}
                vector[(tokens[0], int(tokens[1]))] = [float(tokens[2]), '0', 0]
        # add self
        route_tab[(self.ip, port)] = tab
        return port, timeout, route_tab, neighbors, vector

    def start_host(self):
        # start the host:
        # 1. start thread to listen and process packet
        # 2. start thread to time items
        recv = threading.Thread(target = self.thread_recv)
        recv.daemon = True
        recv.start()
        timer = threading.Thread(target=self.thread_timing)
        timer.daemon = True
        timer.start()

    def thread_timing(self):
        # thread for timing timeout events
        self.send_vector()
        self.time_last_update = time.time()
        # keep checking time:
        while 1:
            time_cur = time.time()
            # check if timeout is reached to send vector to neighbours
            if time_cur - self.time_last_update >= self.timeout:
                self.send_vector()
                self.time_last_update = time.time()
            # check if any neighbors are offline and update route_tab and vector accordingly
            for nei, attr in self.neighbors.items():
                if attr["ACTIVE"] == True:
                    if time_cur - attr["LASTHEARD"] > 3*self.timeout:
                        self.neighbors[nei]["ACTIVE"] = False
                        self.unreachables.add(nei)
                        if nei in self.route_tab:
                            self.route_tab.pop(nei)
                        self.route_tab[(self.ip, self.port)][nei] = float('inf')
                        self.update_vector()
            time.sleep(0.2)

    def thread_recv(self):
        # thread for listening to self.port and process incoming packets
        skt_listn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt_listn.bind(('', self.port))
        while 1:
            # receive packets
            packet, addr = skt_listn.recvfrom(2074)
            # process packets
            self.data_proc(packet, addr)

    def data_proc(self, packet, addr):
        # process packets according to header and data
        # unpack first and check for corruptions
        srcip, dstip, srcp, dstp, seqn, ackn, length, checksum, flags, data = struct.unpack('!LLHHLLHHH2048s',packet)
        recon = struct.pack('!LLHHLLHHH2048s',srcip, dstip, srcp, dstp, seqn, ackn, length, 0, flags, data)
        checksum_re = self.checksum(recon)
        # if no corruptions, process; if yes, discard
        if checksum==checksum_re:
            # if checksum correct: 1. send ACK   2. update vector & route_tab
            sender = (addr[0], srcp)
            if sender in self.unreachables:
                self.unreachables.remove(sender)
            if flags&1==0: # is update_vector packet
                if flags>>1 & 1==0:   # is update packet not ACK
                    #self.neighbors[sender]["ACTIVE"] = True
                    self.neighbors[sender]["LASTHEARD"] = time.time()
                    self.update_table(data, length, sender)
                    #print "table after update:"
                    #self.print_table()
                    self.update_vector()
                    self.send_ack(sender)
                else:   # is ACK
                    # reset timeer of sender
                    self.neighbors[sender]['LASTHEARD'] = time.time()
            elif flags&1==1:    # is file transfer packet
                dstip = self.ip_num_to_str(dstip)
                srcip = self.ip_num_to_str(srcip)
                # if final dest., write to file.
                if self.ip == dstip and self.port == dstp:
                    if seqn==0:
                        filename = data[:length]
                        self.file_trans = open(filename, "ab")
                    elif flags>>2 &1 == 1:
                        self.file_trans.close()
                        print "Packet received"
                        print "Source = "+srcip+":"+str(srcp)
                        print "Destination = "+dstip+":"+str(dstp)
                        print "File received successfully"
                    else:
                        self.file_trans.write(data[:length])
                # if not final dest., forward
                else:
                    self.forward(packet, dstip, dstp, srcip, srcp,  flags )
        


    def forward(self, packet, dstip, dstp, srcip, srcp,  flags):
        # forward file transfer packet to next hop
        dst = (dstip, dstp)
        next_ip = self.vector[dst][1]
        next_port = self.vector[dst][2]
        if next_ip == '0':
            next_ip = dstip
            next_port = dstp
        self.skt_send.sendto(packet, (next_ip, next_port))
        if flags>>2&1 == 1:
            print "Packet received"
            print "Source = "+srcip+":"+str(srcp)
            print "Destination = "+dstip+":"+str(dstp)
            print "Next hop = " + next_ip+":"+str(next_port)


    def update_table(self, data, length, sender):
        # update route_tab based on received vector from neighbors
        lines = data[:length].strip().split('\n')
        tab = {}
        flag = False
        for line in lines:
            tokens = line.split('#')
            if (tokens[0], int(tokens[1])) in self.unreachables:
                tab[(tokens[0], int(tokens[1]))] = float('inf')
            else:
                tab[(tokens[0], int(tokens[1]))] = float(tokens[2])
            if (tokens[0], int(tokens[1])) == (self.ip, self.port) and tokens[3] == '1':
                flag = True
        dist = tab[(self.ip, self.port)]
        if flag and dist!= self.route_tab[(self.ip, self.port)][sender]:
            self.route_tab[(self.ip, self.port)][sender] = dist
        for key in tab:
            tab[key] += self.route_tab[(self.ip, self.port)][sender]
        self.route_tab[sender] = tab
        for key in tab:
            if key not in self.vector:
                self.vector[key] = [float("inf"), '0', 0]

    def send_ack(self, sender):
        # send ack to sender
        ack = self.gen_packet(self.ip, sender[0], self.port, sender[1],0, 0, 2, "")
        self.skt_send.sendto(ack, (sender[0], sender[1]))

    def send_vector(self):
        # send vector to all active neighbours. also indicating if the distance is via other nodes or direct link
        for nei in self.neighbors:
            if self.neighbors[nei]["ACTIVE"]:
                vector_data = ''
                for key, val in self.vector.items():
                    vector_data = vector_data+key[0]+"#"+str(key[1])+"#"
                    if (val[1], val[2])!= nei:
                        vector_data = vector_data+str(val[0])+"#"
                    else:
                        vector_data += "inf#"
                    if val[1] != '0':
                        vector_data += "0\n"      # 0 for via other node, 1 for direct link
                    else:
                        vector_data += "1\n"
                self.send_packet(nei, vector_data)

    def send_packet(self, address, data):
        # send a packet with size 2048
        for ind in range(0, len(data), 2048):
            chunk = data[0:2048]
            ################################### add seq, flags, ackn, etc
            packet = self.gen_packet(self.ip, address[0], self.port, address[1], 0, 0, 0, chunk)
            self.skt_send.sendto(packet, (address[0], address[1]))

    def gen_packet(self, srcip, dstip, srcp, dstp, seqn, ackn, flags, data):
        # generate packet with header
        # source ip(32), dest ip(32), source port(16), dest port(16), seqn(32), ackn(32), datalength(16), checksum(16), flags(16)
        # header->26 Bytes          data->2048 Bytes
        # flags(1)(most right) -> 0:routing update        1:file transfer
        # flags(2)             -> 0:packet                1:ACK
        # flags(3)             -> 0:file transferring     1:file done transfer
        checksum = 0
        length = len(data)
        srcip = self.ip_str_to_num(srcip)
        dstip = self.ip_str_to_num(dstip)
        packet = struct.pack('!LLHHLLHHH2048s',srcip, dstip, srcp, dstp, seqn, ackn, length, checksum, flags, data)
        checksum = self.checksum(packet)
        packet_final = struct.pack('!LLHHLLHHH2048s', srcip, dstip, srcp, dstp, seqn, ackn, length, checksum, flags, data)
        return packet_final

    def ip_str_to_num(self, ip):
        # convert ip to 32bits number
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]

    def ip_num_to_str(self, ip_num):
        #convert 32bits number to ip
        return socket.inet_ntoa(struct.pack('!L', ip_num))

    def checksum(self, data):
        # calculate checksum
        s = 0
        n = len(data)%2
        for i in range(0, len(data)-n, 2):
            s+= ord(data[i]) + (ord(data[i+1])<<8)
        if n:
            s+= ord(data[i+1])
        while (s>>16):
            s = (s & 0xFFFF) + (s>>16)
        s = ~s & 0xffff
        return s

    def update_vector(self):
        # update vector according to routing table
        #print "table:"
        #self.print_table()
        vector = dict(self.vector)
        for key in vector:
            vector[key] = [float("inf"), '0', 0]
        for key_v, val_v in vector.items():
            if key_v not in self.unreachables:
                for key_r, val_r in self.route_tab.items():
                    if key_v in val_r and val_r[key_v] < val_v[0]:
                        val_v[0] = val_r[key_v]
                        if key_r != (self.ip, self.port):
                            val_v[1] = key_r[0]
                            val_v[2] = key_r[1]
                        else:
                            val_v[1] = '0'
                            val_v[2] = 0
                    elif key_v in val_r and val_r[key_v] == val_v[0]:
                        if key_r == (self.ip, self.port):
                            val_v[1] = '0'
                            val_v[2] = 0
        self.vector = vector
        #self.print_vector()

    def comm_proc(self, comm):
        # process user commands
        tokens = comm.strip().split()
        if tokens[0].upper() == "LINKDOWN" and len(tokens) == 3:   # linkdown
            addr = (tokens[1], int(tokens[2]))
            if addr in self.neighbors and self.neighbors[addr]["ACTIVE"]:
                self.route_tab[(self.ip, self.port)][addr] = float("inf")
                self.route_tab[addr][addr] = float("inf")
                self.update_vector()
                self.send_vector()
                self.neighbors[addr]["ACTIVE"] = False
                print "Linkdown done."
        elif tokens[0].upper() == "LINKUP" and len(tokens) == 3:    # linkup
            addr = (tokens[1], int(tokens[2]))
            if addr in self.neighbors and not self.neighbors[addr]["ACTIVE"]:
                self.route_tab[(self.ip, self.port)][addr] = self.neighbors[addr]["ORIGDIST"]
                self.neighbors[addr]["ACTIVE"] = True
                self.update_vector()
                self.send_vector()
                print "Linkup done."
        elif tokens[0].upper() == "CHANGECOST" and len(tokens) == 4:    # change cost
            addr = (tokens[1], int(tokens[2]))
            if addr in self.neighbors and self.neighbors[addr]["ACTIVE"]:
                self.route_tab[(self.ip, self.port)][addr] = float(tokens[3])
                self.route_tab[addr][addr] = float(tokens[3])
                self.update_vector()
                self.send_vector()
                print "Changecost done."
        elif tokens[0].upper() == "SHOWRT":         # showrt
            self.print_vector()
        elif tokens[0].upper() == "TRANSFER" and len(tokens) == 4:  # transfer file
            file = tokens[1]
            addr = (tokens[2], int(tokens[3]))
            if addr in self.vector and self.vector[addr][0]<float("inf"):
                self.transfer(file, addr)

    def transfer(self, filename, addr ):
        # transfer file to next hop in chunks.
        file = open(filename, 'rb')
        # first chunk: filename
        chunk = filename.strip().split("/")[-1]
        next_ip = self.vector[addr][1]
        next_port = self.vector[addr][2]
        if next_ip == '0':
            next_ip = addr[0]
            next_port = addr[1]
        seqn = 0
        print "Next hop = "+next_ip+":"+str(next_port)
        # transfer data in packets
        while chunk:
            packet = self.gen_packet(self.ip, addr[0], self.port, addr[1], seqn, 0, 1, chunk)
            self.skt_send.sendto(packet, (next_ip, next_port))
            chunk = file.read(2048)
            seqn = (seqn+1)%(2**32)
        packet = self.gen_packet(self.ip, addr[0], self.port, addr[1], seqn, 0, 5, chunk)
        self.skt_send.sendto(packet,(next_ip, next_port) )
        print "File sent successfully"



    def print_vector(self):
        # print current vector if user call showrt
        print "<"+str(time.asctime( time.localtime(time.time()) ))+"> Distance vector list is:"
        for i in self.vector:
            if i != (self.ip, self.port):
                mess = "Destination = "+i[0]+":"+str(i[1])+", Cost = "+str(self.vector[i][0])+", Link = ("
                if self.vector[i][1]=='0':
                    mess = mess + i[0]+":"+str(i[1]) +")"
                else:
                    mess = mess + self.vector[i][1]+" "+str(self.vector[i][2])+")"
                print mess
        print

    def print_table(self):
        # print route table for debugging
        for key, val in self.route_tab.items():
            print key, val


# input argument for config file
config_file = sys.argv[1]
# generate an instance of host
host = Host(config_file)
flag_exit = True
# start keyboard track and exit loop/program if see keyboard input "close"
print "Host started..."
while flag_exit:
    print "Please type command:"
    comm = raw_input()
    tokens = comm.strip().split()
    if tokens[0].upper() == "CLOSE":
        break
    host.comm_proc(comm)
