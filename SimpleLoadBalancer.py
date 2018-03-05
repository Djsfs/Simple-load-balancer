
#  Author:  Atzamis Iosif 
#  Purpose: CloudNetController
#  E-mail: 
#  Language:  Python
 

from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random

class SimpleLoadBalancer(object):
    def __init__(self, service_ip, server_ips = []): #initialize
        core.openflow.addListeners(self)
        #write your code here!!!
        print '______- Simple Load Balancer -______'



        self.macToPort={}   
        self.service_ip=service_ip
        self.servers=server_ips #ip of servers
        self.servers_mac=[] #mac of servers
        self.servers_port=[] #port of servers
        self.clients_ip={}  #clients ip
        self.clients_MAC={} #clients mac
        self.clients_port={} #clients port
        
        self.servers_macs={} #key ip value mac
        self.servers_ports={} #key ip value ports
        self.c=0
        self.clients_counter=0



        self.total_servers=len(server_ips)
        for w in range (0,len(server_ips)):
            self.c=self.c+1                                                                         #counter of the servers

            ipv_4=str(server_ips[w]).split('.')                                                     #list apo ta psifia ths ip
            print 'Server has IP  list::\n',self.servers[w]

            self.servers_mac.append(EthAddr('00:00:00:00:00:0'+ipv_4[len(server_ips)-1]))           #put servers MAC in a list
            print 'Server has MAC addresses list::\n',self.servers_mac

        print '\n\nThis is service ip',service_ip                                                   #Load Balancer Ip address

        print '______- End of Constractor -______\n\n'

    def _handle_ConnectionUp(self, event): #new switch connection

        self.lb_mac = EthAddr("0A:00:00:00:00:01") #fake mac of load balancer
        self.broadcast = EthAddr(b"\xff\xff\xff\xff\xff\xff") #highest mac 
        self.connection = event.connection

        for server_ip in self.servers:
            print '\nWe call proxied arp request for every server:'
            self.send_proxied_arp_request(self.connection, server_ip)   


        pass

    def update_lb_mapping(self, client_ip): #update load balancing mapping
        #write your code here!!!
        pass
        
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        
        # Create the ARP reply
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = requested_mac
        arp_reply.hwdst = packet.src
        arp_reply.protosrc = self.service_ip
        arp_reply.protodst = packet.payload.protosrc

        #Create ETHERNET packet
        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = packet.src
        ether.src = requested_mac
        ether.payload = arp_reply

        #Create OPENFLOW message
        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = outport
        self.connection.send(msg)
        #write your code here!!!
        pass
        
    def send_proxied_arp_request(self, connection, ip):
        print '\n_____- SEND PROXIED ARP REQUEST -______'
        print 'send arp request to : '+str(ip)
        
        # Create the ARP request

                                                        #here is the arp header
        req = arp()                                     #we call arp function
        req.hwtype = req.HW_TYPE_ETHERNET
        req.prototype = req.PROTO_TYPE_IP
        req.opcode = req.REQUEST
        req.hwsrc = self.lb_mac                         # mac to loadbalancer
        req.protosrc = self.service_ip                  # ip tou loadbalancer
        req.hwdst = self.broadcast                      # to blepoun oloi
        req.protodst = ip

        #Create ETHERNET packet
                                                #Ethernet packet
        eth = ethernet(type=ethernet.ARP_TYPE, src=self.lb_mac, dst=self.broadcast)
        eth.set_payload(req)                            #we make the ethernet packet
        
        #Create OPENFLOW message
        msg = of.ofp_packet_out()
        msg.data = eth.pack()   
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = of.OFPP_NONE #se auton pou to stelnoume den xreiazetai na vlepei kapoia porta
        self.connection.send(msg)   #stelnoume to message

        print '_____- END OF ARP REQUEST -_____'
    
    def install_flow_rule_client_to_server(self, connection, outport, client_ip, 
                        server_ip, buffer_id=of.NO_BUFFER):

        fm = of.ofp_flow_mod()
        fm.match.in_port =of.OFPP_FLOOD
        fm.actions.append(of.ofp_action_output(port =outport))

        #write your code here!!!
        pass
        
    def install_flow_rule_server_to_client(self, connection, outport, server_ip, 
                        client_ip, buffer_id=of.NO_BUFFER):

        fm = of.of.ofp_flow_mod()
        fm.match.in_port =2
        fm.actions.append(of.ofp_action_output(port =outport))

        #write your code here!!!
        pass
        
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port


        mark=0                                                                      # 0 means that we didnt find the ip of a client in the existed clients dictionary and we have to add it 
                                                                                    # 1 means that we the ip of a client exists in the clients dictionary

        if packet.type == packet.ARP_TYPE:                                          #ARP TYPE MESSAGE
            if packet.payload.opcode == packet.payload.REQUEST:

                for keys in range(0,self.c) :                                       
                    if packet.payload.protodst == self.servers[keys]:               #arp request from client to switch
                        print'ARP Request Package from client to switch\n'
                        for i in range (0,self.clients_counter): 
                            print 'MPAINWWWW:d '                   
                            if self.clients_ip[i]==packet.payload.protodst:         #check if client exist in the clients dictionary
                                mark=1
                                print 'This client allready exist in  the Dictionaries'


                        if (mark == 0) :                                            #Update clients dictionarys
                            lastdigit=str(packet.payload.protodst).split('.')
                            self.clients_MAC[IPAddr(packet.payload.protodst)]='00:00:00:00:00:0'+lastdigit[len(packet.payload.protodst)-1]
                            self.clients_port[IPAddr(packet.payload.protodst)]=lastdigit[len(packet.payload.protodst)-1]
                            self.send_proxied_arp_reply(packet, connection, inport,self.lb_mac)

                            print 'This is the [IP] of clients :MAC\n'                  #prints the dictionaries
                            for keys,values in self.clients_MAC.items():
                                print '        IP:',keys
                                print '       MAC:',values

                                print '\n\nThis is the [IP] of clients :PORT\n'
                                for keys,values in self.clients_port.items():
                                    print '        IP:',keys
                                    print '      PORT:',values                        
                        else:
                            print 'Wrong ARP request'
                #self.send_proxied_arp_reply(packet, connection, inport,self.lb_mac)



            elif packet.payload.opcode == packet.payload.REPLY:
                print '________________THIS IS AN ARP REPLY____________________\n'
                print '_____ FROM',packet.src,'->',self.lb_mac,'______\n'
                for i in range (0,self.c):
                    if packet.payload.protosrc== self.servers[i] :                  #update map
                        self.servers_macs[packet.payload.protosrc]=packet.src       # [IP]:MAC
                        self.servers_ports[packet.payload.protosrc]=inport          # [IP]:PORT
                        

                        print 'This is the [IP] of servers :MAC\n'                  #prints the Dictionaries
                        for keys,values in self.servers_macs.items():
                            print '        IP:',keys
                            print '       MAC:',values

                        print '\n\nThis is the [IP] of servers :PORT\n'
                        for keys,values in self.servers_macs.items():
                            print '        IP:',keys
                            print '      PORT:',values
                        self.macToPort
                print '\n_____________________ARP REPLY END ___________________\n'                

        elif packet.type == packet.IP_TYPE:
            #write your code here!!!

            # if From Client to Switch
                #update_lb_mapping
                #install_flow_rule_client_to_server


            # IP from SERVER to CLIENT that not have been added from client to switch
                #install_flow_rule_server_to_client
            
            # else 
                #Drop the packet

            pass
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return

#launch application with following arguments:   
#ip: public service ip, servers: ip addresses of servers (in string format)
def launch(ip, servers): 
    log.info("Loading Simple Load Balancer module")
    server_ips = servers.replace(","," ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    service_ip = IPAddr(ip)
    core.registerNew(SimpleLoadBalancer, service_ip, server_ips)