#!/usr/bin/python

__author__ = "Marcin Kozlowski <marcinguy@gmail.com>"


"""
    This part is a fork of the python-ping project that makes 
    things work with gevent.
"""

import os
import struct
import sys
import time
import random

import gevent
from gevent import socket
from gevent.pool import Pool
from gevent.event import Event

import argparse
import pprint

from tqdm import tqdm

# From /usr/include/linux/icmp.h; your milage may vary.
ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.


def checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum = 0
    count_to = (len(source_string) / 2) * 2
    for count in xrange(0, count_to, 2):
        this = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum = sum + this
        sum = sum & 0xffffffff # Necessary?

    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer

def test_callback(ping):
    if(ping['success']):
      #print str(ping['dest_addr'])+","+str(ping['success'])
      resfile.write(str(ping['dest_addr'])+":"+str(ping['success'])+"\n")


class GPing:
    """
    This class, when instantiated will start listening for ICMP responses.
    Then call its send method to send pings. Callbacks will be sent ping
    details
    """
    def __init__(self,timeout=4,max_outstanding=2000):
        """
        :timeout            - amount of time a ICMP echo request can be outstanding
        :max_outstanding    - maximum number of outstanding ICMP echo requests without responses (limits traffic)
        """
        self.timeout = timeout
        self.max_outstanding = max_outstanding

        # id we will increment with each ping
        self.id = 0

        # object to hold and keep track of all of our self.pings
        self.pings = {}

        # event to file when we want to shut down
        self.die_event = Event()

        # setup socket
        icmp = socket.getprotobyname("icmp")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error, (errno, msg):
            if errno == 1:
                # Operation not permitted
                msg = msg + (
                    " - Note that ICMP messages can only be sent from processes"
                    " running as root."
                )
                raise socket.error(msg)
            raise # raise the original error

        self.receive_glet = gevent.spawn(self.__receive__)
        self.processto_glet = gevent.spawn(self.__process_timeouts__)


    def die(self):
        """
        try to shut everything down gracefully
        """
        self.die_event.set()
        socket.cancel_wait()
        gevent.joinall([self.receive_glet,self.processto_glet])


    def join(self):
        """
        does a lot of nothing until self.pings is empty
        """
        while len(self.pings):
            gevent.sleep()


    def send(self, dest_addr, callback, psize=64):
        """
        Send a ICMP echo request.
        :dest_addr - where to send it
        :callback  - what to call when we get a response
        :psize     - how much data to send with it
        """
        # make sure we dont have too many outstanding requests
        while len(self.pings) >= self.max_outstanding:
            gevent.sleep()

        #resolve hostnames
        dest_addr  =  socket.gethostbyname(dest_addr)

        # figure out our id
        packet_id = self.id

        # increment our id, but wrap if we go over the max size for USHORT
        self.id = (self.id + 1) % 2 ** 16


        # make a spot for this ping in self.pings
        self.pings[packet_id] = {'sent':False,'success':False,'error':False,'dest_addr':dest_addr,'callback':callback}

        # Remove header size from packet size
        psize = psize - 8

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        my_checksum = 0

        # Make a dummy heder with a 0 checksum.
        header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, packet_id, 1)
        bytes = struct.calcsize("d")
        data = (psize - bytes) * "Q"
        data = struct.pack("d", time.time()) + data

        # Calculate the checksum on the data and the dummy header.
        my_checksum = checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack(
            "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packet_id, 1
        )
        packet = header + data
        # note the send_time for checking for timeouts
        self.pings[packet_id]['send_time'] = time.time()

        # send the packet
        self.socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1

        #mark the packet as sent
        self.pings[packet_id]['sent'] = True


    def __process_timeouts__(self):
        """ 
        check to see if any of our pings have timed out 
        """
        while not self.die_event.is_set():
            for i in self.pings:
                if self.pings[i]['sent'] and time.time() - self.pings[i]['send_time'] > self.timeout:
                    self.pings[i]['error'] = True
                    self.pings[i]['callback'](self.pings[i])
                    #resfile.write(str(self.pings[i]['dest_addr'])+":False\n")
                    resfile.write(str(self.pings[i]['dest_addr']) + ":False\n")
                    del(self.pings[i])
                    break
            gevent.sleep()


    def __receive__(self):
        """ 
        receive response packets 
        """
        while not self.die_event.is_set():
            # wait till we can recv
            try:
                socket.wait_read(self.socket.fileno())
            except socket.error, (errno,msg):
                if errno == socket.EBADF:
                    print "interrupting wait_read"
                    return
                # reraise original exceptions
                print "re-throwing socket exception on wait_read()"
                raise

            time_received = time.time()
            received_packet, addr = self.socket.recvfrom(1024)
            icmpHeader = received_packet[20:28]
            type, code, checksum, packet_id, sequence = struct.unpack(
                "bbHHh", icmpHeader
            )
            
            if packet_id in self.pings:
                bytes_received = struct.calcsize("d")
                time_sent = struct.unpack("d", received_packet[28:28 + bytes_received])[0]
                self.pings[packet_id]['delay'] = time_received - time_sent

                # i'd call that a success
                self.pings[packet_id]['success'] = True

                # call our callback if we've got one
                self.pings[packet_id]['callback'](self.pings[packet_id])

                # delete the ping
                del(self.pings[packet_id])



if __name__ == '__main__':
    if os.geteuid() != 0:
      exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

    parser = argparse.ArgumentParser(description='GPing Scanner v0.99')
    parser.add_argument('-i','--input', help='Input list of IPs', required=True)
    parser.add_argument('-o','--output', help='Output', required=True)
    parser.add_argument('-s','--shuffle', help='Shuffle', required=True)
    args = parser.parse_args()
    input = args.input
    output = args.output
    shuffle = args.shuffle
    
    if(shuffle == "yes"):
      with open(input,'rU') as f:
        lines = f.read().splitlines()
      random.shuffle(lines)
      data = lines
    else:
      with open(input,'rU') as f:
        lines = f.read().splitlines()
      data = lines

    resfile = open(output,'w')
   
    gp = GPing()
    #for domain in tqdm(data):
    for domain in data:
        temp=domain.rstrip()
        hostname=temp.split(',')[0]
        #print hostname
        gp.send(hostname,test_callback)
    gp.join()
