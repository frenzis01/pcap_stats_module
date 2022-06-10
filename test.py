from turtle import end_fill
import scapy.all
from scapy.all import *

mac_A = "1c:75:08:3c:c5:57"
mac_RasPi = "dc:a6:32:aa:22:9d"

def delta(pcap):
   # finds a packet with ip_src ip_dst sent to mac_dst
   def find_pkt(mac_dst, ip_src, ip_dst):
      for pkt in pcap:
         if(pkt.dst == mac_dst and pkt[IP].src == ip_src and pkt[IP].dst == ip_dst):
            return pkt
   

   ref = pcap[0].time      # ms since epoch
   print("Setting time reference at ", ref)

   delta_sum = []       # delta_sum[i] = sum of deltas of the conversations started before i
   delta_all = []       # delta_all[i] = delta_time of the i-conversation
   sent_pkt_index = 0   # counter

            

   def delta_time(pkt, index):
      
      # assuming n is the n-th pkt sent A->B
      def calc_delta_sum(n):
         pkt_n = pcap[n]
         delta_sum.append(0.0);
         for i in range(n):
            pkt = pcap[i]
            # Consider only the packets A->B
            if (pkt.dst == mac_A):
               continue
            pkt_echo = find_pkt(mac_A,pkt[IP].src, pkt[IP].dst)
            if (pkt_echo.time > pkt_n.time): # if 'n' was sent before pkt came back
               delta_sum[n] += delta_all[i]  # add pkt delta to n
            else:
               print("------------------------------DEBUG------------")
      
      # Consider only the packets A->B
      if (pkt.dst == mac_A):
         return
      # find the "echo" packet, the one sent B->A
      pkt_echo = find_pkt(mac_A,pkt[IP].src, pkt[IP].dst)
      if (pkt_echo == None):  # I should never enter this
         print("No matching packet found!")
         return
      duration = pkt_echo.time - pkt.time
      delta = duration # we will change this later. Now it represents "Duration"
      if (index == 0):  # first packet
         delta_sum.append(pkt_echo.time - pkt.time)
      else:
         delta = delta - delta_sum[index - 1] # t1 - t0 - (\sum(deltas of the packets sent before))
         # delta_sum.append(delta_sum[index - 1] + delta)
         calc_delta_sum(index)
         delta_sum[index] += delta
      delta_all.append(delta)    # save delta
      print(index, "\t: ", pkt.time - ref , pkt_echo.time - ref, duration , delta , end="")
      print( "\t| ", delta_sum[index])
      return delta

   print ("index\t   1st pkt  2nd pkt  duration delta        delta_sum")
   for pkt in pcap:
      # Consider only the packets A->B
      if (pkt.dst == mac_A):
         continue

      delta = delta_time(pkt,sent_pkt_index)
      if (delta != None): # I should always enter this
         sent_pkt_index+= 1

      # if (sent_pkt_index == 100):
      #    break

def avg_delta_echopkts(pcap):
   time_sum = 0.0
   t_start = t_end = 0.0
   n = 0
   pkt_prev = pcap[0]
   for pkt in pcap:
      # consider only pkts B->A
      if (pkt.dst != mac_A and pkt.dst != mac_RasPi):
         continue
      if (n != 0):
         time_sum += pkt.time - pkt_prev.time
         t_end = pkt.time
      else:
         t_start = pkt.time
      pkt_prev = pkt
      n += 1
   
   print(pcap.listname, time_sum, n,t_end, t_start )
   return time_sum/n, n/(t_end-t_start)

def avg_rtt(pcap):
   for(pcap)

def read_pcaps():
   import os
   import sys
   import fnmatch

   pcap_files = []
   pcap_paths = []
   for path,dirs,files in os.walk('.'):
      for f in fnmatch.filter(files,'*.pcap'):
         fullname = os.path.abspath(os.path.join(path,f))
         pcap_paths.append(fullname)
   
   pcap_paths.sort()
   # print(*pcap_paths, sep='\n')
   for path in pcap_paths:
      print(path, " Reading...")
      pcap_files.append(rdpcap(path))
      sys.stdout.write("\033[F")
      sys.stdout.write("\033[K")
      print(path[path.rfind("/",0,path.rfind("/"))+1:], " DONE")
      pcap_files[-1].listname = path[path.rfind("/",0,path.rfind("/"))+1:]
   return pcap_files

import json
import decimal

class pcap_stats:
   def __init__(self, name, avg_time, pps):
      self.name = name
      self.avg_time = avg_time
      self.pps = pps
   
   def toJSON(self):
      return self.__dict__
      # return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent = 4)

def write_pcaps_stats(pcap_files, json_path):
   stats  = []
   for pcap in pcap_files:
      x = (avg_delta_echopkts(pcap))
      stats.append(pcap_stats(pcap.listname,str(x[0]),str(x[1])))
      print(stats[-1].toJSON())
   print(json.dumps(stats,default=lambda o: o.toJSON(), indent=4))
   f = open(json_path, "w")
   f.write(json.dumps(stats,default=lambda o: o.toJSON(), indent=4))
   f.close()
   return stats