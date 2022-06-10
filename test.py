from turtle import end_fill
import scapy.all
from scapy.all import *

mac_A = "1c:75:08:3c:c5:57"
mac_RasPi = "dc:a6:32:aa:22:9d"

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
