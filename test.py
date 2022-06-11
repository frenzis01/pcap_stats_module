from turtle import end_fill
from more_itertools import last
import scapy.all
from scapy.all import *

mac_A = "1c:75:08:3c:c5:57"
mac_RasPi = "dc:a6:32:aa:22:9d"
mac_l = [mac_A,mac_RasPi]

# finds a packet with ip_src ip_dst sent to mac_dst
def find_pkt(mac_dst_list, ip_src, ip_dst, pcap, start_index):
   last_index = -1
   for pkt in pcap[start_index:]:
      last_index += 1
      if(pkt.dst in mac_dst_list and pkt[IP].src == ip_src and pkt[IP].dst == ip_dst):
         return pkt,last_index
   return None, -1

def avg_delta_pkts(pcap, echo):
   time_sum = 0.0
   t_start = t_end = 0.0
   n = 0
   pkt_prev = pcap[0]
   for pkt in pcap:
      # consider only pkts B->A
      if (echo == True and pkt.dst != mac_A and pkt.dst != mac_RasPi):
         continue
      if (echo == False and (pkt.dst == mac_A or pkt.dst == mac_RasPi)):
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
   rtt_sum = 0.0
   n = 0
   pkt_index = -1
   last_echo_index = 0
   for pkt in pcap:
      pkt_index += 1
      if (pkt.dst == mac_A or pkt.dst == mac_RasPi):
         continue
      try:
         pkt_echo, last_echo_index = find_pkt(mac_l,pkt[IP].src,pkt[IP].dst, pcap, last_echo_index)
         if (last_echo_index == -1):
            pkt_echo, last_echo_index = find_pkt(mac_l,pkt[IP].src,pkt[IP].dst, pcap, pkt_index)
      except Exception as e:
         print(traceback.format_exc())
         print(pkt.summary(), "\n", pkt_echo.summary(), "\n index ->", pkt_index)
         print("pkt-> ,",pkt[IP].src,pkt[IP].dst)
         print("pkt_echo-> ,",pkt_echo[IP].src,pkt_echo[IP].dst)
         print(pcap.listname)
         
      if (pkt_echo != None): # should never enter this
         rtt_sum += pkt_echo.time - pkt.time
         n += 1
   return rtt_sum/n



import json

def get_paths(path):
   import os
   import sys
   import fnmatch
   pcap_paths = []
   for path,dirs,files in os.walk(path):
      for f in fnmatch.filter(files,'*.pcap'):
         fullname = os.path.abspath(os.path.join(path,f))
         pcap_paths.append(fullname)
   
   pcap_paths.sort(reverse=False)
   return pcap_paths

def read_pcap(path):
   print(path, " Reading...")
   ret = rdpcap(path)
   # sys.stdout.write("\033[F")
   # sys.stdout.write("\033[K")
   print(path[path.rfind("/",0,path.rfind("/"))+1:], " DONE")
   ret.listname = path[path.rfind("/",0,path.rfind("/"))+1:]
   return ret

class pcap_stats:
   def __init__(self, name, avg_time, ppsB, ppsA, rtt):
      self.name = name
      self.avg_time = avg_time
      self.ppsB = ppsB
      self.ppsA = ppsA
      self.rtt = rtt
   
   def toJSON(self):
      return self.__dict__
      # return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent = 4)

def write_pcaps_stats(pcap_paths, json_path):
   stats  = []
   for path in pcap_paths:
      pcap = read_pcap(path)
      x = (avg_delta_pkts(pcap,True))
      y = (avg_delta_pkts(pcap,False))
      rtt = avg_rtt(pcap)
      stats.append(pcap_stats(pcap.listname,str(x[0]),str(x[1]),str(y[1]),str(rtt)))
      print(stats[-1].toJSON())
   print(json.dumps(stats,default=lambda o: o.toJSON(), indent=4))
   f = open(json_path, "w")
   f.write(json.dumps(stats,default=lambda o: o.toJSON(), indent=4))
   f.close()
   return stats

def test():
   write_pcaps_stats(get_paths(".."), "complete_stats_.json")