import scapy.all
import json
from scapy.all import *

mac_A = "1c:75:08:3c:c5:57"
mac_RasPi = "dc:a6:32:aa:22:9d"
mac_l = [mac_A,mac_RasPi]


# avg time difference between packets sent by A or B and
# estimated pps A->B or B->A
# 'echo' boolean parameter affects the traffic direction
# useful when queueing is happening
def avg_delta_pkts(pcap, echo):
   time_sum = 0.0
   t_start = t_end = 0.0
   n = 0
   pkt_prev = pcap[0]
   for pkt in pcap:
      # consider only pkts B->A...
      if (echo == True and pkt.dst != mac_A and pkt.dst != mac_RasPi):
         continue
      # ... or only A->B
      if (echo == False and (pkt.dst == mac_A or pkt.dst == mac_RasPi)):
         continue

      if (n != 0): # base case
         time_sum += pkt.time - pkt_prev.time
         t_end = pkt.time
      else: # first pkt, there is no pkt_prev
         t_start = pkt.time
      pkt_prev = pkt
      n += 1
   
   return time_sum/n, n/(t_end-t_start)

def ip_tuple(pkt):   # used to sort pkt on IP addresses
   if IP in pkt:
      return pkt[IP].src,pkt[IP].dst
   return '',''   #should never enter this. Must call clean_pcap first

def sort_pcap(pcap):
   pcap = sorted(pcap, key=ip_tuple)
   for pkt in pcap[500:550]:
      print(pkt.summary())

# calculates the avg time between packets departure and arrival
# avg(x_echo.time - x.time)
def avg_rtt(pcap):
   rtt_sum = 0.0
   n = 0
   i = 0
   pcap = sorted(pcap, key=ip_tuple)   # sort pcap on IP addresses
   # X and X_echo are now one after the other in the list,
   # UNLESS there are eterogeneous packets in between
   # we'll increment i by 2, if everything goes OK
   while i < len(pcap)-1:
      pkt = pcap[i]
      if IP not in pkt: # odd packet, might be ARP or DNS stuff
         print("Skipping packet: ", pkt.summary())
         i += 1   # increment by 1!!!
         continue
      pkt_echo = pcap[i + 1]  # get echo pkt
      if (IP not in pkt_echo or pkt[IP].src != pkt_echo[IP].src or pkt[IP].dst != pkt_echo[IP].dst ):
         # there is no echo pkt for some reason
         print("Something went wrong! Skipping packet echo: ", pkt_echo.summary())
         i+=1  # increment by 1!!!
         continue

      # base case, everything ok, now calc RTT
      rtt_sum += pkt_echo.time - pkt.time
      n += 1   # increment to calculate avg later
      i += 2
   return rtt_sum/n




# find all pcap files in the given path
# explores subdirs
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

# path should be absolute
def read_pcap(path):
   print(path, " Reading...")
   ret = rdpcap(path)
   sys.stdout.write("\033[F") # flush and clean last written line
   sys.stdout.write("\033[K")
   print(path[path.rfind("/",0,path.rfind("/"))+1:], " DONE")
   ret.listname = path[path.rfind("/",0,path.rfind("/"))+1:]   # make pcap name readable
   return ret

# simple class to avoid using a tuple
class pcap_stats:
   def __init__(self, name, avg_time, ppsB, ppsA, rtt):
      self.name = name
      self.avg_time = avg_time
      self.ppsB = ppsB
      self.ppsA = ppsA
      self.rtt = rtt
   
   def toJSON(self):
      return self.__dict__

def write_pcaps_stats(pcap_paths, json_path):
   stats  = []
   for path in pcap_paths:
      pcap = read_pcap(path)
      print(pcap.listname, "size -> ", len(pcap))
      a_b = (avg_delta_pkts(pcap,True))
      b_a = (avg_delta_pkts(pcap,False))
      rtt = avg_rtt(pcap) # this must be the last, it sorts pcap!
      stats.append(pcap_stats(pcap.listname,str(a_b[0]),str(a_b[1]),str(b_a[1]),str(rtt)))
      print(stats[-1].toJSON())
   
   # print the result on stdout and then write to file
   print(json.dumps(stats,default=lambda o: o.toJSON(), indent=4))
   f = open(json_path, "w")
   f.write(json.dumps(stats,default=lambda o: o.toJSON(), indent=4))
   f.close()
   return stats

def test():
   write_pcaps_stats(get_paths(".."), "complete_stats_.json")