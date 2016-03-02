# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#Sidharth Gilela ID#:1428033 Email:sgilela@ucsc.edu

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
#from scapy import all
#from scapy.all import *
from pox.lib.addresses import EthAddr
log = core.getLogger()



class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def act_like_hub (self, packet, packet_in):
    """
    Implement hub-like behavior -- send all packets to all ports besides
    the input port.
    """

    # We want to output to all ports -- we do that using the special
    # OFPP_ALL port as the output port.  (We could have also used
    # OFPP_FLOOD.)
    self.resend_packet(packet_in, of.OFPP_ALL)

    # Note that if we didn't get a valid buffer_id, a slightly better
    # implementation would check that we got the full data before
    # sending it (len(packet_in.data) should be == packet_in.total_len)).


  def act_like_switch (self, packet, packet_in):
    """
    Implement switch-like behavior.
    """
    """
    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code.

    # Learn the port for the source MAC
    self.mac_to_port ... <add or update entry>

    if the port associated with the destination MAC of the packet is known:
      # Send packet out the associated port
      self.resend_packet(packet_in, ...)

      # Once you have the above working, try pushing a flow entry
      # instead of resending the packet (comment out the above and
      # uncomment and complete the below.)

      log.debug("Installing flow...")
      # Maybe the log statement should have source/destination/port?

      #msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      #msg.match = of.ofp_match.from_packet(packet)
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      #
      #< Add an output action, and send -- similar to resend_packet() >

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL)
     """

  def firewall(self, packet, packet_in, event):
    IPNum = packet.find('ipv4')
    TCPNum = packet.find('tcp')
    # print(packet)
    # TCPdestPort = str(packet.payload.payload.dstport) 
    # TCPsrcPort = packet.srcport
    
    #TO GET PORT NUMBER
    #packet_in.in_port
    
    """
    print(packet.type)
    print(packet.IP_TYPE)
    ip_packet = packet.payload
    print("GOT ONE")
    tcp_packet = ip_packet.payload
    print("GOT TWO")
    print(tcp_packet)
    print("GOT THREE")
    """
    
    if IPNum is not None and TCPNum is None:
       msg = of.ofp_flow_mod()
       msg.match = of.ofp_match.from_packet(packet)
       msg.idle_timeout = 70
       msg.hard_timeout = 10
       msg.buffer_id = event.ofp.buffer_id      
       self.connection.send(msg)
    else:
       msg2 = of.ofp_flow_mod()
       msg2.match = of.ofp_match.from_packet(packet, packet_in.in_port)
       msg2.idle_timeout = 70
       msg2.hard_timeout = 10
       action = of.ofp_action_output(port = of.OFPP_FLOOD)
       msg2.actions.append(action)
       self.connection.send(msg2)
    """
       msg2 = of.ofp_flow_mod()
       msg2.match = of.ofp_match.from_packet(packet)
       msg2.idle_timeout = 70
       msg2.hard_timeout = 10
       msg2.buffer_id = event.ofp.buffer_id
       print(msg2)
       self.connection.send(msg2)
    """
    """
       print("Got Here 0")
       if packet.type == pkt.IP_TYPE:
          print("Got Here 1")
          ip_packet = packet.payload
          print("Got Here 2")
	  if ip_packet.protocol == pkt.TCP_PROTOCOL:
             print("Got Here 3")
	     tcp_packet = ip_packet.payload
             print("Got Here 4")
	     dst_tcp = tcp_packet.dstport
             print("Got Here 5")
             print(dst_tcp)
             self.resend_packet(packet_in, dst_tcp)   
    """

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    # print(packet.ipv4)
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    
    # print("SUPER MEGA PORT NUMBER CHECK")
    # print(event.port)
    # print(packet_in.in_port)  
    """
    print(packet)
    print("HUGE SPACE")
    print(packet_in)
    print("HUGE SPACE 2")
    """    
    # print("before maybe faulty statement")
    # ip_src = event[IP].src
    # print(ip_src)
    """
    a = IP(packet)
    print(a.src)
    print(a.dst)
    """
    """
    if IP in packet:
      print("BEGINNING OF TIME")
      ip_src = packet[IP].src
    print("After faulty statement maybe")
    """
    """
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)
    """
    """
    print("before messege starts") 
    msg2 = of.ofp_flow_mod()
    msg2.idle_timeout = 10
    msg2.hard_timeout = 70
    print(msg2)
    print("SPACEBAR MEGA HUGE")
    print(packet_in.in_port)
    """
    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    self.firewall(packet, packet_in, event)
    #self.act_like_switch(packet, packet_in)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
