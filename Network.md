
- ### What happens when u put the internet wire in the pc and open browser to write google.com?
OSI Model:
 1- From Physical layer, send data on the physical wire.
 2- From Data link layer, reads the MAC address from data packet.
 3- From Network layer, reads the IP address from the packet.
 4- From Transport layer, responsible for the transport protocol and err handling.
 5- From Session layer, establishes connections between two hosts.
 6- From Presentation layer, formats the data so that it can be viewed by user.
 7- From Application layer, service that are used with user application.
 explaining: once i put the cable on the pc , i got my MAC address, then i got my ip from the DHCP(dhcpDiscovery-dhcpOffer-dhcpReq-dhcpAck), then i go to google through the transport layer by using tcp and https(browser asks dns server about google ip - browser req secure https from web server - respond with ssl cert - send encrypted symmetric key with public key - decrypt with private key - communication )
 
 - ### What are routing protocols?
OSPF, RIP, IGRP, EIGRP, BGP

 - ### What can you do with SMB?
enumeration for shares files [enum4linux-Metasploit[smb_enumshares]].

- ### What is port 445,139?
SMB

- ### What is port 88?
Kerberos

 - ### What can you do with SNMP[161 port]?
check for configuration files , check if can change values may lead to RCE

 - ### What will you do if u found SSH port 22 open?
Search for vulnerable version, Password Spray

 - ### What layer are tcp and udp in & diff between them?
4, Transport layer, tcp has 3 way handchake

 - ### What is ping, can run on specific port, Why?
ICMP , No , cuz its Network layer

 - ### Can ping carry app headers like TCP?
No cuz its network layer

