Author: Raul Fuentes Samaniego ( ra.fuentess.sam+Nmap@gmail.com )
Source code website: https://code.google.com/p/itsis-mx/
License: Same as Nmap 6.20 (http://nmap.org/book/man-legal.html#nmap-copyright)

Itsismx (or itsis-mx) is a collection of NSE scripts for Nmap 6.20 and posterior which add some IPv6 scanning techniques. 
The techniques are based on the draft "Network Reconnaissance in IPv6 Networks" of Francisco Gont and T. Chown.

The scripts work for Low-bytes, SLAAC (with special focus for V.M.), Map4to6, and words, plus a special technique for 
extracting sub-networks information from DHCPv6 servers.

As the heart of this work was possible to do it thanks to Nmap, the source code is released with Nmap's license. And the
 master thesis is available with the creative commons licenses (however is on my mother language, spanish) on this link.
 
--  Using the scripts

The best performance is achieved on the GNU/Linux distribution. By two factors:
1 - Nmap can use all his techniques, for probes nodes, only with the original Libpcap for Linux read more on this link.
2 - DHCPv6's script works only for GNU/Linux (need to create raw packets using libcap).

-- Risk of DoS!
By default, only the script for DHCPv6 and wordly are safe to use. The other scripts brings a latent risk of provoking a 
DoS. However, the risk is due poor NDP implementation on the gateways. You can read more about the risk on the RFC 6583 
Operational Neighbor Discovery Problems

On general, the chances of DoS will increase as you increase the size of the sweep. The default values on the scripts are 
inside of a secure search (well, for a Router cisco 2811 with 512 MB of RAM).