# Main description #

Confirm the existence of specific IPv6 sub-networks sending spoofed request to  DHCPv6 servers.

We spoofed Relay agent messages which spoof "ghost" clients requests. This has been tested against the [wide-dhcpv6 open source project](http://sourceforge.net/p/wide-dhcpv6/wiki/Home/) and the Microsoft's DHCPv6 server.



# Main objectives #

  1. DHCPv6 servers.
  1. Pass the confirmed IPv6 sub-networks to other targets-ipv6-recon scripts.

> The objective is  confirm if a subset of sub-networks exist at all. Will generate one single relay-forwarder  message (RFC 3315 20.1.2 p. 59) with a good HOP\_COUNT\_LIMIT (Spoofed) and a host request-message (Spoofed with random DUID) and we are going to wait for a Relay-reply message (20.3 p. 60).

Any sub-network the script is able to detect will be passed to the other scripts. However, running this script is optional and  there is a global argument for sub-networks (`targets-ipv6-recon-subnet `) avoiding this script.

Finally, ACL on the server, ACL on the router,  IPsec between relays agent and server  can kill this technique.



---


# Arguments #

## Unique to the script ##

  * `targets-ipv6-recon-dhcpv6.subnets` - (**Mandatory**) The user can provide one or more IPv6 sub-networks to work directly. We can add one or more subnetwork with a prefix (X:X:X:X::/YY) or one or more entity network address with his prefix, together to the B bits for sub-netting and the total of sub-networks to search (X:X:X:X::/YY, B, Total).   Valid (Lua) formats are:
    * 2001:db8:c0ca::/48
    * { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 }
    * {2001:db8:c0ca::/48, 16, 23}
    * { {2001:db8:c0ca::/48, 16, 23} , 2001:db8:c0ca::/48}

By example, suppose we know the entity 2001:db8:c0ca::/48 and we want to explore the first 100 possible sub-networks, and we believe their sub-networks are all with the prefix 64, we will  give (2001:db8:c0ca::/48, 16, 100), where will try to confirm  the sub-network 2001:db8:c0ca:0::/64 to 2001:db8:c0ca:64::/64 (0x64 is 100)


  * ` targets-ipv6-recon-dhcpv6.TimeToBeg ` - (_Optional_) The RFC 3315 indicate that nodes can indicate on their request how many time that have been trying to get a address. Nodes with higher time will have priority. This argument let us to choice a  16-bits number (0 - 65535) which represent microseconds for the field. **By default is 0**

  * ` targets-ipv6-recon-dhcpv6.Company ` - (_Optional_) When we fabricate the ghost host request, we need to give it a MAC address, **by default the higher part (the OUI) is from DELL (24B6FD)**. However if we need to avoid trace or use a specific brand we can use this argument for change the OUI, though the last 24 bits will be random.

  * ` targets-ipv6-recon-dhcpv6.utime `  - (_Optional_) When we are trying to confirm two or more sub-networks, between each messages we send,  **by default we have a  random waiting time between 1 ms - 200 ms**. With this argument, we can change the maximum time to wait.

  * ` targets-ipv6-recon-dhcpv6.Option_Request ` - (_Optional_) By default the script send a simple request without any additional request. However, a typical node ask by the domain and other data. This argument try to mimic a real node asking for the domain.

## Global ##

NONE

## Nmap arguments ##

The ethernet interface need to be provided using the argument `-e <interface> `

## Verbosity level ##

The script can give additional information of his current status if the Nmap's argument `-v[v...|] [<number>]`  is given.  All the scripts have until 5 level of verbosity.

Level 2: General information (i.e. subnets provided)and error messages.

Level 2: Display the  DUID generated for each sub-network. And final relay request message.

Level 3: Display each component of the (ghost) host request

Level 4: Display each component of the special fields of the host request.

Level 5: Display the DCPdum filter



---


## Examples ##

```

-- @usage
 nmap -6 -v --script targets-ipv6-recon-dhcpv6 --script-args targets-ipv6-recon-dhcpv6.subnets= 2001:db8:c0ca:6006::/64

--@output
NSE: targets-ipv6-recon-dhcpv6.Solicit:  New SOLICIT Message. ID: 09bec2
NSE: targets-ipv6-recon-dhcpv6.Solicit:  Client ID: 0001000e000100011a07eb1a24B6FDe46629
NSE: targets-ipv6-recon-dhcpv6.Solicit:  IA-NA : 0003000c0000000f0000000000000000
NSE: targets-ipv6-recon-dhcpv6.Solicit:  Time: 000800020000
NSE: targets-ipv6-recon-dhcpv6.Solicit:  (G)Host - Link-Address: FE8000000000000026B6FDFFFEe46629 type of request: temporary
 DUID: 000100011a07eb1a24B6FDe46629
 IAID: 0000000f
NSE: targets-ipv6-recon-dhcpv6.prerule
	 Relay Forward:  msg_type: 0C
	 hopcount: 0C
	 linkAdd: 20010db8c0ca6006ffffffffffffffff
	 peerAdd: FE8000000000000026B6FDFFFEe46629
	 Options: 0009002c0109bec20001000e000100011a07eb1a24B6FDe466290003000c0000000f0000000000000000000800020000
NSE: Client ID Option length: 14 bytes
NSE: Server ID Option length: 14 bytes
NSE:  The subnet 2001:db8:c0ca:6006::/64 is Online

```

### Risk of DoS ###

**Nonexistent**


---


## What is behind this technique ##

A original technique proposed by  Ing. Raul Fuentes Samaniego. The [RFC 3315 Dynamic Host Configuration Protocol for IPv6 (DHCPv6)](http://tools.ietf.org/html/rfc3315) is very secure, however  they focus all their efforts on protect the DUIDs. leaving the substract sub-network information as lesser danger.

Of course, this is a game of guessing. The node 2001:db8:c0ca::1 could be inside of sub-network 2001:db8:c0ca::/112, 2001:db8:c0ca::/96 or  2001:db8:c0ca::/64 (or even all of them if there are VLSM) but can help us to begin to draw a possible topology of the entity objective.

## Future works? ##

  * The RFC 3315 indicate two types of address request, IA-NA e IA-TA, however original tests  were unable to make a valid IA-TA request (or  both server were bad configured and never answered the request).