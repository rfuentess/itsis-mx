# Main description #

Explore the network trying to find  IPv6 Nodes with addresses that were mapped using a plain conversion from IPv4 to IPv6 .

Example of Low-bytes address:
  * 2001:db8:c0ca::192.168.1.10/120
  * 2001:db8:c0ca::C0A8:010A/120

Both address are the same, the first one have a more easy representation (for humans) and the second  is written on hexadecimal values.

# Main objectives #

  1. Hosts using stateful configuration (probably DHCPv6).

> Except servers which can have a static configuration, multiple hosts using stateful address probably are behind a DHCPv6 server. The good thing, probably will be less than a thousand nodes by each sub-network.


---


# Arguments #

## Unique to the script ##

  * `targets-ipv6-recon-Map4t6.IPv4Hosts` - (**Mandatory**) The IPv4 addresses which we want to confirm exists on IPv6. Can be one single host, multiple hosts or a full subnetwork (a.b.c.d/YY).   Valid (Lua) formats are:
    * ` 192.168.1.1 `
    * ` { 192.168.1.1, 192.168.2.2 } `
    * ` 192.168.1.0/24 `
    * ` { 192.168.1.0/24, 192.168.2.0/24 } `

## Global ##

  * ` newtargets ` - **Mandatory** (For add the proposed addresses to Nmap list for [the host phase](http://nmap.org/book/nmap-phases.html)).

  * `targets-ipv6-recon-subnet `  - (_Optional_) The user can provide one or more IPv6 sub-networks to work directly. Valid (Lua) formats are:
    * `2001:db8:c0ca::/48`
    * ` { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } `

## Verbosity level ##

The script can give additional information of his current status if the Nmap's argument `-v[v...|] [<number>]`  is given.  All the scripts have until 5 level of verbosity.

Level 2: General information (i.e. subnets provided)and error messages
Level 2: Advise when a new sub-net will be processed.
Level 3: N/A
Level 4: N/A
Level 5: Display each addresses added to the host phase.


---


## Examples ##

```

-- @usage
-- nmap -6 --script targets-ipv6-recon-Map4to6 --script-args newtargets,targets-ipv6-recon-Map4t6.IPv4Hosts=X.X.X.X
--
-- @output
-- Pre-scan script results:
-- | targets-ipv6-recon-map4to6:
-- |_  targets-ipv6-recon-map4to6.prerule:  Were added 18 nodes to the host scan phase

-- Host script results:
-- | targets-ipv6-recon-map4to6:
-- | Host online - Mapped IPv4 to IPv6
-- |_  2001:db8:c0ca:1::9d9f:64e1

```

### Risk of DoS ###

**Medium** If you give a very high number of hosts to scan  (By example 10.0.0.0/8) there is a risk to happen the DoS.

Remember, the total IPv6 addresses scanned by Nmap will impact on the chances of DoS.


---


## What is behind this technique ##

This scenario is strange, very strange. Originally, for  let IPv4 and IPv6 to work, there was a full block  reserved for it, which was ::a.b.c.d/96. That blocked was the original Map 4 to 6. However, was deprecated very quickly. Now is possible to happen something similar if the sys admin choice to  move, literally, the current IPv4 topology to his IPv6 sub-network.

For this to be more strange, Nmap only work IPv4 or IPv6 and not both at the same time. The original (and most efficient idea) was to scan first IPv4 address and only try to map to Ipv6 those who are online. However, need to be done on separate scanning, being that the reason we need to provide the IPv4 list as a mandatory argument to the script.

## Future works? ##

  * If Nmap release a version which can support both protocols at same time, REDO the script.