# Main description #

Explore the network trying to find  IPv6 Nodes using low-bytes.
Low-bytes can work with the lowest 16-bits.

By default run on the range of X:X:X:X::WWWW:UUUU.  Where WWWW go from 0000 to 1000 and UUUU from 0000 to 0100


Example of Low-bytes address:
  * 2001:db8:c0ca::1
  * 2001:db8:c0ca::80
  * 2001:db8:c0ca::80:100

## Version 2.0 ##

The original Low-Bytes was made when Nmap was on the version 6.20 and was unable to create a brute force. However, with 6.40 (and further) the script become unnecessary as Nmap was able to do the same. By this reason, the script was remade.

# Main objectives #

  1. Gateways
  1. Servers

Those address are more easy to manage for a system admin and about all, are static (stateful).

The low-bytes could represent a single host (X:X:X::1), represent the port used for the server ( X:X:X:X::80) or a hybrid which can be useful for virtual environment ( X:X:X:X::80:1, X:X:X:X::23:1 for 2 VM on the same node.


---


# Arguments #

## Unique to the script ##

  * ` targets-ipv6-recon-lowbyt.wseg ` - (_Optional_) Number of number/bits to use on the WWWW segment. Default: 1000

  * ` targets-ipv6-recon-lowbyt.wdec` - (_Optional_) false (Default) the WWWW segment is treated as decimal number instead of hexadecimal.

  * ` targets-ipv6-recon-subnet.useg` - (_Optional_) (Optional) Number of number/bits to use on the UUUU segmen.  Default: 100

  * ` targets-ipv6-recon-subnet.udec` - (_Optional_) false (Default) the WWWW segment is treatedas HEXAdecimal number instead of decimal.


## Global ##

  * ` newtargets ` - **Mandatory** (For add the proposed addresses to Nmap list for [the host phase](http://nmap.org/book/nmap-phases.html)).

  * `targets-ipv6-recon-subnet `  - (_Optional_) The user can provide one or more IPv6 sub-networks to work directly. Valid (Lua) formats are:
    * `2001:db8:c0ca::/48`
    * ` { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } `

  * ` targets-ipv6-recon-IPv6ExMechanism ` - (_Optional_) The script can work the address as string or  4 integers (32 bits)  for mathematical operations. Possible values:
    * `number` - The integer format (**Default**)
    * `string` - The String format.

## Verbosity level ##

The script can give additional information of his current status if the Nmap's argument `-v[v...|] [<number>]`  is given.  All the scripts have until 5 level of verbosity.

Level 2: General information (i.e. subnets provided)and error messages
Level 2: Total of nodes to scan
Level 3: N/A
Level 4: N/A
Level 5: Display each addresses added to the host phase.



---


## Examples ##

```

-- @usage
-- nmap -6 --script targets-ipv6-recon-LowByt
--
-- @output
-- Pre-scan script results:
-- | targets-ipv6-recon-LowByt:
-- |_  targets-ipv6-recon-LowByt.prerule:  Were added 256 nodes to the scan
-- Nmap scan report for ***** (2001:db8:c0ca:1::a)
-- Host is up.

-- Host script results:
-- | targets-ipv6-recon-LowByt:
-- |_    2001:db8:c0ca:1::a

```
### Risk of DoS ###

**Very low** at least the `targets-ipv6-recon-LowByt.OverrideLock` is given, the risk is minimum.

Remember, the total IPv6 addresses scanned by Nmap will impact on the chances of DoS.


---


## What is behind this technique ##

The sys admin can be lazy or we need to place simple and easy address to remember, sometimes writing just X:X:X:X::1 is more easy than remember a fully random 64 bits address (plus the prefix).  This is very similar to use the last or first address on IPv4 for Gateways and servers.


## Future works? ##

  * Currently no one