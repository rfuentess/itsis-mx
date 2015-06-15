# Main description #

Explore the network trying to find  IPv6 Nodes using low-bytes.
Low-bytes can work with the lowest 16-bits (by default).

Example of Low-bytes address:
  * 2001:db8:c0ca::1
  * 2001:db8:c0ca::80
  * 2001:db8:c0ca::80:10



# Main objectives #

  1. Gateways
  1. Servers

Those address are more easy to manage for a system admin and about all, are static (stateful).

The low-bytes could represent a single host (X:X:X::1), represent the port used for the server ( X:X:X:X::80) or a hybrid which can be useful for virtual environment ( X:X:X:X::80:1, X:X:X:X::23:1 for 2 VM on the same node.


---


# Arguments #

## Unique to the script ##

  * `itsismx-LowByt.nbits` - (_Optional_)How many bits will be scanned. The range is  3 - 16 (8 nodes to more than 64 thousand) **Default: 8**.
  * `itsismx-LowByt.OverrideLock` If this argument is given, the `itsismx-LowByt.nbits` will accept higher ranges than 16 bits.

## Global ##

  * ` newtargets ` - **Mandatory** (For add the proposed addresses to Nmap list for [the host phase](http://nmap.org/book/nmap-phases.html)).

  * `itsismx-subnet `  - (_Optional_) The user can provide one or more IPv6 sub-networks to work directly. Valid (Lua) formats are:
    * `2001:db8:c0ca::/48`
    * ` { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } `

  * ` itsismx-IPv6ExMechanism ` - (_Optional_) The script can work the address as string or  4 integers (32 bits)  for mathematical operations. Possible values:
    * `number` - The integer format (**Default**)
    * `string` - The String format.

## Verbosity level ##

The script can give additional information of his current status if the Nmap's argument -v[v...|] [

&lt;number&gt;

]  is given.  All the scripts have until 5 level of verbosity.

Level 1: General information (i.e. subnets provided)and error messages
Level 2: Total of nodes to scan
Level 3: N/A
Level 4: N/A
Level 5: Display each addresses added to the host phase.



---


## Examples ##

```

-- @usage
-- nmap -6 --script itsismx-LowByt
--
-- @output
-- Pre-scan script results:
-- | itsismx-LowByt:
-- |_  itsismx-LowByt.prerule:  Were added 256 nodes to the scan
-- Nmap scan report for ***** (2001:db8:c0ca:1::a)
-- Host is up.

-- Host script results:
-- | itsismx-LowByt:
-- |_    2001:db8:c0ca:1::a

```
### Risk of DoS ###

**Very low** at least the `itsismx-LowByt.OverrideLock` is given, the risk is minimum.

Remember, the total IPv6 addresses scanned by Nmap will impact on the chances of DoS.


---


## What is behind this technique ##

The sys admin can be lazy or we need to place simple and easy address to remember, sometimes writing just X:X:X:X::1 is more easy than remember a fully random 64 bits address (plus the prefix).  This is very similar to use the last or first address on IPv4 for Gateways and servers.

### Why OverrideLock? ###
The   `itsismx-LowByt.OverrideLock` was added due the script was developed with the Nmap v. 6.20, which only had basic IPv6 scanning. However, with Nmap 6.40 was added the  brute force scanning making the argument useless (as do the brute force of Nmap is more efficiency than using NSE).

## Future works? ##

  * Probably remove the override option (as the current Nmap version support a full brute force attack).
  * This was the first script done. His structure is not so optimized (if it's possible to  say it) as the others, so probably will be re-written on near future.