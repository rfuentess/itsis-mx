# Main description #

Explore the network trying to find  IPv6 Nodes using previous known word-play as addresses.

Example of Wordly address:
  * 2001:db8:c0ca::C0CA:C01A
  * 2001:db8:c0ca:DEAD:BEEF::

The script uses the dictionary file: **_Nmap/nselib/targets-ipv6-recon-words-known_**

# Main objectives #

  1. All the nodes

Those address are more easy to manage for a system admin and about all, are static (stateful).

Nodes which were configured using SLAAC (based on EUI-64) are static between all  IPv6 networks. As result, it's a good idea to populate your dictionary with the EUI-64 addresses already discovered.


---


# Arguments #

## Unique to the script ##

  * `targets-ipv6-recon-wordis.nsegments` - (_Optional_) A number of 1 to 16. Represents how many segments of 16 bits  has the addressees to search. By example, if the user provide 1 as _nsegment_, will only search words of 4 hexadecimal length. **By default is 4** (the full 64 bits).

  * ` targets-ipv6-recon-wordis.fillright ` - (_Optional_) When the word is lesser than the sub-network prefix, the remaining space will be filled with Zeros. **By default, the filling zeros are to the left of the word** (2001:db8:c0ca**::**DEAD:BEEF ). Given this argument, will be to the right(2001:db8:c0ca:DEAD:BEEF**::**).



## Global ##

**` newtargets ` -**Mandatory**(For add the proposed addresses to Nmap list for [the host phase](http://nmap.org/book/nmap-phases.html)).**

  * `targets-ipv6-recon-subnet `  - (_Optional_) The user can provide one or more IPv6 sub-networks to work directly. Valid (Lua) formats are:
    * `2001:db8:c0ca::/48`
    * ` { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } `

## Verbosity level ##

The script can give additional information of his current status if the Nmap's argument `-v[v...|] [<number>]`  is given.  All the scripts have until 5 level of verbosity.

Level 2: General information (i.e. subnets provided)and error messages
Level 2: N/A
Level 3: Advise when a new sub-net will be processed.
Level 4: N/A.
Level 5: Display each addresses added to the host phase.



---


## Examples ##

```

-- @usage
-- nmap -6 --script targets-ipv6-recon-wordis --script-args newtargets
--
-- @output
--	Pre-scan script results:
--	| targets-ipv6-recon-wordis:
--	|_  targets-ipv6-recon-wordis.prerule:  Were added 4 nodes to the host scan phase

--	Host script results:
--	| targets-ipv6-recon-wordis:
--	| Host online - IPv6 address wordis
--	|_  2001:db8:c0ca::dead

```

### Risk of DoS ###

**Low** although, If the dictionary become very big (more than thousand words) can increase the risk.

Remember, the total IPv6 addresses scanned by Nmap will impact on the chances of DoS.


---


## What is behind this technique ##

The sys admin can be lazy or we need to place simple and easy address to remember, sometimes writing a single series letters and number  resemble expressions or words is enough (even for the passwords is true).

The good thing for us, this is very well known, and already  exist many places where we can retrieve a full dictionary with the words.

## Future works? ##

  * The dictionary need to increase his size! (was left a concept for the thesis).