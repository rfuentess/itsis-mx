# Main description #

Explore the network trying to find  IPv6 Nodes using Stateless auto-configuration (SLAAC) with the EUI-64 mechanism. There is a special emphasis for Virtual Machines (About all VMware)

Example of EUI-64 address:
  * 2001:db8:c0ca:ae00:209:6bff:fe37:d4a0
  * 2001:db8:c0ca:6006:221:70ff:fe8a:cd00

# Main objectives #

  1. Hosts using SLAAC with eui-64.
  1. Virtual machines (VMware, Virtual Box, Virtual PC, Parallels Virtuozzo and Dekstop).
  1. Special emphasis with V.M. running with VMWare (16 - 8 bits to scan).

By default, any GNU/Linux, and MAC OS/X host will be using this format (Microsoft use a pseudo-privacy address format).  Some routers (as the one from Cisco) can use this format if you don't give a specific address.

Other UNIX bases system could be using Kame instead of USAGI (or any other IPv6 stack).


---


# Arguments #

## Unique to the script ##

  * `targets-ipv6-recon-slaac.nbits` - (_Optional_) A number with range of 1 - 24 (**Default 11**). It's _nbits_ power of 2 nodes to search for physical nodes(<sub>2</sub>nbits = # Nodes to search).

  * ` targets-ipv6-recon-slaac.vendors ` - (_Optional_) The user can provided companies names (Like Apple, Dell, HP, etc.) and the script will add all theirs OUI to the list to scan. The user can provide specifics DUID (5855CA,6C9B02,0CD292, etc.)  or any combination.  If the argument {{targets-ipv6-recon-slaac.vms}} is giving, then this argument will be empty by default,**otherwise will search the 49 OUI of DELL by default**.

Valid (Lua) formats are:
  * ` DELL `
  * ` {DELL, HP} `
  * ` 5855CA `
  * ` {5855CA , 6C9B02, 0CD292} `
  * ` {5855CA , Apple} `

  * ` targets-ipv6-recon-slaac.compute ` - (_Optional_) We can try to search nodes using brute force scanning or using random address. Due we need to search for nodes on a space of 24 bits, it's very probably will not find too much nodes using little bits to explore making a brute attack little effective. **By default his value is random**

More than 20 bits to scan would waste too much resource if we use random values, by this reason, **if `targets-ipv6-recon-slaac.nbits` is 20 or greater this argument will be override and the brute mechanism will be used**.

  * ` targets-ipv6-recon-slaac.vms ` - (_Optional_) If this argument is given, the script will search for Virtual Machine (plus physical one if the ` targets-ipv6-recon-slaac.vendors ` is given as well). The only valid values are:
    * _(empty)_: **Default** Will search for all the V.M. ( VMware, Virtual Box, Paralalles, Virtual PC and QEMU VMs)
    * ` W `:  Will search for VMware VMs (Static and Dynamic)
    * ` wS `: Will search for VMware VMs with static/manual configuration MAC address.
    * ` wD `: Will search for VMware VMs with dynamic configuration MAC address.
    * ` P `: Will search for  Parallels Virtuozzo and Dekstop VMs
    * ` pV `: Will search for  Parallels Virtuozzo  VMs
    * ` pD `: Will search for  Parallels Dekstop  VMs
    * ` pVpD `: Equivalent to "P"
    * ` V `:  Will search for  Oracle Virtual Box VMs
    * ` M `:  Will search for  Microsoft Virtual PC VMs
    * ` L `:  Will search for  Linux  QEMU
    * ` WPVML `: Equivalent to the default option.

  * ` targets-ipv6-recon-slaac.vms-nbits ` (_Optional_) Similar to `targets-ipv6-recon-slaac.nbits` but is taken account only when the VM of VMWare (with dynamic MAC address generated) are to be explored. On those case, 16 bits are fixed (Based on IPv4 or random) and 8 bits are random. **By defualt the value is 2**

With this variable, we are creating searching  256 **x** <sub>2</sub>_vms-nbits_ nodes.

  * ` targets-ipv6-recon-slaac.vmipv4 ` - (_Optional_) Alternative to   ` targets-ipv6-recon-slaac.vms-nbits ` we can provided IPv4 address. With this, we reduced the search to 256 nodes by each IPv4 address provided.

Valid (Lua) format:
  * ` 192.168.1.1 `
  * ` { 192.168.1. , 192.168.1.2 `

  * ` targets-ipv6-recon-slaac.knownbits ` - (_Optional_) Alternative to   ` targets-ipv6-recon-slaac.vms-nbits ` and to ` targets-ipv6-recon-slaac.vmipv4 `. If the user believes to known part of the last 16 bits of the potential IPv4 address he can provided their binary value with this script.

Valid (Lua) format (Any possible binary number until 16 bits):
  * ` 0000000000000000 `
  * ` 000000000000 `
  * ` 00000000 `
  * ` 0000 `
  * ` 0 `

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
Level 2: Advise when a new OUI and/or VM will be processed.
Level 3: Advise when a new sub-net will be processed.
Level 4: Advise when each sub-group of possible VMware is processed.
Level 5: Display each addresses added to the host phase.



---


## Examples ##

```

@use nmap -6 -v3  --script targets-ipv6-recon-slaac --script-args targets-ipv6-recon-slaac.nbits=4,targets-ipv6-recon-slaac.vendors="HP",newtargets

@output 
Starting Nmap 6.40 ( http://nmap.org ) at 2014-04-14 19:36 Romance Daylight Time
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 1) scan.
Initiating NSE at 19:36
NSE: targets-ipv6-recon-slaac.prerule: Begining the Pre-scanning work...
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  001F28 OUI  for the vendor: hp ( hpn supply chain )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  00A068 OUI  for the vendor: hp ( bhp limited )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  001D31 OUI  for the vendor: hp ( highpro international r&d co )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  00193C OUI  for the vendor: hp ( highpoint technologies incorporated )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  0026F1 OUI  for the vendor: hp ( procurve networking by hp )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  001DB3 OUI  for the vendor: hp ( hpn supply chain )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  001FFE OUI  for the vendor: hp ( hpn supply chain )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  0024A8 OUI  for the vendor: hp ( procurve networking by hp )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  B439D6 OUI  for the vendor: hp ( procurve networking by hp )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  F06281 OUI  for the vendor: hp ( procurve networking by hp )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  002561 OUI  for the vendor: hp ( procurve networking by hp )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  C09134 OUI  for the vendor: hp ( procurve networking by hp )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  002347 OUI  for the vendor: hp ( procurve networking by hp )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  0021F7 OUI  for the vendor: hp ( hpn supply chain )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  001C2E OUI  for the vendor: hp ( hpn supply chain )
NSE: targets-ipv6-recon-slaac.prerule.Vendors:  Adding  001B3F OUI  for the vendor: hp ( procurve networking by hp )
NSE: targets-ipv6-recon-slaac.prerule:  Were added  16 OUI for the vendor: hp
Completed NSE at 19:36, 0.11s elapsed
NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 1) scan.
Read data files from: C:\Program Files (x86)\Nmap
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 1.28 seconds
           Raw packets sent: 0 (0B) | Rcvd: 0 (0B)

```

### Risk of DoS ###

**High** For getting higher chances to  find a machine we need to  increase the search near to 20 bits (or more), as result the reliable search  have a real risk of DoS.

Remember, the total IPv6 addresses scanned by Nmap will impact on the chances of DoS.


---


## What is behind this technique ##

This is the most interesting  technique, as we can reduce the search from 64 to 24 bits (millions) and to 16 bits (a little more than 64 thousands). And for VMware could reduce the search to only 8 bits (256).

However, is the most complex to use it. For have any chance we need be able to do a good recollection of data from the entity to explore.

![https://lh5.googleusercontent.com/-fGjTpp-_RfM/U0cVEkOB9vI/AAAAAAAABME/EolivYex9b8/w346-h230/eui64.png](https://lh5.googleusercontent.com/-fGjTpp-_RfM/U0cVEkOB9vI/AAAAAAAABME/EolivYex9b8/w346-h230/eui64.png)

## Future works? ##

  * The brute mechanism have a weak point: Always begin from the first address. We need to add the argument for begin from a specific address, so we can divide the work on different scanning.
  * The random mechanism have a weak point: Is possible to choice invalid low mac address (by example 0x0000). Not sure how to create a better heuristic for this with lua (and without touching Nmap C code).
  * I'm not sure if changing the DELL default value to only one single DUID, as this value probably will always ending with a DoS. (By other hand, Dell is a very common company on many offices).