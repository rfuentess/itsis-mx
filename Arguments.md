# Arguments #

Nmap is a very powerful program which can improve his result using the arguments. However if this your first time using it can overcome you pretty easy. Itsismx scripts have 20 custom arguments, each one for give the greater possible flexibility.

For introduce to the itsismx's argument is necessary to state two types of arguments: **Nmap's arguments** and  **scripts arguments** (which are a special case of Nmap arguments).  All the itsismx argument are the second type, with a very specific name for avoid the risk of overwritten other scripts arguments as Nmap shared the same memory for all the script running on parallel.

## Nmap Arguments ##

As with any other set of NSE scripts, you can combine the scripts with Nmap's argument for getting a more custom result, or even for reduce the risk of DoS, reducing total number or increasing the time for each probe. I could go forever writing each one of possible Nmap's argument, however I'll focus only on those who have a very strong impact on Itsismx scripts.


We have the follow Nmaps arguments to consider:
  * (**Mandatory**) `-6`: Need it for scanning on IPv6.
  * (**Mandatory**) `--scripts=[Script1,script2...]`: Need it for indicate the scripts to run.
  * (_Optional_) `--script-args=[Arg1,Arg2...]`: Need it for make the scripts to run properly.
  * (_Special_)`-e <Interfaz-ID>`: The [DHCPv6 script](DHCPv6.md) need to use a Ethernet Interface (and only work on GNU/Linux).
  * (_Optional_) ` --script-args-file=[Path_File]`: Can be used instead of the previous command
  * (Optional) `-v[v...] | -v[1-5]`: All the scripts were made with 5 level of verbosity, being the level 5 little recommended (as will display EACH addresses added to the host list).

### Arguments for reduce risk of DoS ###

Other set of arguments are displayed on the next table, they are useful to reduce the risk of DoS, however will have a strong impact on the times for the scanning.

  * `--min-hostgroup <Number>` and `--max-hostgroup <Number>`: Adjust the size of the nodes groups to scan at same time (key element for avoid the DoS).
  * `--scan-delay` and `--max-scan-delay`: Adjust the delay between each probe (key element for avoid the DoS).
  * `-T Paranoid|Sneaky|Polite|Normal|Aggressive|Insane`: Use a specific template  for the _user to specify how aggressive they wish to be, while leaving Nmap to pick the exact timing values. The templates also make some minor speed adjustments for which fine-grained control options do not currently exist_(However, his ability to avoiding the DoS is limited).
  * `--min-parallelism <Number>` and `--max-parallelism<Number>`: Adjust the number of probes send on parallel (very low impact, the number of host have a higher impact).

On general, you need to consider the arguments on the [Nmap: Timing and Performance](http://nmap.org/book/man-performance.html) but those were enough for me to avoid the DoS appear (Without them, any exploration with 16 bits or more was a guarantee on my experiments).


### Scripts arguments ###

Each script has his own set of argument, and almost everyone shared one common global argument.

The next table display a resume of those arguments and the type of lua variable expected for them:

| # | **Argument**  | **Lua type of data** |  **Mandatory/Optional?** |
|:--|:--------------|:---------------------|:-------------------------|
| 1 | `targets-ipv6-recon-subnet` | String | Table       | Prefer.                  |
| 2 | `targets-ipv6-recon-IPv6ExMechanism` | _number_ | _string_  | Optional.                |
| 3 | `targets-ipv6-recon-SaveMemory	` |                      | Optional.                |
| 4 | `targets-ipv6-recon-dhcpv6.subnets` | String | Table       | Prefer.                  |
| 5 | `targets-ipv6-recon-dhcpv6.TimeToBeg` | Number               | Optional.                |
| 6 | `targets-ipv6-recon-dhcpv6.Company` | String               | Optional.                |
| 7 | `targets-ipv6-recon-dhcpv6.utime` | Number               | Optional.                |
| 8 | `targets-ipv6-recon-lowbyt.wseg` | Number               | Optional                 |
| 9 | `targets-ipv6-recon-lowbyt.wdec	` | Boolean              |  Optional                |
| 10 | `targets-ipv6-recon-lowbyt.useg` | Number               | Optional                 |
| 11 | `targets-ipv6-recon-lowbyt.udec	` | Boolean              | Optional                 |
| 12 | `targets-ipv6-recon-wordis.nsegments` | Number               | Optional.                |
| 13 | `targets-ipv6-recon-wordis.fillright` |                      | Optional.                |
| 14 | `targets-ipv6-recon-Map4t6.IPv4Hosts` | String  | Table      | Mandatory.               |
| 15 | `targets-ipv6-recon-slaac.vendors` | String  | Table      | Prefer.                  |
| 16 | `targets-ipv6-recon-slaac.nbits` | Number               | Optional.                |
| 17 | `targets-ipv6-recon-slaac.compute` | _random_ | _brute_   | Optional.                |
| 18 | `targets-ipv6-recon-slaac.vms` | Múltiples (Ver más abajo) | Optional.                |
| 19 | `targets-ipv6-recon-slaac.vms-nbits` | Number               | Optional.                |
| 20 | `targets-ipv6-recon-slaac.vmipv4	` | String  | Table      | Optional.                |
| 21 | `targets-ipv6-recon-slaac.knownbits` | String               | Optional                 |
| 22 | `newtargets`  |                      | Mandatory                |


# Examples #

Those are the commands and arguments used on the thesis, they can be find on the section 3.2 and later.



## Single execution ##

This is a example of minimum set of arguments need for executing all the targets-ipv6-recon scripts:
> `nmap -6 -v -e eth0 –-script targets-ipv6-recon* –-script-args targets-ipv6-recon-dhcpv6.subnets=2001:db8:c0ca::/64,targets-ipv6-recon-Map4t6.IPv4Hosts=192.168.1.0/24,newtargets `

The next two example are selective execution of the scripts:

> ` nmap -6 -v -e eth0 –-script targets-ipv6-recon-slaac,targets-ipv6-recon-dhcpv6 –-script-args targets-ipv6-recon-dhcpv6.subnets=2001:db8:c0ca::/64,newtargets `

> ` nmap -6 -v -e eth0 –-script targets-ipv6-recon-words-known,targets-ipv6-recon-map4to6.nse –-script-args targets-ipv6-recon-dhcpv6.subnets=2001:db8:c0ca::/64,targets-ipv6-recon-Map4t6.IPv4Hosts=192.168.1.0/24,newtargets `

And this is a mandatory example of why Nmap is so powerful, the {{-A}} and {{-sC}} enable all the Nmap phases plus the default scripts, together targets-ipv6-recon scripts:

> `nmap -6 -v -e eth0 -A -sC –-script targets-ipv6-recon* –-script-args targets-ipv6-recon-subnet=2001:db8:c0ca::/64,targets-ipv6-recon-Map4t6.IPv4Hosts=192.168.1.0/24,newtargets`

## Modular ##

For reducing the risk of DoS, and avoiding lost all the current memory on a very powerful scanning, we can divide the scanning on a series of executions.

Of course this can be even more advanced and we can create a single bash script for executing the testings, as  I did for running almost all my tests.  The following code is a example of Bash script:

```
#! /bin/bash
CAMINO="/media/instructor/Labo_Redes/"
Log1="/media/instructor/Labo_Redes/Slaac24eui64-1x1_1.txt"
targets-ipv6-recon-ARGS="newtargets,targets-ipv6-recon-subnet=\"2001:db8:c0ca:0fea::/64\",targets-ipv6-recon-slaac.nbits=24,targets-ipv6-recon-SaveMemory"
NmapArgs="-sn -6 -vvv "

echo "Experiment:  24 bits OUI: b8ac6f to las "  `date`
nmap $NmapArgs --script targets-ipv6-recon-slaac --script-args $targets-ipv6-reconARGS",targets-ipv6-recon-slaac.vendors=\"b8ac6f\"" > $Log1
echo "Experiment:  24 bits OUI: b8ac6f to las "  `date`
nmap $NmapArgs --script targets-ipv6-recon-slaac --script-args $targets-ipv6-reconARGS",targets-ipv6-recon-slaac.vendors=\"00096b\"" >> $Log1
echo "Experiment:  24 bits OUI: b8ac6f to las "  `date`
nmap $NmapArgs --script targets-ipv6-recon-slaac --script-args $targets-ipv6-reconARGS",targets-ipv6-recon-slaac.vendors=\"002170\"" >> $Log1
```

> Of course, there is too many way to do it, a more advanced way to do our testings is  using the `--script-args-file <filepath>` argument ,and if wee need,  shell scripting.

By example, having a file with the name: Dhcpv6-testing with the next lines:

```
targets-ipv6-recon-dhcpv6.subnets={2001:db8:c0ca:6001::/64,2001:db8:c0ca:6002::/64,2001:db8:c0ca:6003::/64,2001:db8:c0ca:6006::/64}
targets-ipv6-recon-subnet={2001:db8:c0ca:fea::/64,2001:db8:c0ca:ced0::/64,2001:db8:c0ca:ee01::/64,2001:db8:c0ca:ced0::/64,2001:db8:c0ca:ae00::/64}
targets-ipv6-recon-LowByt.nbits=10
targets-ipv6-recon-slaac.vms=W
targets-ipv6-recon-slaac.nbits=10
targets-ipv6-recon-Map4t6.IPv4Hosts={192.168.1.0/8,192.168.5.0/8}
newtargets
#this-still-argument-but-#-change-his-name
```

And a bash script called nmap-testings.sh with those lines:

```
#! /bin/bash

Scripts="targets-ipv6-recon-dhcpv6,targets-ipv6-recon-LowByt,targets-ipv6-recon-wordis,targets-ipv6-recon-slaac,targets-ipv6-recon-map4to6,targets-ipv6-recon-report"
Script_Args_File="$HOME/dhcpd-testing"
Args="-6 -v3 -sn -e eth0"
Log1="Prueba-Todos-10bits.txt"
Err="ERROR_Prueba-Todos-10bits.txt"

echo "Executing... "
nmap $Args --script $Scripts --script-args-file $Script_Args_File > $Log1 2> $Err
echo "Finished"
```

The two files seem more complex, but for me was very useful for avoid insanity with so many scripts arguments. The Dhcpv6-testing is a single  file  where each line is a script argument; the bash script  is for running tests and defining the Nmap arguments (and the scripts).

This last example is one where all the scripts are being tested. If the node don't have enough memory for all the search, you can give the argument `targets-ipv6-recon-SaveMemory` to reduce the memory uses or  partitioned the scripts-args on multiple files, as many other way.