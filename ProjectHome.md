# Introduction #

Itsismx (or itsis-mx)  is a collection of NSE scripts for Nmap 6.20 and posterior which add some IPv6 scanning techniques.  The techniques are based on the draft  ["Network Reconnaissance in IPv6 Networks"](http://tools.ietf.org/html/draft-ietf-opsec-ipv6-host-scanning-02) of Francisco Gont and T. Chown.

The scripts work for Low-bytes, SLAAC (with special focus for V.M.), Map4to6, and words, plus a special technique for extracting sub-networks information from DHCPv6 servers.

As the heart of this work was  possible to do it thanks to Nmap, the source code is released with [Nmap's license](http://nmap.org/book/man-legal.html#nmap-copyright).  And the master thesis  is available with the  creative commons licenses (however is on my mother language, spanish) on this
[link](http://itsis-mx.googlecode.com/git/Thesis-spanish.pdf).

![https://lh3.googleusercontent.com/-OLO5Q7MJCVs/U0WbqpyZaiI/AAAAAAAABLk/_uSCMqJLJ1o/w1031-h525-no/Itsismx.png](https://lh3.googleusercontent.com/-OLO5Q7MJCVs/U0WbqpyZaiI/AAAAAAAABLk/_uSCMqJLJ1o/w1031-h525-no/Itsismx.png)


---


# Nmap and NSE #

_(extracted from the [main site](http://www.nmap.org))_

> Nmap ("Network Mapper") is a free and open source  utility for network discovery and security auditing.  Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics.

> The Nmap Scripting Engine (NSE) is one of Nmap's most powerful and flexible features. It allows users to write (and share) simple scripts (using the Lua programming language, ) to automate a wide variety of networking tasks. Those scripts are executed in parallel with the speed and efficiency you expect from Nmap. Users can rely on the growing and diverse set of scripts distributed with Nmap, or write their own to meet custom needs.

# Using the scripts #

> The **best performance is  achieved on the GNU/Linux distribution.** By two factors:

  1. Nmap can use all his techniques, for probes nodes, only with the original Libpcap for Linux [read more on this link](http://nmap.org/book/man-host-discovery.html).
  1. DHCPv6's script works only for GNU/Linux (need to create raw packets using libcap).


## "Installing" ##

If you are new to Nmap, this could be a little confused at first, however, it's easy.  **You need to import the scripts to Nmap folders _Nmap/nselib_ and _Nmap/scripts_**. Once the scripts are there, you need to execute the follow command:

nmap --scripts-updatedb

The command is mandatory due Nmap use a special DB for be able to offer his famous modular properties (A very impressive and powerful characteristic).

### Linux users ###

If you use your favorite way to retrieve the application,  probably you need to check version ( _nmap --version_). If the version is lesser than 6.40 is a good idea to go to Nmap's site and install from [the source code](http://nmap.org/book/inst-linux.html).

It's probably you will need to check your  `/usr/local/share/nmap` folder instead of the Nmap Path. And of course, you need enough privilege to copy the files to those folders.

### Windows (Vista/7/8) users ###

You can install the latest version from the [main site](http://nmap.org/book/inst-windows.html).

Nmap by default will be installed on the Program Files folder, for moving the files to the folder, you need enough privileges for do it  or install the program on other directory.


---


## Risk of DoS! ##

By default, only the script for DHCPv6 and wordly are safe to use. The other scripts brings a latent risk of provoking a DoS. However, **the risk is due poor NDP implementation on the gateways**. You can read more about the risk on the [RFC 6583 Operational Neighbor Discovery Problems ](http://tools.ietf.org/html/rfc6583)

On general, the chances of DoS will increase as you increase the size of the sweep. The default values on the scripts are inside of a secure search (well, for a Router cisco 2811 with 512 MB of RAM).

By this same reason, the scripts are on the NSE category of Dos, with the exception of DHCPv6 script. ( [More about NSE categories](http://nmap.org/book/nse-usage.html#nse-categories))

