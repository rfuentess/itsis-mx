# Risk of DoS #

AS is told on the main page, executing a heavy sweep operation on remote IPv6 networks incurs on risk of a DoS.

The problem is well document on [RFC 6583 Operational Neighbor Discovery Problems ](http://tools.ietf.org/html/rfc6583) and easy word can be translated like this: A poor NDP buffer implementation, will make the gateway slowly to exhaust all the RAM as  add new hosts to cache.  Once the memory is exhausted the DoS happens.

Where is the remote network, and which services where running by the Gateway will define the type of DoS.

Lets use the next topology, used on the thesis work, as a example:

![https://lh6.googleusercontent.com/-o-U3gTQEmZA/U07CArQCAVI/AAAAAAAABNQ/JtidmXlmW68/w705-h510-no/cap4_topologia.png](https://lh6.googleusercontent.com/-o-U3gTQEmZA/U07CArQCAVI/AAAAAAAABNQ/JtidmXlmW68/w705-h510-no/cap4_topologia.png)

On the topology, the routing protocol EIGRP for IPv6, and other for IPv4 are running on the routers.

If we begin a heavy exploration on the sub-network C from sub-network B, the DoS will appear as the lost of access to router 3.  As the [R3](https://code.google.com/p/itsis-mx/source/detail?r=3) ram have the RBI for both EIGRP protocol and will be erased. The DoS seem to reduced to one single sub-network.

Other story will be if we try to explore the sub-network with virtual machines. If the DoS happens all the network will lost access as [R2](https://code.google.com/p/itsis-mx/source/detail?r=2) is the backbone of the network.