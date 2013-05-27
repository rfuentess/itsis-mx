local bin = require "bin"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"


description = [[
  The objective is work as "fake" relay agent for DHCPv6. We are going to generate "valids" request for a
  host, but we are going to spoofing the Sub-network. With this, the server  will send us a valid option or 
  nothing (if the subnet is wrong or if there is  ACL or IPsec). 
  
  The objective is not a DoS against the server neither retrive host info but simply confirm if a subset of 
  sub-networks exist at all. Will generate one single relay-forwarder message (RFC 3315 20.1.2 p. 59)
  with a good HOP_COUNT_LIMIT (Spoofed) and a host request-message (Spoofed with random DUID) and we are going 
  to wait for a Relay-reply message (20.3 p. 60) if we got answer, (optional) we send another relay-forwarder 
  message with a host declined-message for don't be evil with the server. 
  
  ACL on the server, ACL on the router,  IPsec between relays agent and server  can kill this technique.
  However almost all the RFC 3315 is more cautious with host poisoning than this type of idea. 
]]


---
-- @usage
-- nmap -6 --script itsismx-dhcpv6 --script-args 
--
-- @output


-- @args itsismx-dhcpv6.subnet 	It's table/single  IPv6 subnetworks to test if exist .
--	   (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )
--		NOTE: If one or more are discovered as valid sub-network will be added to a special
--		registry for all the other scripts (words, slaac, map4to6, mac-prefixes) to be used.

-- Version 0.2
-- 	Created 27/05/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam@gmail.com>
--

author = "Raul Armando Fuentes Samaniego"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

--- 
-- Will generate a random DUID with a valid format. This is going to be:
-- Link-layer address plus time [DUID-LLT] (RFC 3315 9.2 p. 20) 
--  @return String	A valid DUID-LLT
Generar_DUID = function ( ) 

--    0                   1                   2                   3
--     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--    |               1               |    hardware type (16 bits)    |
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--    |                        time (32 bits)                         |
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--    .                                                               .
--    .             link-layer address (variable length)              .
--    .                                                               .
--    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


	local DUID = "0001" -- DUID-LLT begin with the constant 0x0001
	-- Hardware type is a special code of ARP passed to DHCPv6
	-- we can find more info on: http://www.iana.org/assignments/arp-parameters/arp-parameters.xml
	-- By default will be "Ethernet" (0x0001)
	local Hardware = "0001"
	local stime = nmap.clock()
	local LinkAdd, nRand
	
	-- We work first the time Variable. We need to pass to a valid represented in seconds since 
	-- midnight (UTC) January 1, 2000  modulo 2^32
	-- WE have a little problem there... Probably this is a EPOCH  Unix: 01/01/1970 ... 
	if ( stime > 946684800) then  -- Ok, maybe on 17 years this is going to be fatal error
		-- We need to remove 30 years of the time from that lecture... OR give a arbitary 
		-- epochtime = ((((((ts.Days * 24) + ts.Hours) * 60) + ts.Minutes) * 60) + ts.Seconds);

		stime = stime - 946684800 -- For now, we only substract 30 years (more or less)
		
	end
	
	-- We need to conver the number to bytes ( 4 bytes) 
	stime = stdnse.tohex (stime )
	while  #stime < 8 do  stime = "0" .. stime end
	
	-- Now the link-layer Address , we are going to say, we are using a typical DELL PC (By default)
	LinkAdd = "24B6FD"  .. "FFFE" 
	-- The last 24 bits will be random 
	math.randomseed ( nmap.clock_ms() )
	nRand = math.random( 16777216 ) -- 2^24
	nRand = itsismx.DecToHex(nRand )
	-- However, we need be sure this a 24 bits length
	while  #nRand < 6 do  nRand = "0" .. nRand end
	
	LinkAdd = LinkAdd .. nRand
	
	-- Finally we put everythign togheter
	print(" DUID (" .. #DUID * 2 .. " octetos) :" ..   DUID)
	
	return DUID
end 

---
-- Will retrun a host Solicit Message based on chapter 17.1.1 Creation of solict Messages
-- p. 31-
Spoof_Host_Solicit = function () 

-- 	From RFC 3315  section 6. Client/Server Message Formats   p. 16 
--  this is what we are going to create :

--      0                   1                   2                   3
--       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |    msg-type   |               transaction-id                  |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |                                                               |
--      .                            options                            .
--      .                           (variable)                          .
--      |                                                               |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

--   msg-type SOLICIT Message (0x01)
--  transaction-id   - Random value seem to be (We need to remember IT!)
--  Options: 		 - We are force to add (At least) Client Identifier Option, 
--					    IA_TA option and  Elapsed Time option
--					   
 
-- TIP: Our fake host is going to use "temporary adddress" so, we only focus on IA_TA
 
-- TIP: RFC p. 32 say we need to wait random time, howeve,r this is a Spoofed  request
-- after the node is already configured, so... we ignore it.




end
---
-- The script need to be working with IPv6 
prerule = function() return ( nmap.address_family() == "inet6") end

---
-- This run only as pre-scanning phase.
action = function()


	--Vars for created the final report
	
	local tOutput = stdnse.output_table()
	local bExito = false
	local tSalida =  { Subnets={}, Error=""}
	 
	tOutput.Subnets = {}  
	
	itsismx.Registro_Global_Inicializar("Map4t6") -- We prepare our work!
	
	return stdnse.format_output(bExito, tOutput);	
	--return  tOutput
	
end

