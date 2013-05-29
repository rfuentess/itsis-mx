local bin = require "bin"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local itsismx = require "itsismx"

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
--	@return	String	A Link-Address scope 
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
		--print("UNIX EPOCH!") 
	end
	
	-- We need to conver the number to bytes ( 4 bytes) 
	stime = stdnse.tohex (stime )
	while  #stime < 8 do  stime = "0" .. stime end
	
	--  we are using a typical DELL PC (By default)
	-- Future work can give a custom part here. (Don' forget FE80::/10 )
	-- and the constant FFFE for fill the 64 bits
	LinkAdd = "FE80000000000000" .. "24B6FD"  .. "FFFE" 
	-- The last 24 bits will be random (just avoid be so hussy)
	--math.randomseed ( nmap.clock_ms() )
	nRand = itsismx.DecToHex( math.random( 16777216 ) )-- 2^24
	while  #nRand < 6 do  nRand = "0" .. nRand end
	
	LinkAdd = LinkAdd .. nRand
	
	-- Finally we put everythign togheter LinkAdd
	DUID = DUID .. Hardware .. stime .. LinkAdd
	print(" DUID (" .. #DUID / 2 .. " octetos) :" ..   DUID)
	--print("\t Constat 1:  2"  )
	--print("\t Hardware: " .. #Hardware/2)
	--print("\t stime: " .. #stime/2)
	--print("\t LinkAdd: " .. #LinkAdd/2)
	
	stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				".DUID: " .. " New DUID: " ..   DUID  )
				
	return DUID , LinkAdd
end 

-- All the DHCP Options have this format:
--       0                   1                   2                   3
--       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |          option-code          |           option-len          |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |                          option-data                          |
--      |                      (option-len octets)                      |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

---
-- Will generate a  Relay Message Option 
-- RFC 3315 22.10. Relay Message Option p. 70
-- @args	String	The Spoofed message to add.
-- @return  String 	Hexadecimal bytes representing this DHCP option.
local Generar_Option_Relay = function ( Mensaje) 
	
	local Option_Code , Option_Len = "0009"
	Option_Len = itsismx.DecToHex( #Mensaje/2 )
	while #Option_Len < 4 do Option_Len = "0" .. Option_Len end 
	
	return Option_Code .. Option_Len .. Mensaje
end

---
-- Will generate a  IA_TA Option 
-- RFC 3315 22.2. Client Identifier Option p. 70
-- @return  String 	Hexadecimal bytes representing this DHCP option.
-- @return	String	Hexadecimal bytes representing the DUID.
local Generar_Option_ClientID =  function () 
	local ClientID
	-- Option-Len is the DUID lenght in octets. Our DUID have 24 bits
	-- which are 6 hexdecimal and those are 3 octets.
	local Option_Code , Option_Len, DUID, LinkAdd = "0001","0000", Generar_DUID()
	
	-- For now, with this info we simply return it (with the DUID)
	-- (In future we can make a more complex system trying to imitate 
	-- other type of nodes device with different type of DUID)
	Option_Len =  itsismx.DecToHex( #DUID / 2 )
	while #Option_Len < 4 do Option_Len = "0" .. Option_Len end 
	
	--print("\t Option-Code: " .. #Option_Code/2)
	--print("\t Option_Len: " .. #Option_Len/2)
	--print("\t DUID: " .. #DUID/2)
	ClientID = Option_Code .. Option_Len .. DUID
	
	return ClientID, DUID , LinkAdd
end
---
-- Will generate a  Client Identifier Option 
-- RFC 3315 22.5. Client Identifier Option p. 74
-- @return  String 	Hexadecimal bytes representing this DHCP option.
-- @return	String	Hexadecimal bytes representing the IAID.
local Generar_Option_IA_TA = function()
	local IA_TA
	local Option_Code , Option_Len, IAID, Options = "0004", 4, 0, ""
	 
	-- This is going to be very important for the binding (Well at least 
	-- for a real client). With the IAID for a temporary Address and with  DUID
	-- The IAID  ( RFC 3315 p. 9)
	
--	RFC 3315 p. 11
--	An identifier for an IA, chosen by the client.  Each IA has an IAID, which is 
--	chosen to be unique among all IAIDs for IAs belonging to that client.
		
	-- The RFC say "Client generate IAID" and the IAID is 4 octets...
	IAID = itsismx.DecToHex( math.random( 4294967296 ) ) -- 2^32
	while #IAID < 8 do IAID = "0" .. IAID  end
	
	-- The IA_TA Options... is variable lenght and the RFC is not clear 
	-- As we are trying to be a "first time node connecting to the network" 
	-- Im assume we ned the Satus Code NoBinding ( 0x02 ) 
	-- or maybe none ?
	Options = "02"
	Option_Len = itsismx.DecToHex (Option_Len + #Options)
	while #Option_Len < 4 do Option_Len = "0" .. Option_Len  end
	IA_TA = Option_Code .. Option_Len .. IAID .. Options
	
	--print("\t Option_Code: " .. #Option_Code/2)
	--print("\t Option_Len: " .. #Option_Len/2)
	--print("\t IAID: " .. #IAID/2)
	--print("\t Options: " .. #Options/2)
	
	return IA_TA , IAID
end

---
-- Will generate a  Elapsed Time Option 
-- RFC 3315 22.9. Elapsed Time Option  p. 78
-- @return  String 	Hexadecimal bytes representing this DHCP option.
local Generar_Option_Elapsed_Time = function()
	
	--local Time
	local option_code, option_len, elapsed = "0008" , "0002", "0000"
	-- TIP: elapsed-time field is set to 0 in the first message in the message
	-- TIP: unsigned, 16 bit integer
		
	-- Future work: Generate bigger "time" fields  for seem to  "beg" for a
	-- answer.
	--print("\t Option-Code: " .. #option_code/2)
	--print("\t Option_Len: " .. #option_len/2)
	--print("\t elapsed: " .. #elapsed/2)
	return option_code .. option_len .. elapsed
end
---
-- Will retrun a host Solicit Message based on chapter 17.1.1 Creation of solict Messages
-- p. 31.
-- @return 	String	A string representing HEXADECIMAL data (Ready for pack on raw bytes)
-- @return	Table	Tuple <DUID, Type, IAID >
-- @return 	String	Nil if there is no error, otherwise return a error message.
local Spoof_Host_Solicit = function () 

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

	local Solicit, Error = "01", nil
	local TransactionID, DUID, IAID, LinkAdd = 0
	local ClientID, IA_TA, Time
	local Host = { "DUID", "Type", "IAID", "LinkAdd"}
-- RFC 3315, 15.1 P. 27
--   The "transaction-id" field holds a value used by clients and servers
--   to synchronize server responses to client messages.  
-- RFC 3315, 17.1.1 P. 31
--	The client sets the "msg-type" field to SOLICIT.  The client
--   generates a transaction ID and inserts this value in the
--   "transaction-id" field.
-- Tip: The transaction-ID SHOULD be a strong random, however this is a spoofing
-- we are going to be very simple (but random for help us with multiple subnets. )

	-- Counter or Random ? That is the question...
	TransactionID = itsismx.DecToHex( math.random( 16777216 ) ) -- 2^24
	while #TransactionID < 6 do TransactionID = "0" .. TransactionID  end 
	
	stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				".Solicit: " .. " New SOLICIT Message. ID: " ..   TransactionID  )
				
	ClientID, DUID, LinkAdd = Generar_Option_ClientID()
	IA_TA, IAID = Generar_Option_IA_TA ()
	Time = Generar_Option_Elapsed_Time()
	
	--TIP: The client SHOULD include an Option Request option 
	-- AKA: IGNORE IT!!!
	print("TransactionID: " .. TransactionID ) 
	print("ClientID: " .. ClientID ) 
	print("IA_TA: " .. IA_TA ) 
	print("Time: " .. Time ) 
	
	-- Now we update the Tuple for this host
	Host.DUID = DUID
	Host.Type = "temporary" -- This script is using only IA_TA
	Host.IAID = IAID
	Host.LinkAdd = LinkAdd
	
	-- A this point we should have a valid SOLICIT Message... for this "alpha" verison 
	-- we are  going to have blind faith
	Solicit =  Solicit .. TransactionID ..  ClientID .. IA_TA .. Time
	
	return Solicit, Host,  Error
end

---
-- Will return a Relay-Forward message based on.... 
-- @args 	String	A string representing IPv6 Source of the spoofed host 
-- @args 	String	A string representing HEXADECIMAL data (The SOLICIT message)
-- @args	Table	A table of Subnetworks we want to test.
-- @return	String  A string representing HEXADECIMAL data (Ready for pack on raw bytes)
local Spoof_Relay_Forwarder = function ( Source, SOLICIT , Subnets )
	
	-- P. 50, 20.1.1  En el mecanismo real, si un nodo solicita IPv6 el agente Relay 
	-- anexa su prefijo global o de sitio. ESTO ES LO QUE HAREMOS SPOOFING. 
	-- This message will be " relay forwarder" from a spoofed agent to another REAL 
	-- relay agent ( hop-count must be 2-3 or user value)
	
	-- 	RFC 3315 7. Relay Agent/Server Message Formats P. 17
--	--   There are two relay agent messages, which share the following format:
--
--       0                   1                   2                   3
--       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |    msg-type   |   hop-count   |                               |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
--      |                                                               |
--      |                         link-address                          |
--      |                                                               |
--      |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
--      |                               |                               |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
--      |                                                               |
--      |                         peer-address                          |
--      |                                                               |
--      |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
--      |                               |                               |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
--      .                                                               .
--      .            options (variable number and length)   ....        .
--      |                                                               |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	
	local msg_type, hopcount, linkAdd, peerAdd, Options
	
	
	msg_type = "0C" -- msg-type is 12 ( 0x0C)
	hopcount = "02" -- Should be under user control too
	linkAdd = "20010db8c0ca00000000000000000001" -- THIS IS WHAT WE WANT !!!!
	peerAdd  = Source
	Options = Generar_Option_Relay( SOLICIT )
	
	print ("msg_type Message ( " .. #msg_type/2 .. " octetos): " .. msg_type )
	print ("hopcount Message ( " .. #hopcount/2 .. " octetos): " .. hopcount )
	print ("linkAdd Message ( " .. #linkAdd/2 .. " octetos): " .. linkAdd )
	print ("peerAdd Message ( " .. #peerAdd/2 .. " octetos): " .. peerAdd )
	print ("Options Message ( " .. #Options/2 .. " octetos): " .. Options )
	
	
	return msg_type .. hopcount .. linkAdd ..  peerAdd .. Options
end
---
-- The script need to be working with IPv6 
prerule = function()  
  if ( not(nmap.is_privileged()) ) then
		stdnse.print_verbose("%s not running for lack of privileges.", SCRIPT_NAME)
		return false
	end 
 
  if ( not(nmap.address_family() == "inet6") ) then
		stdnse.print_verbose("%s Need to be executed for IPv6.", SCRIPT_NAME)
		return false
	end
	
  return true
end

local Enviar_Mensaje = function (  IPv6src, IPv6dst, Protocolo , Prtsrc, Prtdst , Mensaje)
	local Bytes
	Bytes = bin.pack("H" , Mensaje )
	local Interfaz = nmap.get_interface()
	
	
	-- Seem broadcast-dhcp-discover.nse a good idea to search
	-- however , this don't seem to be working with Windows
	-- even when Nmap is launched with full privileges.
	
	--  targets-ipv6-multicast-mld.nse uses Paclet Lua Class  which work
	-- with raw packetes, however I don't find on the Lua file if is possible
	-- to add Data to custom UDP packets.
	-- local condvar = nmap.condvar(results) -- This is for multithreadign.. (not implemented yet)
	
	--local src_mac = packet.mactobin("00:D0:BB:00:00:01") -- (Spoofed) Cisco device!
	--local src_ip6 = packet.ip6tobin(IPv6src)
	local src_mac = packet.mactobin("60:eb:69:af:2b:83 ")
	local src_ip6 = packet.ip6tobin("fe80::62eb:69ff:feaf:2b83")
	local dst_mac = packet.mactobin("33:33:00:00:00:01")
	local dst_ip6 = packet.ip6tobin(IPv6dst)
	local gen_qry = packet.ip6tobin("::")

	local dnet = nmap.new_dnet()
	local pcap = nmap.new_socket()
	
	dnet:ethernet_open("eth0") -- Uh we need to provided this?
	--pcap:pcap_open(if_nfo.device, 1500, false, "ip6[40:1] == 58") -- this is for AFTER sending the packet
	
	local probe = packet.Frame:new()
	probe.mac_src = src_mac
	probe.mac_dst = dst_mac
	probe.ip_bin_src = src_ip6
	probe.ip_bin_dst = dst_ip6
	
	probe.ip6_tc = 0 -- Traffic Class
	probe.ip6_fl = 0 -- Flow Label 
	probe.ip6_hlimit = 3 -- Hop Limit (This should be variable)
	probe.ip6_nhdr = 17 -- 17 es UDP 
	-- Next header is a UDP
	
	probe.udp_set_sport = Prtsrc
	probe.udp_set_dport = Prtdst
	
	-- Now the secret which is not declare on the Packet.lua Library... 
	-- The Payload method/function/whatever fuse the data
	-- togheter the packet
	probe.udp_count_checksum()  -- just testing...
	probe.udp_set_length = Bytes
	
	
	--UDP packet ready...
	
	probe:build_ipv6_packet() -- This should assemble the IPv6
	probe:build_ether_frame() -- Finally the Frame

	dnet:ethernet_send(probe.frame_buf) -- And we send everything!
	
end
---
-- This run only as pre-scanning phase.
action = function()

	math.randomseed ( nmap.clock_ms() )
	--Vars for created the final report
	
	local tOutput = stdnse.output_table()
	local bExito = false
	local tSalida =  { Subnets={}, Error=""}
	 
	tOutput.Subnets = {}  
	print("HEY!")
	itsismx.Registro_Global_Inicializar("dhcpv6") -- We prepare our work!
	
	local Mensaje, Host, Error, Relay
	
	Mensaje, Host, Error	= Spoof_Host_Solicit()
	
	print ("SOCICIT Message ( " .. #Mensaje/2 .. " octetos): " .. Mensaje )
	
	Relay = Spoof_Relay_Forwarder ( Host["LinkAdd"] , Mensaje , nil )
	
	print ("Relay Message ( " .. #Relay/2 .. " octetos): " .. Relay )
	-- We create a RAW Packet!
	--  "DUID", "Type", "IAID", "LinkAdd"}
	Enviar_Mensaje( Host["LinkAdd"], "FF02::1:2", "udp", 546,547, Mensaje )
	
	return stdnse.format_output(bExito, tOutput);	
	--return  tOutput
	
end

