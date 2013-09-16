local bin = require "bin"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local itsismx = require "itsismx"
local ipOps = require "ipOps"

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
--	   We can have two types of entries: Single subnet ( X:X:X:X::/YY ), or 
--          range of subnets to calculate (X:X:X:X::/YY , Bits, Total ) where  
--	    B are the bits used for subnetting and Total amount of subnets to search.
--	    Please, be sure of the next:  2^Bits >= Total
--	   (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } or 
--          { {2001:db8:c0ca::/48, 16, 23} , 2001:db8:c0ca::/48} )
--		NOTE: If one or more are discovered as valid sub-network will be added to a special
--		registry for all the other scripts (words, slaac, map4to6, mac-prefixes) to be used.

-- @args itsismx-dhcpv6.TimeToBeg	It-s a number. 16 bits expressed in hundreths of a second.
--		When we are sending solicits, the clients indicate  ow much time had spent
--		trying to get a Address, this make some server and relay agents give ive preference
--		 to solicits with higher Time
--@args	itsismx-dhcpv6.Company		String 6 hexadecimal.  By defualt the script will generate
--		random hosts from a DELL OUI (24B6FD). With this argument the user can provided 
--		a specific OUI. However, the last 24 bits will still be generate randomly.
--@args itsismx-dhcpv6.utime		Number. Between each try to get a subnet we wait random time
--					measure on microseconds. By default we wait no more than 
--					200 microseconds. With this argument the user can provided a 
--					another time. (Minimun 1 
-- Version 0.5
--	Update 04/06/2013	- V0.5 Produce the messages to spoof.
-- 	Created 27/05/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam+nmap@gmail.com>
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
	local LinkAdd, nRand, Mac
	-- Note: LinkAdd will generate a IPv6 Address and Mac will generate a MAC address
	--       both will be from the same source (EUI-64)
	
	-- We work first the time Variable. We need to pass to a valid represented in seconds since 
	-- midnight (UTC) January 1, 2000  modulo 2^32
	-- WE have a little problem there... Probably this is a EPOCH  Unix: 01/01/1970 ... 
	if ( stime > 946684800) then  -- Ok, maybe on 17 years this is going to be fatal error
		-- We need to remove 30 years of the time from that lecture... or give a arbitrary value 
		-- epochtime = ((((((ts.Days * 24) + ts.Hours) * 60) + ts.Minutes) * 60) + ts.Seconds);
		stime = stime - 946684800 -- For now, we only substract 30 years (more or less)
	end
	
	-- We need to conver the number to bytes ( 4 bytes) 
	stime = stdnse.tohex (stime )
	while  #stime < 8 do  stime = "0" .. stime end
	
	--  we are using a typical DELL PC (By default)
	-- Future work can give a custom full host   here. (Don' forget FE80::/10 )
	local Ghost = stdnse.get_script_args( "itsismx-dhcpv6.Company" )
	
      	if Ghost ~= nil then
	   -- We need to be sure the OUI be a valid 
	   if itsismx.Is_Valid_OUI(Ghost) then
	     LinkAdd = "FE80000000000000" .. Ghost  .. "FFFE"
	     Mac = Ghost
	   else
	      LinkAdd = "FE80000000000000" .. "24B6FD"  .. "FFFE" 
	      Mac = "24B6FD"
	      stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"DUID-LLT ERROR  " .. " was provided a INVALID OUI value and was ignored. " )
	   end
	else 
	  Mac = "24B6FD"
	  --LinkAdd = "FE80000000000000" .. "24B6FD"  .. "FFFE" 
	  LinkAdd = "FE80000000000000" .. "26B6FD"  .. "FFFE"
	end
	
	-- The last 24 bits will be random (just avoid be so hussy)
	--math.randomseed ( nmap.clock_ms() )
	nRand = itsismx.DecToHex( math.random( 16777216 ) )-- 2^24
	while  #nRand < 6 do  nRand = "0" .. nRand end
	
	 
	LinkAdd = LinkAdd .. nRand
	Mac = Mac .. nRand
	--print("\t Link-Layer: " .. LinkAdd )
	--print("\t MAC       : " .. Mac  )
	
	-- Finally we put everythign togheter LinkAdd
	DUID = DUID .. Hardware .. stime .. Mac
	--print(" DUID (" .. #DUID / 2 .. " octetos) :" ..   DUID)
	--print("\t Constat 1:  2"  )
	--print("\t Hardware: " .. #Hardware/2)
	--print("\t stime: " .. #stime/2)
	--print("\t LinkAdd: " .. #LinkAdd/2)
	
	stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"DUID-LLT: " .. " New DUID: " ..   DUID  )
				
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
-- Will generate a  Client Identifier Option  
-- RFC 3315 22.2. Client Identifier Option p. 70
-- @return  String 	Hexadecimal bytes representing this DHCP option.
-- @return	String	Hexadecimal bytes representing the DUID.
local Generar_Option_ClientID =  function () 
	local ClientID
	-- Option-Len is the DUID lenght in octets. Our DUID have 24 bits
	-- which are 6 hexdecimal and those are 3 octets.
	local Option_Code , Option_Len, DUID, LinkAdd = "0001","0000", Generar_DUID()
	
	-- We need to generate 
	
	
	-- For now, with this info we simply return it (with the DUID)
	-- (In future we can make a more complex system trying to imitate 
	-- other type of nodes device with different type of DUID)
	Option_Len =  itsismx.DecToHex( #DUID / 2 )
	while #Option_Len < 4 do Option_Len = "0" .. Option_Len end 
	
	--print("\t Option-Code: " .. #Option_Code/2)
	--print("\t Option_Len: " .. #Option_Len/2)
	--print("\t DUID: " .. #DUID/2)
	
	stdnse.print_debug(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			".Solicit.Elapsed Time: " .. 
			" \n\t --[[Option]]-Code: " ..   Option_Code .. 
			" \n\t Option Lenght: " ..   Option_Len .. 
			" \n\t DUID: " ..   DUID  )
	
	ClientID = Option_Code .. Option_Len .. DUID
	
	return ClientID, DUID , LinkAdd
end


--- 
-- Will generate a Identity Address Option  RFC 3315 22.6 p. 75
-- @return  String 	Hexadecimal bytes representing this DHCP option.
local Generar_IA_Option = function()

--  The format of the IA Address option is:
-- 
--        0                   1                   2                   3
--        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--       |          OPTION_IAADDR        |          option-len           |
--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--       |                                                               |
--       |                         IPv6 address                          |
--       |                                                               |
--       |                                                               |
--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--       |                      preferred-lifetime                       |
--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--       |                        valid-lifetime                         |
--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--       .                                                               .
--       .                        IAaddr-options                         .
--       .                                                               .
--       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  local Op_IAADDR, option_len, Ipv6Add , preferred, valid, options
  Op_IAADDR = "0005"
  
  --values in the preferred  and valid lifetime fields indicate the client's 
  -- preference for those parameters.  The client may send 0 if it has no 
  -- preference for the preferred and valid lifetimes.
  preferred, valid = "00000000", "00000000" 
 
  -- For now... static but should  be dynamic... if is not static  
  -- we risk to been spoted easy (Two interfaces can have same link/address
  -- as long they are on different subnets)
  --Ipv6Add = "FE8000000000000062eb69fffeaf2b83" 
  Ipv6Add =   "20010db8c0ca000000000000c0a8010b"

 --An IA Address option may appear only in an IA_NA option or an IA_TA
 -- option. For our project mean: NO OPTIONS.
  options = ""
   option_len = itsismx.DecToHex( 24 + #options/2)
   while #option_len < 4 do option_len = "0" .. option_len end

   return Op_IAADDR .. option_len .. Ipv6Add .. preferred .. valid .. options
end

---
-- Will generate a  IA_TA Option
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
	-- Im assume we need the Satus Code NoBinding ( 0x02 ) 
	-- or maybe none ?
	-- OK... Seem we need IA Option field which is inside of IA_TA or IA_NA
	-- P. 76 RFC 3314 22.6
	-- Sep13: After seeing the work of current implemented servers  seem it's better
	-- left it on blank.
	Options = Generar_IA_Option()
	--Options = ""
	
	Option_Len = itsismx.DecToHex (4 + #Options/2)
	while #Option_Len < 4 do Option_Len = "0" .. Option_Len  end
	IA_TA = Option_Code .. Option_Len .. IAID .. Options
	
	--print("\t Option_Code: " .. #Option_Code/2)
	--print("\t Option_Len: " .. #Option_Len/2)
	--print("\t IAID: " .. #IAID/2)
	--print("\t Options: " .. #Options/2)
	stdnse.print_debug(4, SCRIPT_NAME .. 
				".Solicit.Elapsed Time: " .. 
				" \n\t Option-Code: " ..   Option_Len .. 
				" \n\t Option Lenght: " ..   Option_Len .. 
				" \n\t IAID: " ..   #IAID .. 
				" \n\t Options: " ..   Options)
	
	
	return IA_TA , IAID
end

---
-- Will generate a  IA_NA Option
-- RFC 3315 22.3. Client Identifier Option p. 74
-- @return  String 	Hexadecimal bytes representing this DHCP option.
-- @return	String	Hexadecimal bytes representing the IAID.
local Generar_Option_IA_NA = function()
    local IA_NA, Option_Code , Option_Len, IAID, T1, T2
    local IA_NA_Options

--	The format of the IA_NA option is:
--       0                   1                   2                   3
--       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |          OPTION_IA_NA         |          option-len           |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |                        IAID (4 octets)                        |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |                              T1                               |
--     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |                              T2                               |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |                                                               |
--      .                         IA_NA-options                         .
--      .                                                               .
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

      
	  -- Read the Generar_Option_IA_TA comments
	  -- RFC 3315 p. 74:
	  -- In a message sent by a client to a server, values in the T1 and T2
	  ---fields indicate the client's preference for those parameters.  The
	  --client sets T1 and T2 to 0 if it has no preference for those values.

	Option_Code,T1, T2 = "0003", "00000000", "00000000" 
	
	-- The RFC say "Client generate IAID" and the IAID is 4 octets...
	--IAID = itsismx.DecToHex( math.random( 4294967296 ) ) -- 2^32
	IAID="f" --Seem wide-dhcpv6-server need this field to be F
	while #IAID < 8 do IAID = "0" .. IAID  end

	 -- Though those are dynamic seem to be totally optionals.
	IA_NA_Options = ""
	
	Option_Len = itsismx.DecToHex (12 + #IA_NA_Options/2)
	while #Option_Len < 4 do Option_Len = "0" .. Option_Len  end
	 print( "IANA Lenght: " .. 12 + #IA_NA_Options/2 .. " YA en hex:" .. Option_Len ) 
	
	IA_NA = Option_Code .. Option_Len ..  IAID ..  T1 ..  T2  .. IA_NA_Options
	return IA_NA , IAID
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
		
	-- Generate bigger "time" fields  for seem to be "begging" for a quick 
	-- answer.
	local TimetoBeg = stdnse.get_script_args( "itsismx-dhcpv6.TimeToBeg" )
	
	if TimetoBeg ~= nil  then
	    elapsed = itsismx.DecToHex(TimetoBeg )
	    while #elapsed < 4 do elapsed = "0" .. elapsed end
	end
	
	stdnse.print_debug(4, SCRIPT_NAME ..  
				".Solicit.Elapsed Time: " .. 
				" \n\t Option-Code: " ..   option_code .. 
				" \n\t Option Lenght: " ..   option_len .. 
				" \n\t Time elapsed: " ..   elapsed  )
	
	return option_code .. option_len .. elapsed
end



-- Will generate a Option Request Option 
-- RFC 3315 22.7. Elapsed Time Option  p. 78
-- @return  String 	Hexadecimal bytes representing this DHCP option.
local Generar_Option_Request = function()

--      0                   1                   2                   3
--       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |           OPTION_ORO          |           option-len          |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |    requested-option-code-1    |    requested-option-code-2    |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--      |                              ...                              |
--      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
  -- This message is generated due  seem to be neccesary
  local Option_Oro, Option_Len, req_option_code1 = "0006", "0002"
  
  --option-len    2 * number of requested options.
  
  -- The RFC is not clear which are our option however, there is a known one 
  -- for ask the  domain name which is 24 (0x0018) 
  req_option_code1 = "0018"
  
  return Option_Oro .. Option_Len .. req_option_code1

end
---
-- Will retrun a  RANDOM host Solicit Message based on chapter 17.1.1 Creation of 
-- solict Messages p.31.  We don't care too much on the node to create.
-- @return 	String	A string representing HEXADECIMAL data (Ready for pack on raw bytes)
-- @return	Table	Tuple <DUID, Type, IAID, LinkAdd >
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
	local ClientID, IA_TA, Time, Option_Request
	local IA_NA
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
				
	ClientID, DUID, LinkAdd = Generar_Option_ClientID()
	
	-- IA-TA & IA-NA are our option ,however seem not all the dhcpv6 servers work well with both
	-- by example, wide-dhcpv6-server only accept IA-NA
	-- IA_TA, IAID = Generar_Option_IA_TA ()
	IA_NA, IAID = Generar_Option_IA_NA ()
	
	--print(" El problema: " .. IA_NA .. " ( " .. #IA_NA .. ")" )
	
	Time = Generar_Option_Elapsed_Time()
	
	--TIP: The client SHOULD include an Option Request option 
	-- AKA: IGNORE IT!!!
	-- Sep: Bad idea?
	Option_Request = Generar_Option_Request()

	stdnse.print_debug(3, SCRIPT_NAME ..  
				".Solicit: " .. " New SOLICIT Message. ID: " ..   TransactionID  )
	stdnse.print_debug(3, SCRIPT_NAME .. 
				".Solicit: " .. " Client ID: " ..   ClientID  )
				
	--stdnse.print_debug(3, SCRIPT_NAME .. 
	--			".Solicit: " .. " IA-TA : " ..   IA_TA  )
	stdnse.print_debug(3, SCRIPT_NAME ..  
				".Solicit: " .. " Time: " ..   Time  )
	stdnse.print_debug(3, SCRIPT_NAME ..  
				".Solicit: " .. " Option Request: " ..   Option_Request  )
	
	--print("TransactionID: " .. TransactionID ) 
	--print("ClientID: " .. ClientID ) 
	--print("IA_TA: " .. IA_TA ) 
	--print("Time: " .. Time ) 
	
	-- Now we update the Tuple for this host
	Host.DUID = DUID
	Host.Type = "temporary" -- For this version we're  using only IA_TA
	Host.IAID = IAID
	Host.LinkAdd = LinkAdd
	
	stdnse.print_debug(2, SCRIPT_NAME ..  
				".Solicit: " .. " (G)Host - Link-Address: " ..   Host.LinkAdd .. --
				" type of request: " .. Host.Type  .. 
				"\n DUID: " ..  Host.DUID .. "\n IAID: "  .. Host.IAID )
	
	
	-- A this point we should have a valid SOLICIT Message... for this "alpha" verison 
	-- we are  going to have blind faith
	--Solicit =  Solicit .. TransactionID ..  ClientID  .. IA_TA ..   Time .. Option_Request
	Solicit =  Solicit .. TransactionID ..  ClientID  .. IA_NA ..   Time .. Option_Request
	return Solicit, Host,  Error
end

---
-- Will return a Relay-Forward message based on.... 
-- @args 	String	A string representing IPv6 Source of the spoofed host 
-- @args 	String	A string representing HEXADECIMAL data (The SOLICIT message)
-- @args	String  IPv6 Subnet which we want to confirm to exist.
-- @return	String  A string representing HEXADECIMAL data (Ready for pack on raw bytes)
-- @return 	Error	If there is a error will return the reason, otherwise nil
local Spoof_Relay_Forwarder = function ( Source, SOLICIT , Subnet )
	
	-- P. 59, 20.1.1  En el mecanismo real, si un nodo solicita IPv6 el agente Relay 
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
	local Relay, sError, sUnicast, Address, Prefix
	
	msg_type = "0C" -- msg-type is 12 ( 0x0C)
	hopcount = "02" -- Should be under user control too
	linkAdd = "20010db8c0ca00000000000000000001" -- THIS IS WHAT WE WANT !!!!
	peerAdd  = Source
	Options = Generar_Option_Relay( SOLICIT )
	
	if Subnet == nil then
	  linkAdd = "20010db8c0ca00000000000000000001"
	elseif #Subnet == 0 then -- empty or nil is bad (But we need to confirm first is not nil)
	  linkAdd = "20010db8c0ca00000000000000000001"
	else 	--We assume is  IPv6 Address and we need to convert to Hexadecimal value
	 
	    Address, Prefix = itsismx.Extract_IPv6_Add_Prefix(Subnet)
	    sUnicast, sError = ipOps.get_last_ip  (Address, Prefix) --We use the last IPv6 add because is alway valid
	  
	    if sUnicast == nil then
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				  "\n\t Relay Forward: " .. " The subnet provided (" .. stdnse.string_or_blank(Subnet) ..
				  ")  was bad formed and throw the next error: " ..  sError )
		return "", sError
	     else 
		-- WE need to expand the IPv6 address to use all the hexadecimals
		--print ( "linkAdd (" .. #sUnicast .. "): " .. sUnicast  ) 
		-- We need to remove ":" from the chain.
		
		local Segmentos, HexSeg = {}
		local S1, S2, S3, S4, S5, S6, S7, S8
		Segmentos = ipOps.get_parts_as_number(sUnicast)
		S1, S2, S3, S4, S5, S6, S7, S8 = table.unpack( Segmentos )
		linkAdd = ""
		--print(S1 .. S2 .. S3 .. S4 .. S5 .. S6 .. S7 .. S8 )
		
		HexSeg = itsismx.DecToHex(S1)
		while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
		linkAdd = linkAdd .. HexSeg
		HexSeg = itsismx.DecToHex(S2)
		while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
		linkAdd = linkAdd .. HexSeg
		HexSeg = itsismx.DecToHex(S3)
		while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
		linkAdd = linkAdd .. HexSeg
		HexSeg = itsismx.DecToHex(S4)
		while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
		linkAdd = linkAdd .. HexSeg
		HexSeg = itsismx.DecToHex(S5)
		while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
		linkAdd = linkAdd .. HexSeg
		HexSeg = itsismx.DecToHex(S6)
		while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
		linkAdd = linkAdd .. HexSeg
		HexSeg = itsismx.DecToHex(S7)
		while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
		linkAdd = linkAdd .. HexSeg
		HexSeg = itsismx.DecToHex(S8)
		while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
		linkAdd = linkAdd .. HexSeg
		--linkAdd = S1 .. S2 .. S3 .. S4 .. S5 .. S6 .. S7 .. S8
		
		--print ( "linkAdd (" .. #linkAdd .. "): " .. linkAdd  ) 
	      
	    end
	    
	    
	   
	end
	
	
	--print ("msg_type Message ( " .. #msg_type/2 .. " octetos): " .. msg_type )
	--print ("hopcount Message ( " .. #hopcount/2 .. " octetos): " .. hopcount )
	--print ("linkAdd Message ( " .. #linkAdd/2 .. " octetos): " .. linkAdd )
	--print ("peerAdd Message ( " .. #peerAdd/2 .. " octetos): " .. peerAdd )
	--print ("Options Message ( " .. #Options/2 .. " octetos): " .. Options )
	
	stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"\n\t Relay Forward: " .. " msg_type: " ..   msg_type .. 
				"\n\t hopcount: " .. msg_type  .. 
				"\n\t linkAdd: " .. linkAdd  .. 
				"\n\t peerAdd: " .. peerAdd  .. 
				"\n\t Options: " ..  Options   )
	
	Relay = msg_type .. hopcount .. linkAdd ..  peerAdd .. Options
	return Relay, nil
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

	  -- Need to  have access to one ethernet port at least.
	
  return true
end

--- 
-- Will create a spoofed message for transmit (any message)  and inmediatly 
-- will hear for a answer (to be selected by a filter) and will return it.
local Transmision_Recepcion = function (  IPv6src, IPv6dst , Prtsrc, Prtdst , Mensaje, Tcpdumb_Filter)
	local Bytes --, ToTransmit
	Bytes = bin.pack("H" , "0000000000000000" .. Mensaje ) -- those extra bits are for being overwritten

	local Interfaz = nmap.get_interface()
	local Bool
	
	local dnet = nmap.new_dnet()
	local pcap = nmap.new_socket()
	
	local tSalida =  { Subnets={}, Error=""}
	
	-- local condvar = nmap.condvar(results) -- This is for multithreadign.. (not implemented yet)
	
	local src_mac = packet.mactobin("00:D0:BB:00:7d:01") -- (Spoofed) Cisco device!
	--local src_mac = packet.mactobin("00:21:70:1c:9b:79")
	-- local dst_mac = packet.mactobin("33:33:00:00:00:01")  -- Seem to be wrong this Multicast
	  local dst_mac = packet.mactobin("33:33:00:01:00:02")
	--local src_ip6 = packet.ip6tobin(IPv6src)
	--local src_ip6 = packet.ip6tobin("fe80::62eb:69ff:feaf:2b83")
	local src_ip6 = bin.pack("H", IPv6src) --We already have it on "bytes"
	local dst_ip6 = packet.ip6tobin(IPv6dst)

	-- We open all the elements we are going to need
	
	-- dnet:ip_open()
	dnet:ethernet_open("eth0")
	
	-- Before we begin to send packets is a good idea turn on the Pcap 
	-- for retrieve our own packets (That is don't lost our message because we turn on too late).
	--pcap:pcap_open(if_nfo.device, 1500, false, "ip6[40:1] == 58") -- this is for AFTER sending the packet
	
	-- From zero... We need a UDP datagram, then a IP packet  and finally a Ethernet Frame... 
	-- UDP and IP are declared inside of the "Packet class" on packet.lua
	
	local Spoofed = packet.Packet:new()
	
	-- Ejem src, dst, nx_hdr, payload, h_limit, t_class, f_label	
	-- IPv6 Packet with nex Header as UDP, Hoplimit 3, and Traffic class
	-- and Flow label set to zero.
	-- payload ITS dangerous because will place all the data
	-- Howeve,r this data NEED TO HAVE FIRST THE UDP otherwise
	-- the UDP part will overwritten it... 
	-- The Easy solution: Add 4 bytes more to our data.
      
	Spoofed:build_ipv6_packet(src_ip6,dst_ip6,17, Bytes ,3,0,0)
	
	Bool = Spoofed:ip6_parse(false)
	--print("Parse IPv6: " .. tostring(Bool))
	
	--We work the UDP...
	Spoofed:udp_parse(false) --Now the UDP ...
	--print("Parse UDP: " .. tostring(Bool))
	Spoofed:udp_set_sport(Prtsrc) 
	Spoofed:udp_set_dport(Prtdst)
	Spoofed:udp_set_length(#Bytes) 
	Spoofed.ip_p = 17 -- Seem that udp_count_checksum() wasn't update for IPv6...
	Spoofed:udp_count_checksum()
	
	--print("UDP PAcket: " .. Spoofed:udp_tostring())
	
	-- En teoria ya arme el paquete UDP, sigue completar IPv6
	Spoofed:count_ipv6_pseudoheader_cksum()
	
	-- We already have everything, however, we can spoof  the MAC address
	-- This part of packet.lua is... CRAP we ignore the "class"
	-- and write the info directly to our Frame to send.
	local probe = packet.Frame:new()
	probe.mac_dst = dst_mac
	probe.mac_src = src_mac
	probe.ether_type = string.char(0x86, 0xdd)
	probe.buf = Spoofed.buf
	--probe.buf = self.mac_dst..self.mac_src..self.ether_type..self.buf
	--ToTransmit = probe.build_ether_frame(dst_mac , src_mac, string.char(0x86, 0xdd)  ,Spoofed.buf)
	--Spoofed.
	

	--dnet:ip_send(Spoofed.buf)
	dnet:ethernet_send(dst_mac .. src_mac .. string.char(0x86, 0xdd)  .. Spoofed.buf)
	
	--En esta parte debemos capturar  paquetes que se adecueen a nuestro mensaje 
	-- En esencia IPv6 src y que sean de DHCPV (los puertos UDP) deben ser suficiente
	-- para capturar el mensaje correcto. De ahi, desmentalarlo hasta quedarnos exclusivamente
	-- con lo datos que trae el UDP y buscar que posea un mensaje de oferta  (otros mensajes 
	-- pueden avisar de error o que no existe la sub/red, por eso debemos estar seguros 
	-- que sea una oferta de direccion.
	-- Y CERRAR pcap. (No olvidar si encontramos esto, agregamos ipv6src a la tabla tSalidas
	--  con su prefijo )no olvidar que esta tecnica no es exacta con esto(.
	
	-- Finally we close everything we already openeed
	dnet:ip_close()
	dnet:ethernet_close()
	
	return tSalida
end



--- 
-- There are two way the user provided subnets:
-- 1) X:X:X:X::/YY 2) {X:X:X:X::/YY, B, T} 
-- The first is very simple, the user already made all the work. 
-- The second however we need to sub-netting (YY+B) and calculate
-- the first T subnets from the new prefix.
-- @param 	Subnet	String/Table of subnets  X:X:X:X::/YY | {X:X:X:X::/YY, B, T} 
-- @return 	Table	Table of subnets X:X:X:X::/(YY+B)
local Extaer_Subredes = function(Subnet) 

  local Auxiliar = {}
  local  Contador, Valor, Aux
  local Net, Bits, Total, Dirre, Prefijo, NewPrefix, Binario, NewNet, mensaje
    
    if type(Subnet) == "table" then  --  {X:X:X:X::/YY, B, T}  ??
	
	    Net, Bits, Total = Subnet[1] , Subnet[2], Subnet[3]
	    Dirre, Prefijo = itsismx.Extract_IPv6_Add_Prefix(Net) 
	    NewPrefix = Prefijo + Bits
	    
	    Binario, mensaje = ipOps.ip_to_bin(Dirre)
	    
	    if Binario ~= nil then  -- We  proceed to save the entry to the list. 
		for Contador = 1, Total do 
		  Valor = stdnse.tobinary(Contador) -- There is a very low risk of overflow with this tactic...
		  while #Valor < tonumber(Bits) do Valor = "0" .. Valor end
		  
		  NewNet = Binario:sub(1,Prefijo) .. Valor .. Binario:sub(NewPrefix+1 , 128)
		  NewNet = ipOps.bin_to_ip(NewNet)
		  table.insert(Auxiliar, NewNet .. "/" .. NewPrefix)
		  --print("\t Will be added: " .. NewNet .. "/" .. NewPrefix)
		end 
	    
	    else	   -- Error, so we escape this entry 
		  tdnse.print_debug(3, SCRIPT_NAME  .. "\t\t The next provided subnet has wrong syntax: "  .. 
			Subnet ..   mensaje)  
	    end
	  
	  else 
		--print("\t\t Will be added: " .. Subnet)
	       table.insert(Auxiliar, Subnet) -- X:X:X:X::/YY
	  end
       
  return Auxiliar
end


---
-- Will retrieve two posible lists and return on single table.
-- The table will have the total subnet to use for spoofing.
local Listado_Subredes = function ()
    local TotalNets, Aux = {} , {}
    local Subredes = stdnse.get_script_args( "itsismx-dhcpv6.subnets" )
    --local NetworkRanges =  stdnse.get_script_args( "itsismx-dhcpv6.NetRange" )
   -- print("Total de entradas del argumento: " .. #Subredes)
    
    
    local index, campo, Subnets
    local interface_name 
    if Subredes ~= nil then
	if type(Subredes) ==  "table" then
	--  print("Es una tabla... DAH!")
	    for index, campo in ipairs(Subredes) do 
	      Aux = Extaer_Subredes(campo)
	      for _, Subnets in ipairs(Aux) do table.insert(TotalNets,Subnets ) end
	      
	    end
	else
	    Aux = Extaer_Subredes(Subredes)
	    for _, Subnets in ipairs(Aux) do table.insert(TotalNets,Subnets ) end
	    
	end
      
    else -- We need  provided at least one valid sub-net (Future works will 
	 -- let use the current interface IPv6 subnet (48 bits) 
	
	stdnse.print_debug(1, SCRIPT_NAME  .. " ERROR: Need to provided at least one " .. 
			" single subnet to test. Use the argument itsismx-dhcpv6.subnets "  )
	
    end

    
    return TotalNets
end
---
-- This run only as pre-scanning phase.
action = function()

	
	--Vars for created the final report
	
	local tOutput = stdnse.output_table()
	local bExito = false
	local tSalida =  { Subnets={}, Error=""}
	local microseconds = stdnse.get_script_args( "itsismx-dhcpv6.utime" )
	
	if microseconds == nil then
	    microseconds = 200
	else 
	    microseconds = tonumber( microseconds ) 
	end  
	
	tOutput.Subnets = {}  
	--print("HEY!")
	itsismx.Registro_Global_Inicializar("dhcpv6") -- We prepare our work!
	
	local Mensaje, Host, Error, Relay
	local UserSubnets, Index, Subnet
	
	--The mechanism is very simple, we retrieve the list provided by the user
	--then begin to generate the messages for each one of those.
	UserSubnets = Listado_Subredes()
	
	for Index, Subnet in ipairs(UserSubnets) do 
	    math.randomseed ( nmap.clock_ms() )
	    Mensaje, Host, Error	= Spoof_Host_Solicit() -- Each subnet a different host
	    
	    -- NOTE:  We can spoof the message, however, the source need to exist before hand or we are going to
	    -- have problems due Neighbor Discover Protocol.
	    
	    local iface, err = nmap.get_interface_info("wlan0")
	    -- local ifacekey, ifacedata
	    -- for ifacekey, ifacedata in pairs(iface) do print(ifacekey, ifacedata) end 
	    print(iface.address)

	    
	    Transmision_Recepcion( Host.LinkAdd, "FF02::1:2",  546,547, Mensaje )
	    --print ("SOCICIT Message ( " .. #Mensaje/2 .. " octetos): " .. Mensaje )
	    
	    --Relay = Spoof_Relay_Forwarder ( Host["LinkAdd"] , Mensaje , Subnet )
	    --print ("Relay Message ( " .. #Relay/2 .. " octetos): " .. Relay )
	    
	    -- This one will receive all the confirmed elements
	   --tSalida = Transmision_Recepcion( Host.LinkAdd, "FF02::1:2",  546,547, Relay )
	   
	   --Before we pass to the next sub/net candidate we must wait a little time
	   -- Normally Nmap will love to create multithreadings, however WE MUST 
	   -- be careful and not produce to manny DHCPv6 requests at same time
	   -- so, we need truly to kill time.
	   itsismx.waitUtime( math.random(microseconds) )
	
	end
	

	

	
	
	return stdnse.format_output(bExito, tOutput);	
	--return  tOutput
	
end

