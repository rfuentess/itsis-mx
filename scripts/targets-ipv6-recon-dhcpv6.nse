local bin = require "bin"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local itsismx = require "targets-ipv6-recon"
local ipOps = require "ipOps"

description = [[
  The objective is works as "fake" relay agent for DHCPv6. We are going to
  generate a "valid" request for host, but we are going to spoofing the
  Sub-network. The server will send us a valid option or nothing (if the
  subnet is wrong or if there is ACL or IPsec).

  The objective is confirm if a subset of sub-networks exist at all. Will
  generate one single relay-forwarder message (RFC 3315 20.1.2 p. 59) with a
  good HOP_COUNT_LIMIT (Spoofed) and a host request-message (Spoofed with 
  random DUID) and we are going to wait for a Relay-reply message (20.3 p.60).

  Limit: ACL on the server, ACL on the router, IPsec between relays agent and
  server can kill this technique. However almost all the RFC 3315 is more
  cautious with host trying to poisoning the DUID's DB than this aproach. 
]]


---
-- @usage
-- nmap -6 -e eth0 -v --script targets-ipv6-recon-dhcpv6 --script-args targets-ipv6-recon-dhcpv6.subnets=2001:db8:c0ca:6006::/64
--
-- @output
-- NSE: targets-ipv6-recon-dhcpv6.Solicit:  New SOLICIT Message. ID: 09bec2
-- NSE: targets-ipv6-recon-dhcpv6.Solicit:  Client ID: 0001000e000100011a07eb1a24B6FDe46629
-- NSE: targets-ipv6-recon-dhcpv6.Solicit:  IA-NA :  0003000c0000000f0000000000000000
-- NSE: targets-ipv6-recon-dhcpv6.Solicit:  Time: 000800020000
-- NSE: targets-ipv6-recon-dhcpv6.Solicit:  (G)Host - Link-Address: FE8000000000000026B6FDFFFEe46629
-- type of request: temporary
-- DUID: 000100011a07eb1a24B6FDe46629
-- IAID: 0000000f
-- NSE: targets-ipv6-recon-dhcpv6.prerule
--     Relay Forward:  msg_type: 0C
--     hopcount: 0C
--     linkAdd: 20010db8c0ca6006ffffffffffffffff
--     peerAdd: FE8000000000000026B6FDFFFEe46629
--     Options: 0009002c0109bec20001000e000100011a07eb1a24B6FDe466290003000c0000000f0000000000000000000800020000
-- NSE: Client ID Option length: 14 bytes
-- NSE: Server ID Option length: 14 bytes
-- NSE:  The subnet 2001:db8:c0ca:6006::/64 is Online
-- NSE: targets-ipv6-recon-dhcpv6 Were added 4 subnets to scan!

-- @args targets-ipv6-recon-dhcpv6.subnets  It's table/single IPv6 subnetworks 
--                   to test if exist. We can have two types of entries: 
--                   Single subnet ( X:X:X:X::/YY ), or
--                   range of subnets to calculate (X:X:X:X::/YY , Bits, Total)
--                   where B are the bits used for subnetting and Total amount
--                   of subnets to search. Be sure of that 2^Bits >= Total
                   
--                  Ex. 2001:db8:c0ca::/48 or 
--                  { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } or
--                  { {2001:db8:c0ca::/48, 16, 23} , 2001:db8:c0ca::/48} )
--                  NOTE: If one or more sub-net are discovered as valid will
--                  be added to a special registry for all the other scripts
--                  (words, slaac,map4to6, mac-prefixes) to be used.
--                   

-- @args targets-ipv6-recon-dhcpv6.TimeToBeg  A number, 16 bits expressed in
--                hundredths of a second. When clients are sending solicits,  
--                they indicate how much time had spent trying to get a 
--                address, this make some server and relay agents give 
--                preference to solicits with higher Time.
--                

--@args targets-ipv6-recon-dhcpv6.Company    A String of 6 hexadecimal
--                characters. By default the script will generate random hosts
--                from a DELL OUI (24B6FD). With this argument the user can 
--                provides a specific OUI. However, the last 24 bits will still
--                be generate randomly.

--@args targets-ipv6-recon-dhcpv6.Option_Request  If given a Option request
--                will be added to the host request.

--@args targets-ipv6-recon-dhcpv6.utime     Number. Between each try to get a
--                subnet we wait random time measured on microseconds. 
--                By default we wait no more than 200 microseconds.   
--                The user can provided a another time (Minimun 1).

-- Version 1.2
--  Update 05/05/2014  - V1.2 Minor corrections and standardization.
--  Update 28/09/2013  - V1.0 First functional IA-NA mechanism finished.
--  Update 19/09/2013  - V0.7 Finished transmission
--  Update 04/06/2013  - V0.5 Produce the messages to spoof.
--  Created 27/05/2013 - v0.1 Created by Raul Fuentes <ra.fuentess.sam+nmap@gmail.com>
--

author = "Raul Armando Fuentes Samaniego"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {
  "broadcast",
  "discovery",
  "safe",
}

---
-- Will generate a random DUID with a valid format (RFC3315 9.2 p.20).
--
-- This is going to be: link-layer address plus time [DUID-LLT] 
-- @return String    A valid DUID-LLT
-- @return String    A Link-Address scope
function Generar_DUID ()

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
  -- we can find more info on:
  -- http://www.iana.org/assignments/arp-parameters/arp-parameters.xml
  -- By default will be "Ethernet" (0x0001)

  local Hardware = "0001"
  local stime = nmap.clock()
  local LinkAdd, nRand, Mac
  -- Note: LinkAdd will generate a IPv6 Address and Mac will generate a MAC
  --       address both will be from the same source (EUI-64).

  -- We work first the time Variable. We need to pass to a valid represented 
  -- in seconds since midnight (UTC) January 1, 2000 modulo 2^32
  -- Probably this is a EPOCH Unix: 01/01/1970 ...
  if stime > 946684800 then
    -- Ok, maybe on 17 years this is going to be fatal error
    -- We need to remove 30 years of the time from that lecture  
    -- or give a arbitrary value.
    stime = stime - 946684800
  end

  -- We need to convert the number to bytes ( 4 bytes)
  stime = stdnse.tohex(stime)
  while #stime < 8 do
    stime = "0" .. stime
  end

  --  we are using a typical DELL PC (By default)
  -- Future work can give a custom full host  here. (Don' forget FE80::/10 )
  local Ghost = stdnse.get_script_args "targets-ipv6-recon-dhcpv6.Company"

  if Ghost ~= nil then
    -- We need to be sure the OUI be a valid
    if itsismx.Is_Valid_OUI(Ghost) then
      LinkAdd = "FE80000000000000" .. Ghost .. "FFFE"
      Mac = Ghost
    else
      LinkAdd = "FE80000000000000" .. "24B6FD" .. "FFFE"
      Mac = "24B6FD"
      stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
                            "DUID-LLT ERROR " .. " was provided a" ..
                            " INVALID OUI value and was ignored.")
    end
  else
    Mac = "24B6FD"
    LinkAdd = "FE80000000000000" .. "24B6FD" .. "FFFE"
  end

  -- The last 24 bits will be random (just avoid be so hussy)
  --math.randomseed ( nmap.clock_ms() )
  nRand = itsismx.DecToHex(math.random(16777216)) -- 2^24
  while #nRand < 6 do
    nRand = "0" .. nRand
  end

  LinkAdd = LinkAdd .. nRand
  Mac = Mac .. nRand

  -- Finally we put everything together LinkAdd
  DUID = DUID .. Hardware .. stime .. Mac

  stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. "DUID-LLT:" .. 
                       " New DUID: " .. DUID)

  return DUID, LinkAdd
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
-- Will generate a Relay Message Option
-- RFC 3315 22.10. p. 70.
-- @param   String    The Spoofed message to add.
-- @return  String    Hexadecimal bytes representing this DHCP option.
local Generar_Option_Relay = function (Mensaje)

  local Option_Code, Option_Len = "0009"
  Option_Len = itsismx.DecToHex(#Mensaje / 2)
  while #Option_Len < 4 do
    Option_Len = "0" .. Option_Len
  end

  return Option_Code .. Option_Len .. Mensaje
end

---
-- Will generate a Client Identifier Option
-- RFC 3315 22.2. Client Identifier Option p. 70
--
-- NOTE: The Client-ID length need to be fixed for Verify_Relay_Reply()
-- to work OK.
-- @see Verify_Relay_Reply
-- @return  String    Hexadecimal bytes representing this DHCP option.
-- @return  String    Hexadecimal bytes representing the DUID.
local Generar_Option_ClientID = function ()
  local ClientID

  -- Option-Len is the DUID length in octets. Our DUID have 24 bits
  -- which are 6 hexadecimal and those are 3 octets.
  local Option_Code, Option_Len, DUID, LinkAdd = "0001", "0000", Generar_DUID()

  -- For now, with this info we simply return it (with the DUID)
  -- (In future we can make a more complex system trying to imitate
  -- other type of nodes device with different type of DUID)
  Option_Len = itsismx.DecToHex(#DUID / 2)
  while #Option_Len < 4 do
    Option_Len = "0" .. Option_Len
  end

  stdnse.print_verbose(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
              ".Solicit.Elapsed Time: " .. " \n\t --[[Option]]-Code: " ..
              Option_Code .. " \n\t Option Length: " .. Option_Len ..
              " \n\t DUID: " .. DUID)

  ClientID = Option_Code .. Option_Len .. DUID

  return ClientID, DUID, LinkAdd
end


---
-- Will generate a Identity Address Option RFC 3315 22.6 p. 75
-- @return  String     Hexadecimal bytes representing this DHCP option.
local Generar_IA_Option = function ()

  --  The format of the IA Address option is:
  --
  --      0                   1                   2                   3
  --      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  --     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --     |          OPTION_IAADDR        |          option-len           |
  --     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --     |                                                               |
  --     |                         IPv6 address                          |
  --     |                                                               |
  --     |                                                               |
  --     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --     |                      preferred-lifetime                       |
  --     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --     |                        valid-lifetime                         |
  --     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --     .                                                               .
  --     .                        IAaddr-options                         .
  --     .                                                               .
  --     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  local Op_IAADDR, option_len, Ipv6Add, preferred, valid, options
  Op_IAADDR = "0005"

  --values in the preferred and valid lifetime fields indicate the client's
  -- preference for those parameters. The client may send 0 if it has no
  -- preference for the preferred and valid lifetimes.
  preferred, valid = "00000000", "00000000"

  -- For now... static but should be dynamic... if is not static
  -- we risk to been discovered (Two interfaces can have same link/address
  -- as long they are on different subnets)
  --Ipv6Add = "FE8000000000000062eb69fffeaf2b83"
  Ipv6Add = "20010db8c0ca000000000000c0a8010b"

  --"An IA Address option may appear only in an IA_NA option or an IA_TA
  -- option". For our project mean: NO OPTIONS.
  options = ""
  option_len = itsismx.DecToHex(24 + #options / 2)
  while #option_len < 4 do
    option_len = "0" .. option_len
  end

  return Op_IAADDR .. option_len .. Ipv6Add .. preferred .. valid .. options
end

---
-- Will generate a IA_TA Option
-- RFC 3315 22.5. Client Identifier Option p. 74
-- @return  String    Hexadecimal bytes representing this DHCP option.
-- @return  String    Hexadecimal bytes representing the IAID.
local Generar_Option_IA_TA = function ()
  local IA_TA
  local Option_Code, Option_Len, IAID, Options = "0004", 4, 0, ""

  -- This is going to be very important for the binding (Well at least
  -- for a real client). With the IAID for a temporary Address and with DUID
  -- The IAID  ( RFC 3315 p. 9)

  -- RFC 3315 p. 11
  --  An identifier for an IA, chosen by the client. Each IA has an IAID, which
  --  is chosen to be unique among all IAIDs for IAs belonging to that client.

  -- The RFC say "Client generate IAID" and the IAID is 4 octets...
  --IAID = itsismx.DecToHex( math.random( 4294967296 ) ) -- 2^32
  -- NOTE: Original random implementation didn't work...
  IAID = "f" --Wide-dhcpv6-client uses this and seem to work...
  while #IAID < 8 do
    IAID = "0" .. IAID
  end

  -- The IA_TA Options... is variable length and the RFC is not clear
  -- As we are trying to be a "first time node connecting to the network"
  -- I'm assume we need the Satus Code NoBinding ( 0x02 ). Or maybe none ?
  -- P. 76 RFC 3314 22.6
  -- Sep13: After seeing the work of current implemented servers seem 
  -- its better left it on blank.
  Options = Generar_IA_Option()
  --Options = ""

  Option_Len = itsismx.DecToHex(4 + #Options / 2)
  while #Option_Len < 4 do
    Option_Len = "0" .. Option_Len
  end
  IA_TA = Option_Code .. Option_Len .. IAID .. Options

  stdnse.print_verbose(4, SCRIPT_NAME .. ".Solicit.Elapsed Time: " ..
        " \n\t Option-Code: " .. Option_Len .. "\n\t Option Length: " ..
        Option_Len .. " \n\t IAID: " .. #IAID .. " \n\t Options: " .. Options)

  return IA_TA, IAID
end

---
-- Will generate a IA_NA Option
-- RFC 3315 22.3. Client Identifier Option p. 74
-- @return  String     Hexadecimal bytes representing this DHCP option.
-- @return  String    Hexadecimal bytes representing the IAID.
local Generar_Option_IA_NA = function ()
  local IA_NA, Option_Code, Option_Len, IAID, T1, T2
  local IA_NA_Options

  --    The format of the IA_NA option is:
  --     0                   1                   2                   3
  --     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --    |          OPTION_IA_NA         |          option-len           |
  --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --    |                        IAID (4 octets)                        |
  --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --    |                              T1                               |
  --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --    |                              T2                               |
  --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --    |                                                               |
  --    .                         IA_NA-options                         .
  --    .                                                               .
  --    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  -- Read the Generar_Option_IA_TA comments
  -- RFC 3315 p. 74:
  --  In a message sent by a client to a server, values in the T1 and T2
  --  fields indicate the client's preference for those parameters. The
  --  client sets T1 and T2 to 0 if it has no preference for those values.

  Option_Code, T1, T2 = "0003", "00000000", "00000000"

  -- The RFC say "Client generate IAID" and the IAID is 4 octets...
  --IAID = itsismx.DecToHex( math.random( 4294967296 ) ) -- 2^32
  IAID = "f" --Seem wide-dhcpv6-server need this field to be F
  while #IAID < 8 do
    IAID = "0" .. IAID
  end

  -- Though those are dynamic seem to be totally optionals.
  IA_NA_Options = ""

  Option_Len = itsismx.DecToHex(12 + #IA_NA_Options / 2)
  while #Option_Len < 4 do
    Option_Len = "0" .. Option_Len
  end

  IA_NA = Option_Code .. Option_Len .. IAID .. T1 .. T2 .. IA_NA_Options
  return IA_NA, IAID
end

---
-- Will generate a Elapsed Time Option
-- RFC 3315 22.9. Elapsed Time Option p. 78
-- @return  String     Hexadecimal bytes representing this DHCP option.
local Generar_Option_Elapsed_Time = function ()

  local option_code, option_len, elapsed = "0008", "0002", "0000"
  -- TIP: elapsed-time field is set to 0 in the first message in the message
  -- TIP: unsigned, 16 bit integer

  -- Generate bigger "time" fields for seem to be "begging" for a quick answer.
 local TimetoBeg = stdnse.get_script_args "targets-ipv6-recon-dhcpv6.TimeToBeg"

  if TimetoBeg ~= nil then
    elapsed = itsismx.DecToHex(TimetoBeg)
    while #elapsed < 4 do
      elapsed = "0" .. elapsed
    end
  end

  stdnse.print_verbose(4, SCRIPT_NAME .. ".Solicit.Elapsed Time: " ..
              "\n\t Option-Code: " .. option_code .. "\n\t Option Lenght: " ..
              option_len .. " \n\t Time elapsed: " .. elapsed)

  return option_code .. option_len .. elapsed
end

---
-- Will generate a Option Request Option
-- RFC 3315 22.7. Elapsed Time Option p. 78
--
-- Though optional on DHCP all the clients request something more than,
-- we try to no trigger alarm with a strange empty request.
-- @return  String     Hexadecimal bytes representing this DHCP option.
local Generar_Option_Request = function ()

  --      0                   1                   2                   3
  --       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  --      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --      |           OPTION_ORO          |           option-len          |
  --      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --      |    requested-option-code-1    |    requested-option-code-2    |
  --      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  --      |                              ...                              |
  --      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  -- This message is generated because seem be needed for working.
  --option-len = 2 * number of requested options.
  local Option_Oro, Option_Len, req_option_code1 = "0006", "0002"

  -- The RFC is not clear which are our options, however, there is a known one
  -- for ask the domain name which is 24 (0x0018)
  req_option_code1 = "0018"
  -- Future work will give the options to add more things
  --   (Maybe from a Byte Flag)
  return Option_Oro .. Option_Len .. req_option_code1
end

---
-- Will return a  RANDOM host Solicit Message based on chapter 17.1.1 Creation
-- of solicit Messages p.31.
--
-- We don't care too much on the node to create.
-- @return    String    A string representing HEXADECIMAL data 
--                      (Ready for pack on raw bytes)
-- @return    Table     Tuple <DUID, Type, IAID, LinkAdd>
-- @return    String    Nil if there is no error, otherwise return an
--                      error message.
local Spoof_Host_Solicit = function ()

  --     From RFC 3315  section 6. Client/Server Message Formats   p. 16
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
  --  transaction-id - Random value seem to be (We need to remember IT!)
  --  Options:       - We are force to add (At least) Client Identifier Option,
  --                   IA_TA option and Elapsed Time option

  -- TIP: Our fake host is going to use "temporary address"
  --      so, we only focus on IA_TA-

  -- TIP: RFC p. 32 say we need to wait random time, however this is a Spoofed
  --      request after the node is already configured and we ignore it.

  local Solicit, Error = "01", nil
  local TransactionID, DUID, IAID, LinkAdd = 0
  local ClientID, IA_TA, Time, Option_Request
  local IA_NA
  local Host = {
    "DUID",
    "Type",
    "IAID",
    "LinkAdd",
  }

  -- RFC 3315, 15.1 P. 27
  --   The "transaction-id" field holds a value used by clients and servers
  --   to synchronize server responses to client messages.
  -- RFC 3315, 17.1.1 P. 31
  --   The client sets the "msg-type" field to SOLICIT. The client
  --   generates a transaction ID and inserts this value in the
  --   "transaction-id" field.
  -- Tip: The transaction-ID SHOULD be a strong random value, however this 
  --      is a spoofing message, we are going to be very simple (but random
  --      for help us with multiple subnets. )

  -- NOTE: For now, Na_or_Ta has been disabled until we implemented a truly TA.
  --local Na_or_Ta = stdnse.get_script_args( "targets-ipv6-recon-dhcpv6.IA_NA" )
  local Na_or_Ta = true


local bOReq = stdnse.get_script_args "targets-ipv6-recon-dhcpv6.Option_Request"

  -- Counter or Random ? That is the question...
  TransactionID = itsismx.DecToHex(math.random(16777216)) -- 2^24
  while #TransactionID < 6 do
    TransactionID = "0" .. TransactionID
  end

  ClientID, DUID, LinkAdd = Generar_Option_ClientID()

  -- IA-TA & IA-NA are our option
  -- We can send a IA-NA (Non-temporary Address) or IA-TA (Temporary Address)
  -- by default will be IA-TA
  if Na_or_Ta == nil then
    IA_TA, IAID = Generar_Option_IA_TA()
  else
    IA_NA, IAID = Generar_Option_IA_NA()
  end

  Time = Generar_Option_Elapsed_Time()

  -- The Option Request field is optional, however seem to be that all the
  -- clients use it. Yet some servers (Wide-Server, Windows Server 2008/2012)
  -- don't need it.
  if bOReq ~= nil then
    Option_Request = Generar_Option_Request()
  end

  stdnse.print_verbose(3, SCRIPT_NAME .. ".Solicit: " ..
                        " New SOLICIT Message. ID: " .. TransactionID)
  stdnse.print_verbose(3, SCRIPT_NAME .. ".Solicit: " ..
                        " Client ID: " .. ClientID)

  if Na_or_Ta == nil then
    stdnse.print_verbose(3, SCRIPT_NAME .. ".Solicit: IA-TA : " .. IA_TA)

  else
    stdnse.print_verbose(3, SCRIPT_NAME .. ".Solicit: IA-NA : " .. IA_NA)
  end

  stdnse.print_verbose(3, SCRIPT_NAME .. ".Solicit: Time: " .. Time)

  if bOReq ~= nil then
    stdnse.print_verbose(3, SCRIPT_NAME .. ".Solicit: Option Request: " ..
                         Option_Request)
  end

  -- Now we update the Tuple for this host
  Host.DUID = DUID
  Host.Type = "temporary" -- For this version we're using only IA_TA
  Host.IAID = IAID
  Host.LinkAdd = LinkAdd

  stdnse.print_verbose(2, SCRIPT_NAME .. ".Solicit: " ..
             " (G)Host - Link-Address: " .. Host.LinkAdd ..
             "\n type of request: " .. Host.Type .. "\n DUID: " ..
             Host.DUID .. "\n IAID: " .. Host.IAID)


  -- A this point we should have a valid SOLICIT Message... 
  -- we are going to have blind faith
  if Na_or_Ta == nil then
    Solicit = Solicit .. TransactionID .. ClientID .. IA_TA .. Time
  else
    Solicit = Solicit .. TransactionID .. ClientID .. IA_NA .. Time
  end

  if bOReq ~= nil then
    Solicit = Solicit .. Option_Request
  end

  return Solicit, Host, Error
end

---
-- Will return a Relay-Forward message based on the arguments given.
-- @param   String  A string representing IPv6 Source of the spoofed host.
-- @param   String  A string representing HEXADECIMAL data (SOLICIT message).
-- @param   String  IPv6 Subnet which we want to confirm to exist.
-- @return  String  A string representing HEXADECIMAL data (the packet on 
--                  raw bytes ready to be transmitted).
-- @return  String  If there is a error will return the reason, otherwise nil
local Spoof_Relay_Forwarder = function (Source, SOLICIT, Subnet)

  -- P. 59, 20.1.1
  -- This message will be "relay forwarder" from a spoofed agent to another
  -- REAL relay agent ( hop-count must be 2-3 or user value)

  --     RFC 3315 7. Relay Agent/Server Message Formats P. 17
  --   There are two relay agent messages, which share the following format:
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

  msg_type = "0C" -- msg-type is 12 (0x0C)
  hopcount = "00" -- Though this option could be other values some server don't
  -- accept a fake number

  peerAdd = Source
  Options = Generar_Option_Relay(SOLICIT)

  if Subnet == nil then
    -- empty or nil is bad
    linkAdd = "20010db8c0ca00000000000000000001"
  elseif #Subnet == 0 then
    linkAdd = "20010db8c0ca00000000000000000001"
  else
    --We assume is IPv6 Address and we need to convert to Hexadecimal value
    Address, Prefix = itsismx.Extract_IPv6_Add_Prefix(Subnet)
    --We use the last IPv6 addresses because is always valid
    sUnicast, sError = ipOps.get_last_ip(Address, Prefix) 

    if sUnicast == nil then
      stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
                "\n\t Relay Forward: " .. " The subnet provided (" .. 
                stdnse.string_or_blank(Subnet) .. 
                ") was bad formed and throw the next error: " .. sError)
      return "", sError
    else
      -- WE need to expand the IPv6 address to use all the hexadecimals
      linkAdd = itsismx.Expand_Bytes_IPv6_Address(sUnicast)
    end
  end

  stdnse.print_verbose(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
              "\n\t Relay Forward: " .. " msg_type: " .. msg_type .. 
              "\n\t hopcount: " .. msg_type .. "\n\t linkAdd: " .. linkAdd ..
              "\n\t peerAdd: " .. peerAdd .. "\n\t Options: " .. Options)

  Relay = msg_type .. hopcount .. linkAdd .. peerAdd .. Options
  return Relay, nil
end


---
-- We are going to verify our answer from the server.
--
-- Not all the answer mean we got a true positive answer so, we need
-- to retrieve the IA-NA or IA-TA  IPv6 address suggested by the server.
-- @param   String     The Peer Address or better say OUR fake Relay Agent
--                     address.
-- @param   Bytes      The full Relay-Reply message from our server.
-- @param   String     X:X:X:X::/YY subnet we want to confirm.
-- @return  Boolean    The subnet and the answer match (TRUE) otherwise False.
-- @return  String     Nil if the boolean is true, otherwise give hints of the
--                     error.
local Verify_Relay_Reply = function (PeerAddress, Relay_Reply, Subnet)

  --The message we got have the next structure:
  --    msg-type:       RELAY-REPLY (0x0d)
  --    hop-count:      0x00
  --    link-address:   0 ( 128 bits)
  --    peer-address:   A (128 bits)
  --    Relay Message
  --        Option-Code     (0x0009)
  --        Option-Lenght    (16 bits)
  --        Relay-Message    (Variable... but should be Adverstiment Message)

  -- Our TCPdump filter has all the thing is important to us.  
  -- Our Relay-message has only one Message option left so the first extension
  --  is know to us. 8+8+128+128+16+16=304/8
  -- So, we begin at line 305 and we are going to have this message:

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

  --    msg-type: 0x02
  --    transaction-id: (16 bits)
  --    Options... Can BE VARIABLE

  local Longitud, Adv_Msg = #Relay_Reply - (49 + 38) + 1, ""
  local hex_pos, hex_dhcp_data, Campos
  local Candidata, bBool, sBool

  hex_pos, hex_dhcp_data = bin.unpack("H" .. tostring(Longitud), Relay_Reply,
                                        49 + 38)

  -- Should be a valid one but we are going to be sure.
  if hex_dhcp_data:sub(1, 2) ~= "02" then
    return false, "It's not a Solicit message"
  end
  -- Now we have two possible scenarios:
  -- IA-TA with the next structure:
  --    Client ID Option (Our target is here)
  --    Server ID Option
  --    Plus any other options (WE don't care)
  -- IA-NA with the next structure
  --    Client ID Option
  --    Server ID Option
  --    Identity Association for Non-temporary Address (Our target is here)
  --    Plus any other options (WE don't care)

  -- The Client ID OPtion is variable...

  local Na_or_Ta = stdnse.get_script_args "targets-ipv6-recon-dhcpv6.IA_NA"
  Na_or_Ta = true

  local offset = 0

  if Na_or_Ta then
    -- IA-NA

    offset = 7 + 2 + 4
    Campos = hex_dhcp_data:sub(offset) -- We extract until "Option-len"

    Longitud = Campos:sub(1, 4)

    stdnse.print_verbose(3, "Client ID Option length: " ..
                         tonumber(Longitud, 16) .. " bytes")

    -- Now the Server ID Option
    offset = 7 + 2 + 4 + 4 + tonumber(Longitud, 16) * 2 + 4
    Campos = hex_dhcp_data:sub(offset) -- We extract until "Option-len"
    Longitud = Campos:sub(1, 4)

    stdnse.print_verbose(3, "Server ID Option length: " .. 
                         tonumber(Longitud, 16) .. " bytes")

    -- Identity Association for Non-temporary Address
    offset = offset + tonumber(Longitud, 16) * 2 + 4
    Campos = hex_dhcp_data:sub(offset)

    -- This option have the follow parts:
    --Option (0x0003)
    --Lenght (16 bits )
    --IAID (16 bits)
    --T1 (32 bits)
    --T2 (32 bits)
    -- IP address
    --        Option ( 0x0005 )
    --        Lenght ( 16 bits ) PERO tiene que ser 24
    --        Address (128 bits) OUR TARGET!!
    --        pREFERERD TIME (32 bits)
    --        vALID Time (32 bits)
    offset = offset + 4 + 4 + 4 + 8 + 8 + 4
    Campos = hex_dhcp_data:sub(offset)

    if Campos:sub(1, 4) ~= "0005" then
      return false, "We are waiting for a IA-NA but got another type of" .. 
	            " answer: " .. Campos:sub(1, 4)
    end

    offset = offset + 4 + 4
    Campos = hex_dhcp_data:sub(offset)
    Candidata = Campos:sub(1, 32)

    return true, Campos:sub(1, 32)

  else
    -- TODO: Need to add those lines when Find a good document talking about
    -- the format as the RFC is unclear how to address it.
    stdnse.print_verbose(1, "IA-TA is not yet implemented.!")
  end

  bBool, sBool = ipOps.ip_in_range(Candidata, Subnet)
  if bBool then
    return bBool, nil
  else
    return bBool, sBool
  end
end

---
-- Will create a spoofed message for transmit (any message) and immediately
-- will hear for a answer (to be selected by a filter) and will return it.
--
-- You may want to use -d1 to catch any error.
-- @param   String    Source IPv6 Address.
-- @param   String    Destiny IPv6 Address.
-- @param   String    Source Port Address.
-- @param   String    Destiny Port Address.
-- @param   String    String representing bytes (The message to send).
-- @param   String    String representing the Interface Name.
-- @param   String    X:X:X:X::/YY Subnet (String format).
-- @return  Boolean   True if we got a positive answer, false otherwise
local Transmision_Recepcion = function (IPv6src, IPv6dst, Prtsrc, Prtdst,
                                         Mensaje, Interface, Subnet)

  local Bytes
  -- those extra bits are for being overwritten
  Bytes = bin.pack("H", "0000000000000000" .. Mensaje)

  local Interfaz, err = nmap.get_interface_info(Interface)
  local Bool, Tcpdumpfilter

  local dnet = nmap.new_dnet()
  local pcap = nmap.new_socket()

  -- This is for multithreading.. (not implemented yet)
  -- local condvar = nmap.condvar(results)

  local src_mac = packet.mactobin "00:D0:BB:00:7d:01" --(Spoofed) Cisco device
  -- NOTE: We need a Multicast MAC address, however 33:33:00:00:00:01 it's not
  --       valid (or better say, never worked for me)
  local dst_mac = packet.mactobin "33:33:00:01:00:02"

  local src_ip6 = bin.pack("H", itsismx.Expand_Bytes_IPv6_Address(IPv6src))
  local dst_ip6 = packet.ip6tobin(IPv6dst)

  -- We open all the elements we are going to need
  -- dnet:ip_open()
  dnet:ethernet_open(Interfaz.device)

  -- Before we begin to send packets is a good idea turn on the Pcap
  Tcpdumpfilter = "ip6 dst " .. IPv6src .. 
                  " and udp src port 547 and udp dst port 547"

  stdnse.print_verbose(5, "\t The DCPdump filter: \t" .. Tcpdumpfilter)
  pcap:pcap_open(Interfaz.device, 1500, true, Tcpdumpfilter)

  -- From zero...
  -- We need a UDP datagram, then a IP packet and finally a Ethernet Frame...
  -- UDP and IP are declared inside of the "Packet class" on packet.lua
  local Spoofed = packet.Packet:new()

  -- Ejem src, dst, nx_hdr, payload, h_limit, t_class, f_label
  -- IPv6 Packet with next Header as UDP, Hoplimit 3, and Traffic class
  -- and Flow label set to zero.
  -- payload ITS dangerous because will place all the data
  -- However this data NEED TO HAVE FIRST THE UDP header otherwise
  -- the data (message) will overwritten it...
  Spoofed:build_ipv6_packet(src_ip6, dst_ip6, 17, Bytes, 3, 0, 0)
  Bool = Spoofed:ip6_parse(false)

  --We work the UDP...
  Spoofed:udp_parse(false)

  Spoofed:udp_set_sport(Prtsrc)
  Spoofed:udp_set_dport(Prtdst)
  Spoofed:udp_set_length(#Bytes)
  Spoofed.ip_p = 17 -- Seem that udp_count_checksum() wasn't update for IPv6
  Spoofed:udp_count_checksum()

  -- TCP datagram Ready, now  IPv6 packet
  Spoofed:count_ipv6_pseudoheader_cksum()

  -- We already have everything, however, we can spoof the MAC address
  -- This part of packet.lua is CRAP we ignore the "class"
  -- and write the info directly to our Frame to send.
  local probe = packet.Frame:new()
  probe.mac_dst = dst_mac
  probe.mac_src = src_mac
  probe.ether_type = string.char(0x86, 0xdd)
  probe.buf = Spoofed.buf

  --dnet:ip_send(Spoofed.buf)
  dnet:ethernet_send(dst_mac .. src_mac .. string.char(0x86, 0xdd) ..
                      Spoofed.buf)

  -- HERE IS THE SECOND PART OF FUTURE WORK
  -- If we are trying to spoof nodes, we need to listen ND Neighbor 
  -- Solicitation for our spoofed node and then answer it with the 
  -- correct NDP Neighbor Advertisement (Or just send the second?).

  -- More info: http://nmap.org/nsedoc/lib/nmap.html#pcap_receive
  local status, plen, l2_data, l3_data, time, hex_pos, hex_l3_data
  status, plen, l2_data, l3_data, time = pcap:pcap_receive()


  if status == nil then
    -- No packet captured (Timeout)
    stdnse.print_verbose(3, " The subnet " .. Subnet ..
                         " seem not be available")
    Bool = false
  elseif status == true then
    -- We got a packet ... time to work with it
    -- On this point we got a packet with a length of 100-110 bytes
    -- OR 100 to 110 hexadecimal characters big-end
    Bool, err = Verify_Relay_Reply(src_ip6, l3_data, Subnet)

    if Bool == false then
      stdnse.print_verbose(1, " The subnet " .. Subnet ..
                            " got this error: " .. err)
    else
      stdnse.print_verbose(3, " The subnet " .. Subnet .. " is On-line")
    end

  end

  -- Finally we close everything we already opened
  pcap:pcap_close()
  dnet:ip_close()
  dnet:ethernet_close()

  return Bool
end

---
-- We extract the sub-networks provided by the users.
--
-- There are two way the user provided subnets:
-- 1) X:X:X:X::/YY 2) {X:X:X:X::/YY, B, T}
-- The first is very simple, the user already made all the work.
-- The second however we need to sub-netting (YY+B) and calculate
-- the first T subnets from the new prefix.
-- @param   Subnet  String/Table of subnets X:X:X:X::/YY | {X:X:X:X::/YY, B, T}
-- @return  Table   Table of subnets X:X:X:X::/(YY+B)
local Extaer_Subredes = function (Subnet)

  local Auxiliar = {}
  local Contador, Valor, Aux
  local Net, Bits, Total, Dirre, Prefijo, NewPrefix, Binario, NewNet, mensaje

  if type(Subnet) == "table" then
    --  {X:X:X:X::/YY, B, T} ??

    Net, Bits, Total = Subnet[1], Subnet[2], Subnet[3]
    Dirre, Prefijo = itsismx.Extract_IPv6_Add_Prefix(Net)
    NewPrefix = Prefijo + Bits

    Binario, mensaje = ipOps.ip_to_bin(Dirre)

    if Binario ~= nil then
      -- We proceed to save the entry to the list.
      for Contador = 1, Total do
        -- There is a very low risk of overflow with this tactic...
        Valor = stdnse.tobinary(Contador)
        while #Valor < tonumber(Bits) do
          Valor = "0" .. Valor
        end

        NewNet = Binario:sub(1, Prefijo) .. Valor ..
                             Binario:sub(NewPrefix + 1, 128)
        NewNet = ipOps.bin_to_ip(NewNet)
        table.insert(Auxiliar, NewNet .. "/" .. NewPrefix)
      end

    else
      -- Error, so we escape this entry
      stdnse.print_verbose(3, SCRIPT_NAME .. 
                   "\t\t The next provided subnet has wrong syntax: " ..
                   Subnet .. mensaje)
    end

  else
    table.insert(Auxiliar, Subnet) -- X:X:X:X::/YY
  end

  return Auxiliar
end


---
-- Will retrieve two possible lists and return on single table.
-- The table will have the total subnet to use for spoofing.
-- @return    Table  total subnets to sue for spoofing.
local Listado_Subredes = function ()
  local TotalNets, Aux = {}, {}
  local Subredes = stdnse.get_script_args "targets-ipv6-recon-dhcpv6.subnets"

  local index, campo, Subnets
  local interface_name
  if Subredes ~= nil then
    if type(Subredes) == "table" then

      for index, campo in ipairs(Subredes) do
        Aux = Extaer_Subredes(campo)
        for _, Subnets in ipairs(Aux) do
          table.insert(TotalNets, Subnets)
        end

      end
    else
      Aux = Extaer_Subredes(Subredes)
      for _, Subnets in ipairs(Aux) do
        table.insert(TotalNets, Subnets)
      end

    end

  else
    -- We need provided at least one valid sub-net (Future works will
    -- let use the current interface IPv6 subnet (48 bits)
    stdnse.print_verbose(1, SCRIPT_NAME .. " ERROR: Need to provided at" ..
                         " least one single subnet to test. Use the" ..
                         " argument targets-ipv6-recon-dhcpv6.subnets ")

  end

  return TotalNets
end

---
-- The script need to be working with IPv6.
function prerule ()
  if not (nmap.is_privileged()) then
    stdnse.print_verbose("%s with lack of privileges (and we need GNU/Linux).",
                          SCRIPT_NAME)
    return false
  end

  if not (nmap.address_family() == "inet6") then
    stdnse.print_verbose("%s Need to be executed for IPv6.", SCRIPT_NAME)
    return false
  end

  -- Need to have access to one ethernet port at least.
  --local iface, err = nmap.get_interface_info("eth0")
  if nmap.get_interface() == nil then
    stdnse.print_verbose("The NSE Script need to work with a Ethernet" ..
                         " Interface, Please use the argument -e <Interface>.")
    return false
  end

  local iface, err = nmap.get_interface_info(nmap.get_interface())

  if err ~= nil then
    stdnse.print_verbose(1, "dhcv6 can't be initialized due the next" .. 
                            " ERROR: " .. err)
    return false
  elseif iface.link ~= "ethernet" then
    stdnse.print_verbose(1, " The NSE Script need to work with a Ethernet" ..
                   "Interface, Please use the argument -e <Interface>" .. 
                   " to select it.")
    return false
  end

  return true
end

---
-- We send the spoofed DHCPv6 Relay message request.
function action ()
  --Vars for created the final report
  local tOutput = stdnse.output_table()
  local bExito, bRecorrido = false, false
  local tSalida = {
    Subnets = {},
    Error = "",
  }
  local microseconds = stdnse.get_script_args "targets-ipv6-recon-dhcpv6.utime"
  local bIPv6Address = stdnse.get_script_args "targets-ipv6-recon-dhcpv6.Spoofed_IPv6Address"
  local Spoofed_IPv6Address

  if microseconds == nil then
    microseconds = 200
  else
    microseconds = tonumber(microseconds)
  end

  tOutput.Subnets = {}
 -- itsismx.Registro_Global_Inicializar "dhcpv6" -- We prepare our work!
  itsismx.Registro_Global_Inicializar "PrefixesKnown"
  
  local Mensaje, Host, Error, Relay
  local UserSubnets, Index, Subnet

  --The mechanism is very simple, we retrieve the list provided by the user
  --then begin to generate the messages for each one of those.
  UserSubnets = Listado_Subredes()

  for Index, Subnet in ipairs(UserSubnets) do
    math.randomseed(nmap.clock_ms())
    Mensaje, Host, Error = Spoof_Host_Solicit() -- Each subnet a different host
    Relay = Spoof_Relay_Forwarder(Host["LinkAdd"], Mensaje, Subnet)

    -- NOTE: We can spoof the message, however, the source need to exist 
    -- beforehand or we are going to have problems due NDP.
    -- At least there is preventive work for spoofing (Which will be left
    -- for future work we need to use a REAL IPv6 source address).
    if Bool_IPv6Address == nil then
      local iface, err = nmap.get_interface_info(nmap.get_interface())

      -- This should be redudent due we already did this on the Pre-Rule
      if err ~= nil then
        tSalida.Error = err
        --   return stdnse.format_output(bExito, tOutput)
      else
        Spoofed_IPv6Address = iface.address
      end

    else
      -- Future work if we want to spoof a fake node.
      Spoofed_IPv6Address = Host.LinkAdd
    end

    -- This one will receive all the confirmed elements
    bRecorrido = Transmision_Recepcion(Spoofed_IPv6Address, "FF02::1:2",
                                       546, 547, Relay, nmap.get_interface(),
                                       Subnet)

    bExito = bExito or bRecorrido
    if bRecorrido then
      table.insert(tSalida.Subnets, Subnet)
    end

    --Before we pass to the next sub-net candidate we must wait a little time
    -- Normally Nmap will love to create multi-threadings, however WE MUST
    -- be careful and not produce to manny DHCPv6 requests at same time
    -- so, we need truly to kill time.
    itsismx.waitUtime(math.random(microseconds))

  end

  -- There is at least one node on the list ?
  if bExito then
    nmap.registry.itsismx.PrefixesKnown = tSalida.Subnets
    stdnse.print_verbose(1, SCRIPT_NAME .. " Were added " .. 
                         #tSalida.Subnets .. " subnets to scan!")
  else
    stdnse.print_verbose(1, SCRIPT_NAME .. 
                         " Not sub-net were added to the" .. " scan list!")
  end

  return stdnse.format_output(bExito, tOutput)
end
