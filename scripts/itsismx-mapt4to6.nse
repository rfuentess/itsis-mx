local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local target = require "target"
local itsismx = require "itsismx"


description=[[
  This script run a typcal Nmap discovery of hosts  on IPv4 
  but for each host up will try to map to IPv6, the IPv6 subnet 
  must had be discovery by a previous script or provided by the .
 
  There is a problem on the nmap 6.25 architecture:  OR only get IPv4
  or only get IPv6 by execution. This mean we can't check first for 
  the IPv4 address to be up so, the user must provided the IPv4 hosts
 to check. I choice to believe the user will first to check for valid 
 IPv4 host and then pass those using a filetext as argument to the script
 (The reason, normal scan are better than NSE for doing that)
 
  The script run at pre-scanning phase and script phase (The first for 
  create tentative 4to6 address and the second for put the living
  nodes on the list of discovered nodes).
]]

---
-- @usage
-- nmap -6 --script itsismx-Map4to6 --script-args newtargets,itsismx.Map4t6.IPv4Hosts=X.X.X.X
--
-- @output


-- nmap.registry.itsismx.Map4t6 Is a global Registry (the final objective of this script)
--   will have all the valid IPv6 address discovered with this Script
-- nmap.registry.map6t4_PreHost is a global registry which will 
-- 	used by the script for the host rule (detect new targets from previous)

-- @args itsismx.Map4t6.IPv4Hosts This must have at least one IPv4 Host  for the script
--	 be able to work (Ex. 192.168.1.1 or { 192.168.1.1, 192.168.2.2 } ) or 
--   The best element is use Nmap for explore the IPv4 address first and then add the 
--   discovered nodes to one single file.
-- @args itsismx-subnet IT's table/single  IPv6 address with prefix
--	   (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )
-- @args newtargets  MANDATORY Need for the host-scaning to succes 


--
-- Version 0.1
-- 	Created 28/03/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam@gmail.com>
--

author = "Raul Armando Fuentes Samaniego"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

--- 
-- This function will add all the list of IPv4 host to IPv6 
-- The most normal is returning X:X:X:X::Y.Y.Y.Y/96
-- The conversion is going to be totattly IPv6 sintax (we are going to 
-- concatenate strings 
-- @args	IPv6_Network  	A IPv6 Address  ( X:X:X:X:: )
-- @args	IPv6_Prefix		A IPv6 Prefix, for this we are waiting 64-96
--					        more will cancel the conversion because there 
--							are not more space for  Map 4-to-6
-- @return	Table		A table of IPv6 hosts (NO prefix) 
-- @return	Error		A warning if something happened. ( Nil if everything was fine)
local From_4_to_6  = function (IPv6_Network, IPv6_Prefix, IPv4SHosts )
	local sError, Listado = nil, {}
	local _ , Host -- _ Can give problem 
	local sBin6, sBin4
	
	--We check if the PRefix are OK, anything less than 96 is fine 
	if IPv6_Prefix > 96 then 
		return  Listado , " The IPv6 subnet: "  .. IPv6_Network .. "/" .. IPv6_Prefix ..
						" can't support a direct Mapping 4 to 6." 
	end
	sBin6 = ip_to_bin(IPv6_Network)
	for _ ,  Host in ipairs(IPv4SHosts) do 
	
			sBin4 = ip_to_bin(Host)
			Host =  sBin6:sub(1,96) ..  sBin4
			print (Host)
			table.insert(Listado, bin_to_ip(host))
	end
	
	return Listado
end

local Prescanning = function ()

	local bSalida = false
	local tSalida = { Nodos={}, Error=""}
	local IPv6_Subnet , IPv6_Add, IPv6_Prefix
	local IPv6Host, sError = {}
	local IPv4Hosts, IPv6User, IPv6Knowns  = stdnse.get_script_args("itsismx.Map4t6.IPv4Nets", 
	local iIndex															"itsismx-subnet", "itsismx.PrefixesKnown" )
	stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Pre-scanning work... "    )
																	
																	
	-- Because Nmap current limitation of working ONE single IP family we must be sure to have everything 
	-- for work the Mapped IPv4 to IPv6
	if  IPv4Subnets == nil then 
		tSalida[Error] = "There is not IPv4 subnets to scan!. You must provide it using the argument: itsismx.Map4t6.IPv4Nets "  
		return bSalida, tSalida
	end

	-- Now we need to have based IPv6 Prefix, the most important is the previous known
	if IPv6User == nil and IPv6Knowns == nil then 
		tSalida[Error] = "There is not IPv6 subnets to try to scan!. You can run a script for discovering or adding your own" ..  
							"  with the arg: itsismx.PrefixesKnown."
		return bSalida, tSalida
	end
	
	if IPv6Knowns ~= nil then
		
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"	Number of Prefixes Known from other sources: " .. #IPv6Knowns    )
				
		for _ , IPv6_Subnet in ipairs(IPv6Knowns) do --We need to extract the data
			IPv6_Add, IPv6_Prefix  = Extract_IPv6_Add_Prefix(IPv6_Subnet) --  We break the data 
			IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix,IPv4Subnets )
			if ( sError ~= nil) then
				stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..  " ERROR: One IPv6 subnet wasnt translate") 
				tSalida[Error] = tSalida[Error] .. "\n" ..  sError
			else -- We need to concatenate the new nodes 
				for iIndex = 1 , #IPv6Host do 
					table.insert(tSalida.Nodos, IPv6Host[iIndex])
				end
				
			end
		end
	end
	
	if IPv6User ~= nil then  -- We got tww options with this.
		if   type(IPv6User) ==  "string" then 
			IPv6_Add, IPv6_Prefix  = Extract_IPv6_Add_Prefix(IPv6User)
			IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix,IPv4Subnets )
			if ( sError ~= nil) then
				stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..  " ERROR: One IPv6 subnet wasnt translate") 
				tSalida[Error] = tSalida[Error] .. "\n" ..  sError
			else -- We need to concatenate the new nodes 
				for iIndex = 1 , #IPv6Host do 
					table.insert(tSalida.Nodos, IPv6Host[iIndex])
				end
			end
		elseif type(IPv6User) ==  "table" then 
			for _ , IPv6_Subnet in ipairs(IPv6User) do --We need to extract the data
				IPv6_Add, IPv6_Prefix  = Extract_IPv6_Add_Prefix(IPv6_Subnet) --  We break the data 
				IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix,IPv4Subnets )
				if ( sError ~= nil) then
					stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..  " ERROR: One IPv6 subnet wasnt translate") 
					tSalida[Error] = tSalida[Error] .. "\n" ..  sError
				else -- We need to concatenate the new nodes 
					for iIndex = 1 , #IPv6Host do 
						table.insert(tSalida.Nodos, IPv6Host[iIndex])
					end
				end
			end
		else 
			-- This only mean the user pass something odd... 
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..  " WARNING:  The itsismx-subnet was ignored because wrong values")
		end
		
	
	end
   --if   type(PrefijosUsuario) ==  "string"  and   #PrefijosUsuario > 0  then end
			
	return bSalida, tSalida		
end

--- 
-- Very simpe action is this one. We add each one of the hosts in the final register.
local Hostscanning = function (host) 
	
	local tSalida = { Nodos={}, Error=""}
	local aux
	
	--Each host is too much!
	stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Host-scanning results... "    )

	-- We are going to be sure don't do stupid thing on wrong register (Because we don't have
	-- handlres for working with registers)
	if nmap.registry.itsismx == nil then 
		tSalida.Error = "You must first initialize the global register Itsismx (There is a global function for that)"
		return false, tSalida
	end
	aux = nmap.registry.itsismx[SCRIPT_NAME]
	if aux == nil then 
		
		tSalida.Error = "The global register Itsismx wasn't initialzed correctly (There is a global function for that)"
		return false, tSalida
	end
	
	--We use the aux for be able to add a new element to the table
	aux[#aux +1] = host.ip
	nmap.registry.itsismx[SCRIPT_NAME] = aux
	table.insert(tSalida.Nodos,host.ip)
	
	return true, tSalida

end

---
-- The script need to be working with IPv6 (To bad can't do it with both at same time ) 
prerule = function() return ( nmap.address_family() == "inet6") end
---
-- We are going to check if the host up was discovered by a list generated in the prescanning
-- phse ( Registry nmap.registry.map6t4_PreHost ).
hostrule = function(host) 
	
	local  Totales, Objetivo, bMatch, sMatch  = nmap.registry.map6t4_PreHost	
	
	if Totales == nil  then return false end
	
	for _, Objetivo in pairs( Totales ) do
		bMatch, sMatch = ipOps.compare_ip(host.ip, "eq", Objetivo)
		if bMatch == nil then
			stdnse.print_debug(1, "\t hostrule  had a error with " ..   
								host.ip .. "\n Error:" .. sMatch )
		elseif bMatch then
			return true
		end
	end
	
	return false
end


action = function(host)

	--Vars for created the final report
	local tOutput = {} 
	tOutput = stdnse.output_table()
	local bExito = false
	local tSalida =  { Nodos={}, Error=""}
	local  bHostsPre, sHostsPre 
	
	itsismx.Registro_Global_Inicializar(SCRIPT_NAME) -- We prepare our work!
	
	-- The aciton is divided in two parts: Pre-scanning and host scanning.
	if ( SCRIPT_TYPE== "prerule" ) then
		bExito , tSalida = Prescanning()
	end
	
	if ( SCRIPT_TYPE== "hostrule" ) then
		bExito , tSalida = Hostscanning(host)
	end

	return stdnse.format_output(bExito, tOutput);	
end
