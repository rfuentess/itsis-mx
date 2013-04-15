local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local target = require "target"
local itsismx = require "itsismx"
local datafiles = require "datafiles"
local bin = require "bin"
local table = require "table"
local math = require "math"

description=[[
  
  This script is very simple, will run a brute-force attack for discovering 
  all the posible hosts  using a stateless SLAAC configuration.  Remember
  this mean the first  64 bits are for the subnet then   next 64 bits 
  are like this <High Mac> FF FE <Low Mac>
  
  By default will search 4,096 random hosts for one particular MAC vendor 
  but will have arguments for run a full scan of  16,777,216.00  host 
  by each vendor provided ( Only for the INSANE! ).
  
  BE CAREFUL , remember some vendors have more than one single OIED
]]

---
-- @usage
-- nmap -6 --script itsismx-Map4to6 --script-args newtargets
--
-- @output


-- @args newtargets  MANDATORY Need for the host-scaning to succes 
-- @args vendors	 (Optional) One or more vendors of NIC if there is no one 
--					  	the script will use "DELL" (arbytrary choice)
-- @args nbits		Number
-- @args compute	String  Will be the way to compute the last 24 bits.
--					 (Default) random	- Will calculate random address. Don't use if 
--										  you plan to sweep more than 20 bits (even less) 
--							   brute 	- Will make a full sweep of the first IPv6 
--										  address to the last of the bits provided.
-- @args itsismx-subnet 			IT's table/single  IPv6 address with prefix
--	   (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )
-- @args itsismx-IPv6ExMechanism 	Only care if you are using brute computing
--      Nmap don't do math operations with IPv6  because the big value of those address. 
--		We use own methods which are: 
--			"number"	- 4 Numbers of 32 bits (Mathematical operations)
--			"sring"		- (Default) 128 Characters on string  (Pseudo Boolean operations)
--
-- Version 0.1
--	
-- 	Created 10/04/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam@gmail.com>
--


local Brute_Range = function( IPv6Base, nBits ) 
	local TheLast, TheNext, err
	local Hosts, Prefix  = {},0
	-- This can be affected by itsismx-IPv6ExMechanism
	local IPv6ExMechanism = stdnse.get_script_args( "itsismx-IPv6ExMechanism" )
	
	--First, how many bits we are going to work ?
	if nBits == nil then 
		Prefix =  128 -11
	elseif nBits > 2 and  nBits <= 24 then
		Prefix =  128 - nBits
	else 						-- Something wrong, we must be careful
		return nil
	end 
	
	print("\t\t  Preparativos:" ..  IPv6Base .. "00:0/" .. Prefix )
	--  2001:db8:c0ca:0:0:0:0:0021c:23ff:fe00:0
	TheNext, TheLast, err = ipOps.get_ips_from_range(IPv6Base .. "00:0000/" .. Prefix)
	
	print("\t\t  Preparativos:" ..  err )
	
	stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					".Vendors.Address: " .. " will be calculated 2 ^ " .. 
					nBits  .. " hosts using brute values for: " .. IPv6Base)
	
	-- Now the hard part...   numbers in NSE (LUA 5.2) are limited to 10^14..
	-- So... we can0t do the easy life to pass to number and do the maths there...
	-- There are extras libraries for Lua 5.2 but aren't part of Nmap project (yet)
	-- So, we use our special mechanism.
	repeat  
		table.insert(Hosts,TheNext)
		-- Testing local Number_Instead_String = false
		TheNext = itsismx.GetNext_AddressIPv6(TheNext,Prefix, IPv6ExMechanism)
		print("\t\t WAJU: " .. IPv6Base .. hHost   )
	until not ipOps.ip_in_range(TheNext, IPv6Base .. "/" .. Prefix)
	return Hosts
end

---
-- This function will be getting the first 88 bits  and will generate 
-- the last 24 bits will be calculated using randome values.
-- 	By default we are going to work  11 bits ( 2 ^ 11  ) for   the total 
--  host. That is: Around 2,048 nodes that are only  00.122% of the possible range.
-- The user can increase the number to the 24 bit BUT Will take A LOT OF RESOURCES
-- and TIME because. 
-- 	@args IPv6Base 	String	First 88 bits 
--	@args nBits		Number of bits to use (Default: 11 )
-- 	@returns 		List  of IPv6 address host ( Nil if there is a error)
local Random_Range = function ( IPv6Base, nBits ) 

	-- WE need begin to create the ranges but... There is a lot way to do it ... 
	-- The first one is going to be random values In a number of 24 bits
	local  MaxNodos =  10
	
	--First, how many bits we are going to work ?
	if nBits == nil then 
		nBits = 11
		MaxNodos =  math.pow(2, nBits)
	elseif nBits > 2 and  nBits <= 24 then
		MaxNodos =  math.pow(2, nBits)
	else 						-- Something wrong, we must be careful
		return nil
	end 
	
	local iAux, iIndex, _, iValor, bUnico, hHost
	local  Hosts, Numeros = {}, {}
	--print("\t Random for:" .. IPv6Base)

	stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					".Vendors.Address: " .. " will be calculated 2 ^ " .. 
					nBits  .. " hosts using random values for: " .. IPv6Base)
	
	for iIndex = 1, MaxNodos do 
		iAux = math.random( 16777216 )  --Remember this a C/C++ Random, isn-t better than that!
		
		--Before continue we  must be sure the Random number isn-t duplicated...
		bUnico = true
		for _ , iValor  in ipairs(Numeros ) do
			if iValor == iAux then 
				bUnico= false
				--print(print("\t\t Chale :" ))
				break
			end
		end
		--print("\t\t iIndex :" .. iIndex .. " " )
		if bUnico ~= true then
			iIndex = iIndex - 1	-- We are 
		else 
			table.insert(Numeros, iAux)
			hHost = itsismx.DecToHex(iAux)
			
			-- We must be sure hHost is 6 hexadecimals
			while #hHost < 6 do
				hHost = "0" .. hHost
			end
			hHost = hHost:sub(1,2) .. ":" .. hHost:sub(3,6) 
			table.insert( Hosts, IPv6Base .. hHost)
			--print("\t\t WAJU: " .. IPv6Base .. hHost   )
		end
		
	end
	return Hosts
end
---
--  Mechanisn based by the RFC 4291  
local getSlaacCandidates = function ( IPv6Prefix , HighPart ) 
	
	local hosts, sError ={}, nil
	local _, OIED, hexadecimal, bitsAlto
	local Metodo, NumBits = stdnse.get_script_args("itsismx.slaac.compute", "itsismx.slaac.nbits")
	
	-- We have some options  there, we can calculate Random hosts  or brute force
	-- We can work 8 - 24 bits ( 256 - 16 millions of hosts  )  
	-- By default will be Random with 12 bits ( 4,096 random hosts )
	-- The last 64 bits to create will have this format:
	
	  -- |0              1|1              3|3              4|4              6|
	  -- |0              5|6              1|2              7|8              3|
	  -- +----------------+----------------+----------------+----------------+
	  -- |ccccccugcccccccc|cccccccc11111111|11111110mmmmmmmm|mmmmmmmmmmmmmmmm|
	  -- +----------------+----------------+----------------+----------------+
	  
	-- Where "C" are the bits of HighPart,  "m" are the  bits we are to create 
	-- and "u" "g" are bits to overlap the one from Highpart ( for this script 
	--  will be  10) 
	
	-- There should be special Candidates, thoses will be the one from 
	-- known virtual machines. On those cases "HIGHParth"  would be longer than 24 bits
	-- (Actually the general values  come as a string XXXXXX  so, 
	-- any longer 6 character will be "Special"
	
	if NumBits == nil then  
		 -- Actually this is a little redundant but better a strict control than nothing
		 NumBits = 11  
	elseif tonumber(NumBits) < 2 then 
		NumBits = 2
		sError = "Was add a very small value to nbits. Was fixed to 2"
	elseif tonumber(NumBits) > 24 then 
		NumBits = 24
		sError = "Was add a very high value to nbits. Was fixed to 24"
	end
	
	-- We begin with the OIED candidates, and for each group we'll try to add them 
	-- to our IPv6 subnets	
	for _ , OIED in ipairs(HighPart) do 
	
		if #OIED == 6 then -- Our clasic case! 
			hexadecimal = tonumber(OIED,16) 
			
			hexadecimal =  bit32.replace( hexadecimal , 2,16,2) -- This or AND
			bitsAlto = itsismx.DecToHex( hexadecimal) -- This ignore the high part...
			
			-- The XXXXXX10...XXXb make alway the string to be 5 or 6 hexadecimals
			while #bitsAlto < 6 do
				bitsAlto = "0" .. bitsAlto
			end
			
			-- We begin to create the  hosts ranges! We already have the first 88 bits
			-- Sp we only need to create the last 24
			-- Lo primero, creamos la parte estatica de 88 bits
			local IPv6Base = ipOps.expand_ip(IPv6Prefix)
	
			-- Format to:   XXXX:XXXX:XXXX:XXXX:MMMM:MMFF:FE??:????
			IPv6Base = IPv6Base:sub(1,64) .. bitsAlto:sub(1,4) .. ":" .. bitsAlto:sub(5,6) .. "ff:fe"
			
			-- Random or Brute mechanism?
			if Metodo == nil then
				--Random_Range(IPv6Base,NumBits )
				Brute_Range(IPv6Base,8 )
			elseif Metodo == "random" then
				Random_Range(IPv6Base,NumBits )
			elseif Metodo == "brute" then
				Brute_Range(IPv6Base,NumBits )
			else	-- ERROR!
				return nil, "ERROR: The compute mechanism is incorrect: " .. Metodo
			end
			
		end
	end
	return hosts, sError

end

local getMacPrefix = function ( Vendedores, MacList   ) 

	local sLista, hLista = {},{}
	local hMac, sID, _, sUserMac
	
	if type(Vendedores) ==  "string" then 
		table.insert(sLista, Vendedores)
	elseif type(Vendedores) ==  "table" then 
		sLista = Vendedores
	else 
		return nil
	end
	
	
	-- Now we search for the vendors in the Table. WE SEARCH ALL THE TABLE   not only the first
	-- option. Why? Because some vendors can have more than one registry.
	for _, sUserMac in pairs ( sLista)  do 
		sUserMac = sUserMac:lower()
		for hMac, sID in pairs( MacList ) do
			sID = sID:lower()
			if sID:find(sUserMac) ~= nil then
				table.insert(hLista,hMac ) 
				stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					".Vendors: " .. " Adding  " ..   hMac .. " OUI  for the vendor: " .. sUserMac  .. 
					" ( " .. sID .. " )")
			end
		end
		
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				".Vendors: " .. " Were addedd  " ..   #hLista .. " OUI for the vendor: " .. sUserMac  )
	end
	
	 
	return hLista
end

local Prescanning = function ()

	
	local MacList, PrefixAux, _
	local bSalida, tSalida = false , { Nodos={}, Error=""}
	local MacUsers,IPv6User  = stdnse.get_script_args("itsismx.slaac.vendors","itsismx-subnet")
	local IPv6Knowns = nmap.registry.itsismx.PrefixesKnown
	local PrefixHigh, IPv6Total = {}, {}
	local IPv6_Add, IPv6_Prefix 
	-- Actu
	
	stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Pre-scanning work... "    )
	
	-- First, we retrie the MAC address list 
	bSalida, MacList = datafiles.parse_mac_prefixes ()
	
	-- We don't have anything to fail on this...
	-- We don't use Try/Catch because we don't need to clean any mesh
	if not bSalida then 
		tSalida.Error = " The Mac Prefixes file wasn't find!"
		return bSalida, tSalida
	end
	
	
	
	-- Now we must retrieve the Prefixes given by the user and retrieve the total numbers
	-- if the user didn-t give one we are going to use a Default
	if (MacUsers == nil ) then
		PrefixHigh = getMacPrefix( "DELL",MacList  )
	else
		PrefixHigh = getMacPrefix( MacUsers,MacList  )
	end
	
	-- Now we must retrieve the total number of PRefix  to which uses the previous data 
	bSalida = false
	if IPv6User == nil and IPv6Knowns == nil then 
		tSalida[Error] = "There is not IPv6 subnets to try to scan!. You can run a script for discovering or adding your own" ..  
							"  with the arg: itsismx.PrefixesKnown."
		return bSalida, tSalida
	end
	
	-- The next two If are very healthy for my mind...
	if IPv6Knowns ~= nil then
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"	Number of Prefixes Known from other sources: " .. #IPv6Knowns    )		
		for _ , PrefixAux in ipairs(IPv6Knowns) do 
			table.insert(IPv6Total,PrefixAux )	
		end		
	end
	
	if IPv6User ~= nil then
		if type(IPv6User) ==  "string" then 
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"	Number of Prefixes Known from other sources: 1 "     )
			table.insert(IPv6Total,IPv6User )
		elseif type(IPv6User) ==  "table" then
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"	Number of Prefixes Known from other sources: " .. #IPv6User    )		
			for _ , PrefixAux in ipairs(IPv6User) do -- This is healthy for my mind...
				table.insert(IPv6Total,PrefixAux )	
			end	
		end
			
	end
	
	-- Now we begin  to work all the prefix and to increase the list !
	for  _, PrefixAux in ipairs(IPv6Total) do
		
		--First we must be sure those are 64 bits of Prefix
		IPv6_Add, IPv6_Prefix  = itsismx.Extract_IPv6_Add_Prefix(PrefixAux)
		if( IPv6_Prefix ~= 64) then
			tSalida.Error = tSalida.Error .. "\n" .. PrefixAux .. " Must have a prefix of 64 (Was ommited)"  
		else
			getSlaacCandidates ( IPv6_Add , PrefixHigh ) 
		end
	end
	
	
end


---
-- The script need to be working with IPv6
prerule = function() return ( nmap.address_family() == "inet6") end
---
-- We need to confirm that host is one of the previous pre-scanning phase nodes  
-- and return true.
hostrule = function(host) 
	--Debug
	 -- local key, elemento 
	  -- for key, elemento in pairs(nmap.registry.args) do
		  -- print(key, elemento)
	 -- end

	
	local  Totales, Objetivo, bMatch, sMatch  = nmap.registry.slaac_PreHost	
	
	
	-- print(Totales)
	if Totales == nil  then return false end
	--print("Totales:" .. #Totales)
	
	-- for key, elemento in pairs(Totales) do
		 -- print(key, elemento)
	 -- end
	
	for _, Objetivo in pairs( Totales ) do
		
		bMatch, sMatch = ipOps.compare_ip(host.ip, "eq", Objetivo)
		if bMatch == nil then
			--print (sMatch)
			stdnse.print_debug(1, "\t hostrule  had a error with " ..   
								host.ip .. "\n Error:" .. sMatch )
		elseif bMatch then
			return true
		end
	end
	
	return false
end


action = function ( host ) 

	--Vars for created the final report
	local tOutput = {} 
	tOutput = stdnse.output_table()
	local bExito = false
	local tSalida =  { Nodos={}, Error=""}
	local  bHostsPre, sHostsPre 
	
	itsismx.Registro_Global_Inicializar("sbkmac") -- Prepare everything!
	math.randomseed ( nmap.clock_ms() ) -- We are going to use  Random  values, so Seed!
	
	-- The aciton is divided in two parts: Pre-scanning and host scanning.
	-- The first choice the tentative hosts to scan and the second only 
	-- confirm which are truly up.
	if ( SCRIPT_TYPE== "prerule" ) then
		bExito , tSalida = Prescanning()
		-- Now we adapt the exit to tOutput and add the hosts to the target!
		tOutput.warning = tSalida.Error 
		
		if bExito then
			for _,  sHostsPre in ipairs(tSalida.Nodos) do
				bTarget, sTarget = target.add(sHostsPre)
				if bTarget then --We add it!

					--IF everything is well tSalida.Nodos & Nodos are the 
					--same size BUT we must be sure the nodes are added to 
					-- the host scan phase.
					table.insert(Nodes, sHostsPre)
					
				else 
					tOutput.warning = tOutput.warning .. " \n" .. sTarget
				end
			end
		
			--Final report of the Debug Lvl of Prescanning
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
								" Temptative Mapped IPv4 to IPv6 added to the scan:" ..  #tSalida.Nodos .. 
								"\n Succesful Mapped IPv4 to IPv6 added to the scan:" ..  #Nodes )
			-- We add those to the global registry
			-- We don't add those nodes to the standard exit BECAUSE ARE TEMPTATIVE ADDRESS
			nmap.registry.slaac_PreHost = Nodes 
			table.insert(tOutput, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ":  Were added " .. #Nodes .. 
							" nodes to the host scan phase" )

		end
	end

end