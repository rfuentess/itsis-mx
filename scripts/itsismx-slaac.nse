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
  
  BE CAREFUL , remember some vendors have more than one single OUI
]]

---
-- @usage
-- nmap -6 --script itsismx-slaac --script-args newtargets
--
-- @output

-- 
-- @args newtargets  MANDATORY Need for the host-scaning to succes 
-- @args vendors	 (Optional) String/Table The user can provided companies names (Like Apple, Dell, HP, etc.)
--					 which have a valid register for a OUI.  The user can too add a specific OUI (5855CA , 
--					 6C9B02, 0CD292, etc.) when has done homework and is very sure can reduce the search.
--					If the vms argument isn’t provided the default value is “DELL” otherwise will be empty. 
-- @args vms		(Optional) If added will search SLAACs based on well known 
--						Virtual MAchines technologies, the user can add those arguments:
--						(DEFAULT)	:  Will search for VMware, Virtual Box, Paralalles,
--									   Virtual PC and QEMU VMs
--						"W"			:  Will search for VMware VMs (Static and Dynamic)
--						"wS"		:  Will search for VMware VMs with static/manual configuration MAC address.
--						"wD"		:  Will search for VMware VMs with dynamic configuration MAC address.
--						"P"			:  Will search for  Parallels Virtuozzo and Dekstop VMs
-- 						"pV"		:  Will search for  Parallels Virtuozzo  VMs
-- 						"pD"		:  Will search for  Parallels Dekstop  VMs
--						"V"			:  Will search for  Oracle Virtual Box VMs
--						"M"			:  Will search for  Microsoft Virtual PC VMs
--						"L"			:  Will search for  Linux  QEMU
--						"WPVML"		:  Equivalent to the defualt option.
--						"pVpD"		:  Equivalent to "P" ("P" override the others two)  
-- @args itsismx-slaac.nbits		(Optional)  Number of 1-24. This indicate how many bits to calculate or 
--									what is the same: How much host to calculate (2^nbits).  By default the 
--									is 11 (Except VMware case which is lower because his range is 1-16).
-- @args itsismx-slaac.compute		(Optional) String  Will be the way to compute the last 24 bits.
--										(Default) random	- Will calculate random address. Don't use if 
--										  					  you plan to sweep more than 20 bits (even less) 
--										brute 				- Will make a full sweep of the first IPv6 
--										  					  address to the last of the bits provided.
-- @args itsismx-slaac.vmipv4		(Optional) Table/String IPv4 address used for calculate VMware VM servers.
--									The user can provided IPv4 which him believe are used for the VMware Host, 
--									this will save a lot of time and resources for the script.
-- @args itsismx-slaac.knownbits  	(Optional) String. Binary values used for calculate VMware VM servers.
--									When the user don’t know tentatives IPv4 address of the VMware host but 
--									he assume to know some part of the last 16 bits of the IPv6 address 
--									(maybe from the sub-networks scheme)  he can add them as binary value
--									with this argument.

-- @args itsismx-subnet 			IT's table/single  IPv6 address with prefix
--	   (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )
-- @args itsismx-IPv6ExMechanism 	(Optional) Only if you are using brute computing
--      Nmap don't do math operations with IPv6  because the big value of those address. 
--		We use own methods which are: 
--			"number"	- 4 Numbers of 32 bits (Mathematical operations)
--			"string"		- (Default) 128 Characters on string  (Pseudo Boolean operations)
--
-- Version 1.0
--	Updated 25/04/2013	- v1.3	- First version at full power! (and minor corrections)
--	Updated 24/04/2013	- v1.0 
-- 	Created 10/04/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam@gmail.com>
--

---
-- This function get the first 88 bits of a SLAAC IPv6 address and will calculate the  
-- last 24 bits using brute force (A Sweep of address).   This is the one to use when we 
-- dare to sweep all the 24 bits of candidates (Just remeber, we are talkign about millions)
-- @args 	IPv6Base	String - First 88 bits of the IPv6 address on string IPv6 Format
-- @args 	nBits		Number - How many bits we are going to calculate ( Range: 3-24) 
-- @return 	Table		A table with IPv6 Slaac address candidates. Nil if there was a error.
local Brute_Range = function( IPv6Base, nBits ) 
	local TheLast, TheNext, err
	local Hosts, Prefix  = {},0
	-- This can be affected by itsismx-IPv6ExMechanism
	local IPv6ExMechanism = stdnse.get_script_args( "itsismx-IPv6ExMechanism" )
	
	--nBits with brute force mean how many samples we are to take, this will impact on the 
	-- Prefix
	if nBits == nil then 
		Prefix =  128 -11
	elseif tonumber(nBits) > 2 and  tonumber(nBits) <= 24 then
		Prefix =  128 - nBits
	else 						-- Something wrong, we must be careful
		return nil
	end 
	
	--print("  Preparativos:" ..  IPv6Base .. "00:0/" .. Prefix )

	TheNext, TheLast, err = ipOps.get_ips_from_range(IPv6Base .. "00:0/" .. Prefix)
	
	--print("\tRango:" ..  TheNext .. " - " .. TheLast )
	stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					".Vendors.Address: " .. " will be calculated 2 ^ " .. 
					nBits  .. " hosts using brute values for: " .. IPv6Base)
	
	-- Now the hard part...   numbers in NSE (LUA 5.2) are limited to 10^14..
	-- So...  we use our special mechanism.
	--print("\t\t WAJU: " .. TheNext   )
	repeat  
		stdnse.print_debug(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					".Vendors.Address:  Added IPv6 address " .. TheNext .. " to the host scanning list...")
		table.insert(Hosts,TheNext)
		TheNext = itsismx.GetNext_AddressIPv6(TheNext,Prefix, IPv6ExMechanism)
		--print("\t\t WAJU: " .. TheNext   )
		bool ,err = ipOps.ip_in_range(TheNext, IPv6Base .. "00:0/" .. Prefix)
		-- if err ~= nil then
			-- print("\t\t ERROR: " .. err   )
		-- end
	until not ipOps.ip_in_range(TheNext, IPv6Base .. "00:0/" .. Prefix)
	
	return Hosts
end


---
-- This function get the first 88 bits of a SLAAC IPv6 address and will calculate the  
-- last 24 bits using random values. This is useful when we don't dare to sweep all the 
-- networking and don't want to look only for the lower mac-address. However we are going 
-- to get differents results because the "random" choice of the nodes.
-- @args 	IPv6Base	String - First 88 bits of the IPv6 address on string IPv6 Format
-- @args 	nBits		Number - How many bits we are going to calculate ( Range: 3-24) 
-- @return 	Table		A table with IPv6 Slaac address candidates. Nil if there was a error.
local Random_Range = function ( IPv6Base, nBits ) 

	-- WE need begin to create the ranges but... There is a lot way to do it ... 
	-- The first one is going to be random values In a number of 24 bits
	local  MaxNodos =  10
	
	--First, how many bits we are going to work ?
	if nBits == nil then 
		nBits = 11
		MaxNodos =  math.pow(2, nBits)
	elseif tonumber(nBits) > 2 and  tonumber(nBits) <= 24 then
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
			iIndex = iIndex - 1	-- We don0t leave until got a new  Value...
		else 
			table.insert(Numeros, iAux)
			hHost = itsismx.DecToHex(iAux)
			
			-- We must be sure hHost is 6 hexadecimals
			while #hHost < 6 do
				hHost = "0" .. hHost
			end
			hHost = hHost:sub(1,2) .. ":" .. hHost:sub(3,6)
			stdnse.print_debug(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					".Vendors.Address:  Addeding IPv6 address " .. IPv6Base .. hHost .. " to the host scanning list..." )
			 
			table.insert( Hosts, IPv6Base .. hHost)
			--print("\t\t WAJU: " .. IPv6Base .. hHost   )
		end
		
	end
	return Hosts
end

--- 
-- This function will generate the sweep address for the case where the IPv4 address 
-- are already known.
-- We already known the IP4 list to work, we know almost everything , 
-- we only need to do a brute force for 8 bits and that is all.  
local Vmware_Range_000C29WellKnown = function( IPv6Base, sHexadecimal , IPv4Candidatos, IPv6ExMechanism ) 

	local  _, Candidato, sIPv4L, Segmentos,sError
	local sIPv4Ldot3, sIPv4Ldot4, sIPv6P120 
	local IPv6Prefix, TheNext, TheLast
	local hosts = {}
	for _, Candidato in ipairs(IPv4Candidatos) do
		
		-- For each candidate we retrieve the last 16 bits.
		Segmentos,sError = ipOps.get_parts_as_number(Candidato)
		if ( sError ~= nil) then
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
						" VMware(dynamic): ERROR with one or more IPv4 provided by the user:" ..  
						Posible .. ". Error Message: " .. sError)
			return nil
		end
		
		sIPv4Ldot3, sIPv4Ldot4 = itsismx.DecToHex(Segmentos[3])  ,  itsismx.DecToHex(Segmentos[4])
			
		while #sIPv4Ldot3 < 2 do sIPv4Ldot3 = "0" .. sIPv4Ldot3 end
		while #sIPv4Ldot4 < 2 do sIPv4Ldot4 = "0" .. sIPv4Ldot4 end
		sIPv4L 	= sIPv4Ldot3 .. sIPv4Ldot4
		
		-- Now we alredy have everything for get the first 120 bits!
		Segmentos,sError = ipOps.get_parts_as_number(IPv6Base)
		if ( sError ~= nil) then
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
						" VMware(dynamic): ERROR with" ..  IPv6Base .. "/64. Error Message: " .. sError)
			return nil
		end
		
		---- PPPP:PPPP:PPPP:PPPP:020C:29FF:FEXX:XX??
		IPv6Prefix = itsismx.DecToHex(Segmentos[1]) .. ":" .. itsismx.DecToHex(Segmentos[2]) .. ":" .. 
			   itsismx.DecToHex(Segmentos[3]) .. ":" .. itsismx.DecToHex(Segmentos[4]) .. ":" .. 
			   sHexadecimal .. "FF:FE" .. sIPv4L:sub(1,2) .. ":" .. sIPv4L:sub(3,4) .. "00"
		
		-- Now... we only need to do a sweep on the last 8 bits...
		TheNext, TheLast, sError = ipOps.get_ips_from_range(IPv6Prefix .. "/120")
		if ( sError ~= nil) then
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
						" VMware(dynamic): ERROR with (Variable IPv6Prefix)" ..  
						IPv6Prefix .. "/120. Error Message: " .. sError)
			return nil
		end
		
		stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
						" VMware(dynamic):  Will be add 255 targets to the scan list: " .. IPv6Prefix .. "/120")
						
		repeat  
	
			stdnse.print_debug(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
						" VMware(dynamic):  Added IPv6 address " .. TheNext .. " to the host scanning list...")
			table.insert(hosts,TheNext)
			TheNext = itsismx.GetNext_AddressIPv6(TheNext,120, IPv6ExMechanism)
			bool ,sError = ipOps.ip_in_range(TheNext, IPv6Prefix .. "/120" )
			if ( sError ~= nil) then
				stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
						" VMware(dynamic): Error generating range of IPv6 address " .. sError )
				return nil
			end
			
		until not ipOps.ip_in_range(TheNext, IPv6Prefix .. "/120" )
		
	end
	
	return  hosts
end


---
-- We search in the range of MAC  00:0C:29:WW:TT:UU but here is very special  WW:TT can be 
-- known beforehand because is based on IPv4 addres (are the last 16 bits) and UU is random.
-- nBits will play  a role different on other functions. Here will indicate the number of samples
-- to generate  ( 2^nBits ) 
-- @args	IPv6Base	String IPv6 Address (WELL-FORMED)
-- @args	nBits		(Optional) Number  of bits to try to scan
-- @args	Metodo		(Optional) String  random values or sweep
-- @return	Table		Valid IPv6 hosts address ( or nil if there was a error)
local Vmware_Range_000C29 = function ( IPv6Base, nBits, Metodo )
	local hosts, sError = {} , nil
	local IPv4Candidatos, Num_Aleatorios,iC, iAux = {},{},0
	local IPv4Argumentos, BitsKnown = stdnse.get_script_args("itsismx-slaac.vmipv4","itsismx-slaac.knownbits")
	local IPv6ExMechanism = stdnse.get_script_args( "itsismx-IPv6ExMechanism" )
	local TotalMuestras, Wellknown, RangoAleatorio
	local Segmentos,sError, Candidato,IPv6Prefix,IPv6Candidato
	
	--  ccccccugcccccccc:cccccccc
	--  0000000000001100:00101001
	-- ___________________________
	--  0000001000001100:00101001	
	local sHexadecimal = "020C:29" -- This is the high 24 bits

	-- There is 2 way to this function: 1) We known beforehand IPv4 address
	-- 2) We need to generate the IPv4 address.  Both choices are dictated by 
	-- IPv4Argumentos. 
	
	if IPv4Argumentos ~= nil then
		-- Can be a single one or multiples, for my health I will pass  
		-- everything to a single new table.
		if type(IPv4Argumentos) ==  "string" then 
			stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				" VMware (Dynamic): The user provided  1  IPv4 address."     )
			table.insert(IPv4Candidatos,IPv4Argumentos )
		elseif type(IPv4Argumentos) ==  "table" then
			stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				" VMware (Dynamic): The user provided " ..  #IPv4Argumentos ..  " IPv4 address."     )		
			for _ , PrefixAux in ipairs(IPv4Argumentos) do -- This is healthy for my mind...
				table.insert(IPv4Candidatos,PrefixAux )	
			end	
		end	 -- To this point the first way don-t need to do more... 
		
		return  Vmware_Range_000C29WellKnown (  IPv6Base, sHexadecimal , IPv4Candidatos, IPv6ExMechanism ) 
	
	end
	
	-- From this point we only care for the Random option (WEEEE!)
	-- We  are to generate 16 bits of random values BUT the user can  provided 
	-- some of thoses bits  chaning everything. 
	-- However we are going by defaulwork  with 4 of 16 bits which will generate
	-- 8 tentatives address groups of 255 address for give a total   
	--  4,080  of  16,711,680 samples. 
	-- The user can be more brave and give more bits.
	-- Tip:Because this is special, we check again the global registry otherwise 
	-- nBits will read with 11 instead of nil.
	if stdnse.get_script_args("itsismx-slaac.nbits") == nil then
		nBits = 4 
	elseif tonumber(nBits) > 16 then -- As this is a special case, this can happens.
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				" VMware (Dynamic): The args nbits was trunked to 16 for compute this part. "  )
		nBits = 16
	end
	
	--nBits = 4  --DEBUG!!!
	
	if BitsKnown == nil then
		Wellknown = 0
	elseif itsismx.Is_Binary (BitsKnown) then
		Wellknown = #BitsKnown
	else  -- The user provided something very important, wrong, SO WE STOP.
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				" VMware (Dynamic): The user provided a wrong binary value: " ..  BitsKnown  )
		return nil
	end
	
	-- Now we begin to compute the information.
	
	if  nBits + Wellknown >  16 then --  Houston we have a problem...
		--There is something wrong, probably from the other VM or testing or from 
		-- the way the user is using the system, so, we STOP.
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				" VMware (Dynamic): There is incongruity with knownbits and/or nbits" .. 
				" because are bigger than 16: " .. nBits .. " + " ..  Wellknown .. " > 16"  )	
		return nil 
	end 
	
	TotalMuestras = math.pow(2, nBits)				-- How many samples to do
	RangoAleatorio = math.pow(2, 16 - Wellknown)	-- How big the random number to compute
	
	-- The question is .. brute or random mechanism? At least the user choice by himself. 
	
	if Metodo == nil then
		-- More than half of samples is bad for random because overhead with the extra 
		-- table.
		if RangoAleatorio <=  math.floor( 0.5 *  TotalMuestras) then
			Metodo = "brute"
			
		else 
			Metodo = "random"
		end
	end
	
	-- Now we begin to create candidates. Those will have decimal number for now and will be 
	-- stored on a table.
	while  iC < TotalMuestras  do
		if Metodo == "brute" then 
			table.insert(IPv4Candidatos, iC)
			iC = iC + 1
		elseif  Metodo == "random" then -- We are going to use a extra table 
			iAux = math.random( RangoAleatorio )
			bBool = true
			for _ , Canditato in ipairs(IPv4Candidatos) do
				if Canditato == iAux then
					 bBool = false
					 break
				end
			end
			if bBool then
				table.insert(IPv4Candidatos, iAux)
				iC = iC + 1
			end
		end			
	end
	
	-- Now we have almost all the data need for formed a valid IPv6 address like this:
	Segmentos,sError = ipOps.get_parts_as_number(IPv6Base)
		if ( sError ~= nil) then
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
						" VMware(dynamic): ERROR with" ..  IPv6Base .. "/64. Error Message: " .. sError)
			return nil
		end
		
	-- The last part is assemble the XX:XX and create the sweep scan for the last  8 bits 
	IPv6Prefix = itsismx.DecToHex(Segmentos[1]) .. ":" .. itsismx.DecToHex(Segmentos[2]) .. ":" .. 
			     itsismx.DecToHex(Segmentos[3]) .. ":" .. itsismx.DecToHex(Segmentos[4])	.. ":" .. 
			     sHexadecimal .. "FF:FE"   
	-- PPPP:PPPP:PPPP:PPPP:020C:29FF:FEXX:XX?? to bits
	IPv6Prefix, sError = ipOps.ip_to_bin(IPv6Prefix.."00:0000" )  -- FE::/104 ~= FE00::/112
	if sError ~= nil then
				print( "ARG " .. IPv6Prefix.."00:0000"  .. " "  .. sError)
			end
	--print( "ARG " ..  IPv6Prefix .. " " ..  #IPv6Prefix)
	--print ("YYYY Muestra "  .. #IPv4Candidatos  )
	
	for _ , Candidato in ipairs( IPv4Candidatos )	do
		 	-- We convert the number to hexadecimal and then to binary 
			iAux = itsismx.DecToHex(Candidato)
			iAux = itsismx.HextToBin(iAux) 
			
			-- Now, we  can have a problem, suppose we were working with a number of 13 bits
			-- with the last function "iAux" will have 16 bits instead of 13, so we need 
			-- to be sure the lenght is correct.  BUT by other hand we have the other alternative
			-- the number could be simple: 1 and will return "0001" instead of "0000000000001"
			--print ("YYYY iAux "  .. iAux  .. " " .. #iAux )
			if  16 - Wellknown < #iAux  then --too big?
				while   16 - Wellknown < #iAux  do iAux = iAux:sub(2) end
			elseif 16 - Wellknown > #iAux then -- too small?
				while   16 - Wellknown > #iAux  do iAux = 0 .. iAux end
			end
			
			--print ("YYYY iAux "  .. iAux .. " " .. #iAux  )
			-- We assemble the Prefix! but... we had a Hex part and a binary part... is chaos 
			-- we pass everything to binary.
			--
			
			
			--print ("YYYY LEER "  .. #IPv6Prefix:sub(1,104) .. " " .. #iAux .. " 8"  )
			if  Wellknown == 0  then
				IPv6Candidato = IPv6Prefix:sub(1,104) .. iAux .. "00000000"
			else 
				IPv6Candidato = IPv6Prefix:sub(1,104) .. BitsKnown .. iAux .. "00000000"
			end
			
			-- We should have 128 bits and pass them to IPv6 again...
			--print ( "YYYY: IPv6Candidato " .. #IPv6Candidato ) 
			IPv6Candidato = ipOps.bin_to_ip( IPv6Candidato )
			--print ( "YYYY: " .. IPv6Candidato )

						
			-- And now brute force!
			TheNext, TheLast, sError = ipOps.get_ips_from_range(IPv6Candidato .. "/120")
			if ( sError ~= nil) then
				stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
							" VMware(dynamic): ERROR with (Variable IPv6Candidato)" ..  
							IPv6Candidato .. "/120. Error Message: " .. sError)
				return nil
			end
			
			stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
							" VMware(dynamic):  Will be add 255 targets to the scan list: " .. IPv6Candidato .. "/120")
							
			repeat  
		
				stdnse.print_debug(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
							" VMware(dynamic):  Added IPv6 address " .. TheNext .. " to the host scanning list...")
				table.insert(hosts,TheNext)
				TheNext = itsismx.GetNext_AddressIPv6(TheNext,120, IPv6ExMechanism)
				bool ,sError = ipOps.ip_in_range(TheNext, IPv6Candidato .. "/120" )
				if ( sError ~= nil) then
					stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
							" VMware(dynamic): Error generating range of IPv6 address " .. sError )
					return nil
				end
				
			until not ipOps.ip_in_range(TheNext, IPv6Candidato .. "/120" )
		
	end
	
	return hosts  
end

---
-- We search in the range of MAC  00:50:56:XX:YY:ZZ but is special, only generate random values for 
-- YY:ZZ because the range of XX is well-known: 00-3F.
-- @args	IPv6Base	String IPv6 Address (WELL-FORMED)
-- @args	nBits		(Optional) Number  of bits to try to scan
-- @args	Metodo		(Optional) String  random values or sweep
-- @return	Table		Valid IPv6 hosts address ( or nil if there was a error)
local Vmware_Range_005056 = function ( IPv6Base, nBits, Metodo )
	local hosts, sError,IPv6Segmentos = {} , nil
	
	 --  ccccccugcccccccc:cccccccc
	 --  0000000001010000:01010110
	 -- ___________________________
	 --  0000001001010000:01010110
	 --  0x250 :  0x56
	
	--print ("\t\t TATATA " ..IPv6Base )
	
	-- Format to:   XXXX:XXXX:XXXX:XXXX:0250:56FF:FEXX:????			
	IPv6Segmentos,sError = ipOps.get_parts_as_number(IPv6Base)
	
	if sError ~= nil then
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
						" VMware(static): Error: " .. sError )
		return nil, sError
	end
	
	IPv6Base = itsismx.DecToHex(IPv6Segmentos[1]) .. ":" .. itsismx.DecToHex(IPv6Segmentos[2]) .. ":" .. 
			   itsismx.DecToHex(IPv6Segmentos[3]) .. ":" .. itsismx.DecToHex(IPv6Segmentos[4]) .. ":" .. 
			    "0250:56ff:fe"
	
  
	-- Now, we are going to search on the next 6 bits, but this mean we need to adjust a little more 
	-- nBits for be sure don't overflow the 128 bits range of search
	if tonumber(nBits) > 18 then --24-6
		nBits = 18
		Metodo = "brute"
		sError = " \n VMware Static MAC: Was need to reduce the bits to 18."
	elseif tonumber(nBits) > 16 then -- IF we are going to search for 25% of host... then brute force.
		Metodo = "brute"	-- Probably is more efficient than random
	end
			
		
			
	-- Random or Brute mechanism?
	if Metodo == nil then
		hosts = Random_Range(IPv6Base,nBits )
	elseif Metodo == "random" then
		hosts = Random_Range(IPv6Base,nBits )
	elseif Metodo == "brute" then
		hosts = Brute_Range(IPv6Base,nBits )
	else	-- ERROR!
		return nil, "ERROR: The compute mechanism is incorrect: " .. Metodo
	end
		
	return hosts , sError
end

---
--  Mechanisn based by the RFC 4291 
-- This function will be getting the first 88 bits  and will generate 
-- the last 24 bits by randome or brute choices mechanism.
-- By default we are going to work  11 bits ( 2 ^ 11  ) for with random mechanism. 
---That is: Around 2,048 nodes that are only  00.122% of the possible range.
-- The user can increase the number to the 24 bit BUT Will take A LOT OF RESOURCES
-- and TIME (and when using 22 or more bits will be with brute force only). 
-- @args 	IPv6Prefix 	String - IPv6 Subnet ( PRefix MUST BE 64)
-- @args	HighPart	Table	- OUI candidates (the higher 24 bits Mac ddres)
-- @return 	Table		Total Hosts IPv6 address for the IPv6 Subnet (or Nil)
-- @return	String		Error message when there is one (Nil otherwise)
local getSlaacCandidates = function ( IPv6Prefix , HighPart ) 
	
	local hosts, sError =nil, ""
	local _, OUI, hexadecimal, bitsAlto
	local Metodo, NumBits = stdnse.get_script_args("itsismx.slaac.compute", "itsismx-slaac.nbits")
	local IPv6Base, IPv6Segmentos
	local FinalList, Candidate, Index = {}
	-- RFC 4291  The last 64 bits to create will have this format:
	
	  -- |0              1|1              3|3              4|4              6|
	  -- |0              5|6              1|2              7|8              3|
	  -- +----------------+----------------+----------------+----------------+
	  -- |ccccccugcccccccc|cccccccc11111111|11111110mmmmmmmm|mmmmmmmmmmmmmmmm|
	  -- +----------------+----------------+----------------+----------------+
	  
	-- Where "C" are the bits of HighPart,  "m" are the  bits we are to create 
	-- and "u" & "g" are bits to overlap the one from Highpart ( for this script 
	--  will be  10) 
	
	-- There should be special Candidates, thoses will be the one from 
	-- known virtual machines. On those cases "HIGHParth"  would be longer than 24 bits
	-- (Actually the general values  come as a string XXXXXX  so, 
	-- any longer 6 character will be "Special" BUT the user could make the mistake of use 
	-- introduce 6 hex digits from a special case. 
	
	-- Though with 22 bits we are covering only 12.5% of possibe address, we are talkign about
	-- a lookup table of 4 million when we are using random mechanism ( yep, there is a special 
	-- table for control duplicates). 
	if NumBits == nil then  
		 -- Actually this is a little redundant but better a strict control than nothing
		 NumBits = 11  
	elseif tonumber(NumBits) < 2 then 
		NumBits = 2
		sError = "Was add a very small value to nbits. Was fixed to 2"
	elseif tonumber(NumBits) > 24 then 
		NumBits = 24
		Metodo = "brute"
		sError = "Was add a very high value to nbits. Was fixed to 24"
	elseif tonumber(NumBits) > 21 and tonumber(NumBits) <= 24  then
		Metodo = "brute"
	end
	
	-- We begin with the OUI candidates, and for each group we'll try to add them 
	-- to our IPv6 subnets	
	for _ , OUI in ipairs(HighPart) do 
		math.randomseed ( nmap.clock_ms() ) -- We are going to use  Random  values, so Seed!
		if #OUI == 6 then -- Our clasic case! (And some Virtual  mahcines cases too)
			
			--print( "XXDS " .. OUI )
			hexadecimal = tonumber(OUI,16) 
			--print( "XXDS " .. hexadecimal )
			hexadecimal =  bit32.replace( hexadecimal , 2,16,2) -- This or AND
			bitsAlto = itsismx.DecToHex( hexadecimal) -- This ignore the high part...
			
			-- The XXXXXX10...XXXb make alway the string to be 5 or 6 hexadecimals
			while #bitsAlto < 6 do
				bitsAlto = "0" .. bitsAlto
			end
			
			-- We begin to create the  hosts ranges! We already have the first 88 bits
			-- Sp we only need to create the last 24 (The prefix is going to be override on the 
			-- next lines)
			IPv6Base, sError = ipOps.expand_ip(IPv6Prefix)
			if ( sError ~= nil ) then -- Weak point if the IPv6 address  is bad formed
				return nil, sError
			end
			-- Format to:   XXXX:XXXX:XXXX:XXXX:MMMM:MMFF:FE??:????			
			IPv6Segmentos = ipOps.get_parts_as_number(IPv6Base)
			IPv6Base = itsismx.DecToHex(IPv6Segmentos[1]) .. ":" .. itsismx.DecToHex(IPv6Segmentos[2]) .. ":" .. 
			           itsismx.DecToHex(IPv6Segmentos[3]) .. ":" .. itsismx.DecToHex(IPv6Segmentos[4]) .. ":" .. 
					   bitsAlto:sub(1,4) .. ":" .. bitsAlto:sub(5,6) .. "ff:fe"
			

			-- Random or Brute mechanism?
			if Metodo == nil then
				hosts = Random_Range(IPv6Base,NumBits )
				Metodo = "random"
			elseif Metodo == "random" then
				hosts = Random_Range(IPv6Base,NumBits )
			elseif Metodo == "brute" then
				hosts = Brute_Range(IPv6Base,NumBits )
			else	-- ERROR!
				return nil, "ERROR: The compute mechanism is incorrect: " .. Metodo
			end
			
			--There is a chance the host table will be empty, this a premature error
			if hosts == nil then
				sError =  "\n There was a error with the Prefix:  "  .. IPv6Prefix .. 
						" or maybe with the OUI: " ..  HighPart .. 
						" you can use -dddd for more information"
			end
		
		elseif (OUI == "VMware-Alls" ) then  --VMware Cases!
			-- Actually VMware has two specific cases: 
			--	Manually configured MAC address of the VMs: 00:50:56:XX:YY:ZZ
			-- 	Dynamic  configured MAC address of the VMs: 00:0C:29:WW:TT:UU
			
			hosts = Vmware_Range_000C29(IPv6Prefix,NumBits, Metodo  )
			
			-- Uh... we need to get ready hosts ofr the next one...
			if hosts ~= nil then
				for Index , Candidate in ipairs(hosts)  do table.insert(FinalList, Candidate) end
			else 
				sError =  " \n The compute of VMware 00:0C:29:WW:TT:UU had a error for the prefix  "  .. 
						IPv6Prefix .. " you can use -dddd for find the error (probably human)."
			end
			math.randomseed ( nmap.clock_ms() ) -- We update the Seed again.
			hosts = Vmware_Range_005056 (IPv6Prefix,NumBits )
			
			if hosts == nil then
				sError =  " The compute of VMware 00:50:56:XX:YY:ZZ had a error for the prefix  "  .. 
						IPv6Prefix .. " you can use -dddd for find the error (probably human)."
			end
		elseif (OUI == "VMware-Static" ) then --VMware Static MAC address assignation. 
			hosts = Vmware_Range_005056 (IPv6Prefix,NumBits )
			if hosts == nil then
				sError =  " The compute of VMware 00:50:56:XX:YY:ZZ had a error for the prefix  "  .. 
						IPv6Prefix .. " you can use -dddd for find the error (probably human)."
			end
		elseif (OUI == "VMware-Dynamic" ) then --VMware Dynamic MAC address assignation. 
			hosts = Vmware_Range_000C29 (IPv6Prefix,NumBits )
			if hosts == nil then
				sError =  " The compute of VMware 00:0C:29:WW:TT:UU had a error for the prefix  "  .. 
						IPv6Prefix .. " you can use -dddd for find the error (probably human)."
			end
		end
	
		--We add those hosts to the final list for avoid lost them to the next round
		for Index , Candidate in ipairs(hosts)  do table.insert(FinalList, Candidate) end
	
	end
	
	if sError == nil then
		sError = ""
	end
	return FinalList, sError
	--return FinalList, "RAYOS"
end

---
-- This will search for the OUI of a specific company  and will return a list 
-- for each field find, can receive a valid format OUI but will not try to valid it.
-- @args	Vendedores		Table/String - A list of vendors/OUI to add to the scan.
-- @args	MacList			Table - A list of the Valid OUI with Companies name.
-- @return	Table			A list of valid OUI (6 Hexdecimal numbers) otherwise nil
local getMacPrefix = function ( Vendedores, MacList   ) 

	local sLista, hLista = {},{}
	local hMac, sID, _, sUserMac
	
	if type(Vendedores) ==  "string" then  -- This only make the search easy...
		table.insert(sLista, Vendedores)   
	elseif type(Vendedores) ==  "table" then 
		sLista = Vendedores
	else 
		return nil
	end
	
	-- This is a good place for look for the special case that are the VM 
	-- Virtual Box and Parallels are easy, is just add theirs OUI  to the list
	-- Vmware is a little more complex .
	-- However the user could try to detect only 
	
	-- Now we search for the vendors in the Table. WE SEARCH ALL THE TABLE   not only the first
	-- option. Why? Because some vendors can have more than one registry.
	for _, sUserMac in pairs ( sLista)  do 
		sUserMac = sUserMac:lower()
		
		--There is two cases, a name or a full OUI, the problem the OUI is only hexadecimal of 
		-- 6 Charactes the other isn't it, so IF there is any companie which has exactly that 
		-- will cause a False positive (But nah!).
		if itsismx.Is_Valid_OUI(sUserMac ) then 
			
				table.insert(hLista,sUserMac )
				stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					": " .. " Was added the OUI  " ..   sUserMac .. " provided by the user. "   )
			
		else  -- Name of a companie
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
				": " .. " Were addedd  " ..   #hLista .. " OUI for the vendor: " .. sUserMac  )
		
		
		end
		
		
	end
	
	
	
	return hLista
end

---
-- This is the nasty part of the code. Here we prepare everything to be calculated. 
-- the user can provided one or more OUI,  one or more VM  or nothing 
-- (By Default is calculated Dell computers only, if VM option is provided  the DELL 
--  will be discarded. )
-- @return  Table  	Potential hosts IPv6 address (Nil if there was error)
-- @return  String	String of error if there was something to happen, 
--					otherwise nil
local Prescanning = function ()

	local MacList, PrefixAux, _
	local bSalida, tSalida = false , { Nodos={}, Error=""}
	local MacUsers,IPv6User,VM  = stdnse.get_script_args("itsismx.slaac.vendors","itsismx-subnet","itsismx.slaac.vms")
	local IPv6Knowns = nmap.registry.itsismx.PrefixesKnown
	local PrefixHigh, IPv6Total = {}, {}
	local IPv6_Add, IPv6_Prefix 
	-- Actu
	
	stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Pre-scanning work... "    )
	
	-- First, we retrieve the MAC address list 
	bSalida, MacList = datafiles.parse_mac_prefixes ()
	
	-- We don't have anything to fail on this...
	-- We don't use Try/Catch because we don't need to clean any mesh
	if not bSalida then 
		tSalida.Error = " The Mac Prefixes file wasn't find!"
		return bSalida, tSalida
	end
	
	
	
	-- Now we must retrieve the Prefixes given by the user and retrieve the total numbers
	-- if the user didn-t give one we are going to use a Default. 
	-- There is too, the option the user give a OUI for search a specify one   
	-- So, we are going to validate that. 
	if (MacUsers == nil ) then
		-- IF the user has the argument for virtual machines we don't add anything
		if  VM == nil then		 
			PrefixHigh = getMacPrefix( "DELL",MacList  )
		end
	else
		PrefixHigh = getMacPrefix( MacUsers,MacList  )
	end
	
	-- We search for the virtual Machine argument
	-- Except the VMware technologies all the other VMs plataforms  generate the lower part
	-- with random values, so truly don-t are very different to the "general case"
	local sVM = " Was added the next VM plataforms to the search: " 
	if  VM ~= nil then	
		
		if type(VM) == "number" then -- Default case (Strange, but if the argument is empty is a number) 
			table.insert(PrefixHigh, "VMware-Alls") 
			table.insert(PrefixHigh, "001C42")
			table.insert(PrefixHigh, "001851")
			table.insert(PrefixHigh, "080027")
			table.insert(PrefixHigh, "525400")
			
			sVM = sVM .. " VMware VMs, Virtual Box VMs, Parallels Virtuozzo & Desktop VMs, Microsoft Virtual PC VMs, Linux QUEMU VMs"  
		else --WPVML 
		
			-- are very simple. --WPVML
			if VM:find("W") then  --VMware case
				table.insert(PrefixHigh, "VMware-Alls") -- will work in other part.
				sVM = sVM .. " VMware VMs ," 
			elseif VM:find("wS") then  --VMware Static/Manual assignation
				table.insert(PrefixHigh, "VMware-Static") -- will work in other part.
				sVM = sVM .. " VMware VMs (Manual) ," 
			elseif VM:find("wD") then  --VMware Static/Manual assignation
				table.insert(PrefixHigh, "VMware-Dynamic") -- will work in other part.
				sVM = sVM .. " VMware VMs (Dynamic) ," 
			end
			

			
			if VM:find("P") then  --Parallels  case
				-- Are two special cases to add, so will work in other part.
				table.insert(PrefixHigh, "001C42")
				table.insert(PrefixHigh, "001851")
				sVM = sVM .. " Parallels Virtuozzo & Desktop VMs ," 
			elseif VM:find("pV") then 
				table.insert(PrefixHigh, "001851") --Parallels  Virtuozzo 
				sVM = sVM .. " Parallels Virtuozzo VMs ," 
			elseif VM:find("pD") then 
				table.insert(PrefixHigh, "001C42") --Parallels  Desktop
				sVM = sVM .. " Parallels Desktop VMs ," 
			end
			
			if VM:find("V") then  -- Virtual-Box case
				table.insert(PrefixHigh, "080027")
				sVM = sVM .. " Virtual Box VMs ," 
			end
			
			if VM:find("M") then  --Virtual PC case
				table.insert(PrefixHigh, "VMware-Alls")
				sVM = sVM .. " Microsoft Virtual PC VMs ," 
			end
			
			if VM:find("L") then  --QEMU case
				table.insert(PrefixHigh, "525400")
				sVM = sVM .. " Linux QUEMU VMs" 
			end
		
		
		end
		
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": "  .. sVM )
	end
	
	-- Now we must retrieve the total number of PRefix  to which uses the previous data 
	bSalida = false
	if IPv6User == nil and IPv6Knowns == nil then 
		tSalida.Error = "There is not IPv6 subnets to try to scan!. You can run a script for discovering or adding your own" ..  
							"  with the arg: itsismx-subnet."
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
			
			tSalida.Nodos,tSalida.Error = getSlaacCandidates ( IPv6_Add , PrefixHigh ) 
			
		end
	end
	
	return true, tSalida
end

---
-- This a gently wind of the script, will save the host to the final register (The 
--  only purpose of this nasty script)
local Hostscanning = function( host)
	local tSalida = { Nodos=nil, Error=""}
	local aux
	
	-- Only for the braves ... 
	stdnse.print_debug(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Host-scanning results... " )    
	
	-- Should be impossible, but better be sure and cover this
	if nmap.registry.itsismx == nil then 
		tSalida.Error = "You must first initialize the global register Itsismx (There is a global function for that!)"
		return false, tSalida
	end	
	
	aux = nmap.registry.itsismx.sbkmac
	if aux == nil then 
		tSalida.Error = "The global register Itsismx wasn't initialzed correctly (There is a global function for that!)"
		return false, tSalida
	end
	
	--We use the aux for be able to add a new element to the table
	aux[#aux +1] = host.ip
	nmap.registry.itsismx.sbkmac = aux
	
	tSalida.Nodos = host.ip 	-- This rule ALWAY IS ONE ELEMENT!
	
	return true, tSalida
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
	local Nodes = {} -- Is a Auxiliar 
	itsismx.Registro_Global_Inicializar("sbkmac") -- Prepare everything!
	
	
	-- The aciton is divided in two parts: Pre-scanning and host scanning.
	-- The first choice the tentative hosts to scan and the second only 
	-- confirm which are truly up.
	if ( SCRIPT_TYPE== "prerule" ) then
		bExito , tSalida = Prescanning()
		-- Now we adapt the exit to tOutput and add the hosts to the target!
		tOutput.warning = tSalida.Error 
		
		if bExito then
			--local a,b
			--print( "INICIO")
			--for a,  b in ipairs(tSalida.Nodos) do print( a .. " " .. b) end
			
			for _,  sHostsPre in ipairs(tSalida.Nodos) do
				bHostsPre, sTarget = target.add(sHostsPre)
				if bHostsPre then --We add it!

					--IF everything is well tSalida.Nodos & Nodes are the 
					--same size BUT we must be sure the nodes are added to 
					-- the host scan phase.
					table.insert(Nodes, sHostsPre)
					
				else 
					tOutput.warning = tOutput.warning .. " \n" .. sTarget
				end
			end
		
			--Final report of the Debug Lvl of Prescanning
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
								" Temptative address based on SLAAC added to the scan:" ..  #tSalida.Nodos .. 
								"\n Succesful address based on SLAAC added to the scan:" ..  #Nodes )
			-- We add those to the global registry
			-- We don't add those nodes to the standard exit BECAUSE ARE TEMPTATIVE ADDRESS
			nmap.registry.slaac_PreHost = Nodes 
			table.insert(tOutput, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ":  Were added " .. #Nodes .. 
							" nodes to the host scan phase" )
			
		end
	
	elseif ( SCRIPT_TYPE== "hostrule" )  then
		 bExito , tSalida = Hostscanning(host)
		 tOutput.warning = tSalida.Error
		 
		 if ( bExito ~= true) then
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
								" Error: " .. tSalida.Error)
		 end
		 
		 tOutput.name = "Host online - IPv6 address SLAAC"
		table.insert(tOutput,tSalida.Nodos) --This will be alway one single host.
	end 
	
	return stdnse.format_output(bExito, tOutput);	
end