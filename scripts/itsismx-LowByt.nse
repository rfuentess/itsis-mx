local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local target = require "target"
local itsismx = require "itsismx"

description=[[
 Explore the network tryng to find  IPv6 Nodes using low-bytes. 
 Will try to use already known sub-networks of any range and if there
 are not one will check for one on the argumentos. If there are not 
 one  it's going to use  the first valid IPv6 prefix from the Client .
 
 The script run at pre-scanning phase and script phase (The first for 
 create tentative low-bytes address and the second for put the living
 nodes on the list of discovered nodes).
]]

---
-- @usage
-- nmap -6 --script itsismx-LowByt
--
-- @output
-- Pre-scan script results:
-- | itsismx-LowByt:
-- |_  itsismx-LowByt.prerule:  Were added 256 nodes to the scan
-- Nmap scan report for Muu.int-evry.fr (2001:db8:c0ca:1::a)
-- Host is up.

-- Host script results:
-- | itsismx-LowByt:
-- |_    2001:db8:c0ca:1::a


-- nmap.registry.itsismx.LowBytes.LowByt_PreHost Thought it-s a variable
--   isn't for the user but instead is for pass information from Pre-scanning 
--   script to  Host-scanning script
-- nmap.registry.itsismx.LowByt Is a global Registry (the final objective of this script)
--   will have all the valid IPv6 address discovered with this Script
-- 
-- @args itsismx-subnet 			(Optional)	IT's table/single  IPv6 address with prefix
--	   								(Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 })
-- @args itsismx-IPv6ExMechanism 	(Optional)Nmap don't do math operations with IPv6  because the 
--		 							big value of those address. We use own methods which are: 
--										"number"	- 4 Numbers of 32 bits (Mathematical operations)
--										"sring"		- (Default) 128 Characters on string  (Pseudo Boolean
--														operations)
-- @args itsismx-LowByt.nbits  		Indicate how many Bites to consider
--     								as low. Valid range: 3-16 (default 8 )
-- @args itsismx-LowByt.OverrideLock  TRUE: Will get ALL the posibles hosts, even if
--									that mean brute force of 96 bits. FALSE: Will not exced from 16 bits.
--      							By default it's False (any  value different to Nil will be take 
--									as "TRUE", except FALSE
-- @args newtargets  MANDATORY Need for the host-scaning to succes 


--
-- Version 1.0
-- 	Update 27/03/2013	- v 1.0 
-- 	Created 26/02/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam+itsismx@gmail.com>
--

author = "Raul Fuentes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

dependencies = {"itsismx-dhcpv6"}

---
-- This function will create all the host which can be formed from the range give 
-- Because the things can become BAD with a high number this is going to be truncated
-- ( 120-128) at least that OverrideLock (User agument) it's set. 
-- @args	IPv6PRefix	A String/Table IPv6 address with Prefix: X:X:X::/YY
-- @args	Prefix		Prefix number (0-128)
-- @return	Table		Table with valids host from the IPv6Prefix with low-bytes
local IPv6_Create_HostsRange = function( IPv6Address, Prefix) 
	local TheLast, TheNext
	local Hosts = {}
	
	
	TheNext, TheLast = ipOps.get_ips_from_range(IPv6Address .. "/" .. Prefix)
	
	-- This can be affected by itsismx-IPv6ExMechanism
	local IPv6ExMechanism = stdnse.get_script_args( "itsismx-IPv6ExMechanism" )

	
	-- Now the hard part...   numbers in NSE (LUA 5.2) are limited to 10^14..
	-- So... we can0t do the easy life to pass to number and do the maths there...
	-- There are extras libraries for Lua 5.2 but aren't part of Nmap project (yet)
	-- we have only strings for do the things 
	repeat  
		table.insert(Hosts,TheNext)
		-- Testing local Number_Instead_String = false
		TheNext = itsismx.GetNext_AddressIPv6(TheNext,Prefix, IPv6ExMechanism)

	until not ipOps.ip_in_range(TheNext, IPv6Address .. "/" .. Prefix)
	return Hosts
end

---
-- This function must obtain all the nodes with the Low Bytes. From a IPv6/Prefix
-- @args	IPv6PRefix	A String/Table IPv6 address with Prefix: X:X:X::/YY
-- @args	NBits		How many bits we are to use 
-- @return 	Boolean		TRUE if the range was Ok. False if PRefix+NBits > 128
-- @return	Table		Table with valids host from the IPv6Prefix with low-bytes
-- @return  String		Error Message
local IPv6_GetLowBytesHost = function( IPv6PRefix , NBits)
	
	local TablaHost = {}
	local SubRed, Prefijo
	local bExito = false
	local sError = "";
	local LockBrute = stdnse.get_script_args( SCRIPT_NAME ..'OverrideLock')
	
	if 	LockBrute   ~=  nil then
		if s:lower(LockBrute) == "false" then --It-s odd  to happen but better be sure...
			LockBrute = false
		else
			LockBrute = true
		end
	end
	
	-- We can get Strings (single Address/PRefix) or Table (One or more Address/PRefix)
	if ( type(IPv6PRefix) ==  "string") then
			SubRed, Prefijo = itsismx.Extract_IPv6_Add_Prefix(IPv6PRefix)
		 
			-- We beegin to do the magic... 
			if Prefijo + NBits >= 128 then
				sError = " The give prefix (  " .. Prefijo .. 
				  " ) it-s too big for use the Bytes provided ( " ..  NBits .. " )"
				  return bExito, TablaHost , sError
			else
				Prefijo =  128-NBits
			end
			
			-- Low bytes mean a quick Brute force of hosts... Try to avoid other thing...
			if  not LockBrute   then  
				if Prefijo < 128-16 then 
					Prefijo = 128-16
					Error = "\t The prefix had to be cut to 112 for avoid  over-do"
				end
				
			end
			
			TablaHost = IPv6_Create_HostsRange(SubRed,Prefijo)
			
			stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. " Subnet/Prefix: " ..
					IPv6PRefix .. "\t Total low-bytes nodes (Using the last " .. 128 - Prefijo ..
					" bits ) found: " .. #TablaHost )
			
			bExito = true
	elseif ( type(IPv6PRefix) ==  "table") then
	
		local Hosts_Subred = {}
		local L,IPv6Subnet_Prefix 
		local TodoOk = true
		
		for L,IPv6Subnet_Prefix in ipairs(IPv6PRefix)  do
			
			Hosts_Subred = {}
			
			SubRed, Prefijo = itsismx.Extract_IPv6_Add_Prefix(IPv6Subnet_Prefix)
			
			
			if Prefijo + NBits >= 128 then
				sError = sError .. "\n\t The  prefix (  " .. Prefijo .. 
				  " ) it's too big for the Bytes provided ( " ..  NBits .. " )"
				  -- WE can/t stop there but we skip this Prefix 
				  TodoOk = false
				  stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. "\t Subnet/Prefix: " ..
					IPv6Subnet_Prefix .. " had a wrong total prefix: " .. Prefijo + NBits  )
				  
			else
			
				Prefijo =  128-NBits
				if  not LockBrute   then  
					if Prefijo < 128-16 then 
						Prefijo = 128-16
						Error = "The prefix had to be cut to 112 for avoid  over-do"
					end
				end
				
				
				
				Hosts_Subred = IPv6_Create_HostsRange(SubRed,Prefijo)

				stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. "\t Subnet/Prefix: " ..
					IPv6Subnet_Prefix .. " Total low-bytes nodes (Prefix " .. Prefijo ..
					" ) found: " .. #Hosts_Subred )				
				
				-- This is the best moment for adding those new hosts to a SINGLE TABLE 
				-- not a table with tables entires, but a table with strings
				for _,v in ipairs(Hosts_Subred) do  table.insert(TablaHost,v) end
				
			end
			
		end
	
		stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
							"\t Total low-bytes nodes calculated: " .. #TablaHost )	
		
		bExito = TodoOk
	else	--How this happened?
		sError = "IPv6PRefix must be a String or a table"
	
	end
	
	
	return bExito, TablaHost, sError
end

---
-- This is the core of the script. Is here where  we are adding groups of host by 
-- each prefix ( Only 3 bytes of each subnet)
-- @return Boolean 		TRUE si no se hallo problema alguno durante el proceso.
-- @return Table 		TABLA Listado de prefijos explorados y cantidad de bits en cada uno.
local PreScanning = function()

	local PrefijosUniversales = {} 	-- Formato esperado: X:X:X:X::/YY
	local PrefijosUsuario = {}		-- Formato esperado: X:X:X:X::/YY
	local NumBits = 8;				-- Formato esperado: 3-24
	local tSalida = { Nodos={}, Error=""}
	local bExito = false
	local Usuarios, Universales = {},{}
	local bUniv, sUniv, bUser, sUser = true, "", true, ""
	
	stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Pre-scanning work... "    )
	
	-- Existen 2 fuentes de Prefijos previos (No excluyentes):
	-- 1: Universales descubiertos por todo los scripts de la tesis
	-- 2: Provistos por el usuario mediante un argumento
	-- 3?: A partir de la interfaz de red del usuario  (Aunque solo sirve local)
	
	
	PrefijosUniversales = nmap.registry.itsismx.PrefixesKnown
	PrefijosUsuario, NumBits = stdnse.get_script_args('itsismx-subnet', 'itsismx-LowByt.nbits')
	
	if PrefijosUniversales == nil and PrefijosUsuario == nil then  --Esto si es muy malo
		tSalida.Nodos = {}
		tSalida.Error = " There are not any prefix to scan."
		return bExito, tSalida 
	elseif PrefijosUniversales == nil then -- Zero it-s better than Nil
		PrefijosUniversales = {}
	elseif PrefijosUsuario == nil then
		PrefijosUsuario = {}
	end
	
	
	-- By default we work with a Byte
	if NumBits == nil then  
		NumBits = 8
	elseif tonumber(NumBits) < 2 then 
		NumBits = 2
		tSalida.Error = "Was add a very small value to nbits. Was fixed to 2"
	elseif tonumber(NumBits) > 16 then 
		NumBits = 16
		tSalida.Error = "Was add a very high value to nbits. Was fixed to 16"
	end
	
	stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Numbers of bits we took as \"Low-bytes\": " ..  NumBits   )
	
	-- Damos preferencia a los universales y luego a los proveidos por el usuario.
	-- for _,Ruta in ipairs(PrefijosUniversales) do 
	if #PrefijosUniversales > 0 then 
		stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Number of  Subnets Known from other sources: " ..  #PrefijosUniversales   )
		bUniv, Universales, sUniv = IPv6_GetLowBytesHost(PrefijosUniversales, NumBits)
		for _,v in ipairs(Universales) do  table.insert(tSalida.Nodos,v) end 
	end
	-- end 
	--We have two options with  PrefijosUsuario String (ONE) or Table (One or more) 
	if   type(PrefijosUsuario) ==  "string"  and   #PrefijosUsuario > 0  then
		stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..  
							" Number of Subnets provided by  the user: 1"  )
				
		bUser, Usuarios, sUser = IPv6_GetLowBytesHost(PrefijosUsuario, NumBits)
		for _,v in ipairs(Usuarios) do  table.insert(tSalida.Nodos,v) end
		
	elseif (#PrefijosUsuario > 0) then
		stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..  
							" Number of  Subnets provided by  the user: " .. #PrefijosUsuario )
		bUser, Usuarios, sUser = IPv6_GetLowBytesHost(PrefijosUsuario, NumBits)
		for _,v in ipairs(Usuarios) do  table.insert(tSalida.Nodos,v) end
	end
	
	
	-- Now we have everything! except of course the final booleans...
	bExito = bUser and bUniv
	tSalida.Error = tSalida.Error .. "\n" ..  sUniv .. "\n" .. sUser
	
	return bExito, tSalida
end

---
-- All the nodes that come to this point were discovered by the pre-scanning function
-- So we only need to generate a final report 	
-- @return 	Boolean 			TRUE si no se hallo problema alguno durante el proceso.
-- @return 	Table 				(Salida estandar)TABLA Listado de prefijos explorados y 
--								  cantidad de bits en cada uno.
local HostScanning = function( host)
	
	local tSalida = { Nodos={}, Error=""}
	local aux
	
	--Each host is too much!
	stdnse.print_verbose(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Host-scanning results... "    )

	-- We are going to be sure don't do stupid thing on wrong register (Because we don't have
	-- handlres for working with registers)
	if nmap.registry.itsismx == nil then 
		tSalida.Error = "You must first initialize the global register Itsismx (There is a global function for that)"
		return false, tSalida
	end
	
	aux = nmap.registry.itsismx.LowByt
	if aux == nil then 
		
		tSalida.Error = "The global register Itsismx wasn't initialzed correctly (There is a global function for that)"
		stdnse.print_verbose(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			".WARNING: " ..  tSalida.Error  )
		return false, tSalida
	end

	--We use the aux for be able to add a new element to the table
	aux[#aux +1] = host.ip
	nmap.registry.itsismx.LowByt = aux
	table.insert(tSalida.Nodos,host.ip)
	
	
	return true, tSalida
end

---
-- The script need to be working with IPv6
prerule = function() 
	  if ( not(nmap.address_family() == "inet6") ) then
		stdnse.print_verbose("%s Need to be executed for IPv6.", SCRIPT_NAME)
		return false
	end
	
	if ( stdnse.get_script_args('newtargets')==nil ) then
		stdnse.print_verbose(1, "%s Will only work on pre-scanning. The argument newtargets is needed for the host-scanning to work.", SCRIPT_NAME)
	end
	
	return true end
---
-- This rule actually can do almost everything we need. "host" will be each host that is up
-- so we only need to confirm that host is one of the previous pre-scanning phase nodesand return 
-- true.
hostrule = function(host) 
	
	local  Totales, Objetivo, bMatch, sMatch  = nmap.registry.LowByt_PreHost	
	if Totales == nil  then return false end

	for _, Objetivo in pairs( Totales ) do
		
		bMatch, sMatch = ipOps.compare_ip(host.ip, "eq", Objetivo)
		if bMatch == nil then
			stdnse.print_verbose(1, "\t hostrule  had a error with " ..   
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
	
	itsismx.Registro_Global_Inicializar("LowByt")
	
	
	-- Lo mas sano es irnos por separar las acciones de cada fase.
	if ( SCRIPT_TYPE== "prerule" ) then
		bExito, tSalida = PreScanning()
		
	elseif ( SCRIPT_TYPE== "hostrule" ) then
		
		bExito, tSalida = HostScanning(host)

		
	else -- uh? (Can't happen but better cover this)
		tSalida[Error] = "The type of rule  isn't correct. You must review the description of the script."
		bExito = false;
	end
	

	
	-- Poblamos la tabla de salida 
	tOutput["warning"] = ""
	tOutput["name"] = ""
	if not bExito then 
		table.insert(tOutput, tSalida.Error)
	else -- Hay que recordar que esta tabla la comparten dos Fases de Nmap...
		
		if SCRIPT_TYPE== "prerule"  then	-- We add the to the  host phase scanning.
			tOutput["name"] = "LowByte: Pre-rule"
			
			bAdding, sHostsPre = target.add(table.unpack(tSalida.Nodos) )
			if bAdding == true then
				
				--stdnse.registry_add_array( "LowByt_PreHost", tSalida.Nodos) 
				nmap.registry.LowByt_PreHost  = tSalida.Nodos
				table.insert(tOutput, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ":  Were added " .. #tSalida.Nodos .. " nodes to the scan" )
				
				
				
				if #tSalida.Error ~= 0 then 
					tOutput.warning =  SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ":WARNING: There had been some lesser incovenient." .. 
							" You can use -d[d] for see the problem " 
				else 
					tOutput.warning = SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ":WARNING: Not all the nodes were able to place for the scanning pahe." .. 
							" Only " .. sHostsPre  
				end
				stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. "  finished."  )
			else
				bExito = false
				tOutput.warning = SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ": " .. sHostsPre
			end 
		
	
		elseif SCRIPT_TYPE== "hostrule" then -- Now we display the targets!
				tOutput["name"] = "Host online - Low-Byte "
				table.insert( tOutput , tSalida.Nodos  ) 
			
				if (#tSalida.Error == 0 ) then
					tOutput.warning = tSalida.Error
				end
				
				
		end 
	end
	 
	return stdnse.format_output(bExito, tOutput);
	

end
