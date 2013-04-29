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
  This is the most simple and easier of all the scripts. 
  The objective is to do a discover based on dictionary.  
  
  For each prefix we discover, we are going to check 
  against known hex-words.  ( EX. 2001:db8:c0ca::beef )
  
  P.d. The dictionary still need more entries for this 
  script become very useful. 
]]

---
-- @usage
-- nmap -6 --script itsismx-slaac --script-args newtargets
--
-- @output



-- @args newtargets  MANDATORY Need for the host-scaning to succes 
-- @args itsismx-subnet 	(Optional)	IT's table/single  IPv6 address with prefix
--	   (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )

-- Version 1.0
-- 	Created 29/04/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam@gmail.com>
--

--- 
-- Get a Prefix and for that one will add all the valids  words  we known.
local CrearRangoHosts = function (Direccion, Prefijo, TablaPalabras ) 
	
	local IPv6Bin, Error   = ipOps.ip_to_bin (Direccion )
	local Candidatos, sError = {} , ""
	local Indice, Palabras, MaxRangoSegmentos, Filler, Host

	local User_Segs, User_Right = stdnse.get_script_args("itsismx.wordis.nsegments","itsismx.wordis.fillright" )
	if IPv6Bin == nil then	--Niagaras!
		return false, {}, Error
	end
	
	-- Its simple, we have (128 -  n ) / ( 16 )
	-- The first part are how many bits are left to hosts portion 
	-- the Second are the siz of the segments ( 16 bits). 
	-- We need to use Ceiling because 4.3  don't have sense... 
	if (User_Segs ~= nil  ) then
		MaxRangoSegmentos  = math.ceil( (128 - Prefijo)/16 )
		User_Segs = false
	else 
		MaxRangoSegmentos  = tonumber(User_Segs) 
	end
		
	stdnse.print_debug(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					":  Will be add " .. #TablaPalabras .. "  hosts for the subnet: " .. Direccion .. "/" .. Prefijo  )
	
	-- Palabras is a table with two elements Segmento & Binario
	for  Indice , Palabras in ipairs(TablaPalabras ) do
		--print("\t\t [" .. Indice .. "] " .. #Palabras )
		
		if ((tonumber( Palabras.Segmento) <= MaxRangoSegmentos ) and User_Segs == false )  or 
			(User_Segs and  (tonumber( Palabras.Segmento) == MaxRangoSegmentos )  )then
			-- We are going to add binaries values but the question is 
			-- whene must fill with zeros?
			Filler = ""
			--print("\t\t Filler Size " ..  #Filler )
			while (Prefijo + #Filler + #Palabras.Binario  ) < 128 do
				if (User_Right ~= nil ) then
					Filler = "0" ..Filler
				else
					Filler = Filler .. "0"
				end
			end
			
			Host = IPv6Bin:sub(1, Prefijo) .. Filler .. Palabras.Binario
			--print("\t\t Host (B) " ..  Host .. " " .. #Host) 
			
			-- We pass the binaries to valid IPv6
			Host, Error = ipOps.bin_to_ip(Host)
			if Host == nil then	-- Something is very wrong but we don-t stop
				sError = sError .. "\n" .. Error
			else 
				--print("\t\t Host: " .. Host ) 
				table.insert(Candidatos , Host )
				stdnse.print_debug(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					":  Added IPv6 address " .. Host .. " to the host scanning list...")	
			end
		end
	end
	
	return true, Candidatos, sError
end
---
-- The heart of this script...
-- This is the parsing process (but for now is very crude) will search for the file
-- and  return only the binaries numbers (String)  that matches with the number of 
-- segments we want to use.
-- @args	Number	(Optional) Range of segments to search on the file.
-- @return	Table	Table of elements returned (Nil if there was a error )
-- @return	String	Empty if there is no error, otherwise will have the error message. 
local LeerArchivo = function ( RangoSegmentos )
-- [ "^%s*(%w+)%s+[^#]+" ] = "^%s*%w+%s+([^#]+)" }
	local bBoolean, Archivo = datafiles.parse_file("nselib/itsismx-words-known",{  "^[^#]+%d" }) 
	local index, reg, token
	local Candidatos = {}
	local Registro  = { ["Segmento"]=0, ["Binario"]="0"}
	local sMatch = {}
	--print(bBoolean )
	print (Archivo )
	
	if bBoolean ~= true  then
		return nil , Archivo
	end
	
	for index, reg in pairs(Archivo) do
		print  ("[" ..  index .. "]  "  .. reg)
		
		-- The structure is very well'known:  Digit  Word  Binary
		sMatch = {}
		Registro  = { ["Segmento"]=0, ["Binario"]="0"}
		for token in  reg:gmatch("%w+" ) do  
			--print("\t" .. token)
			sMatch[#sMatch+1] = token
		end
		--print(#sMatch)
	
		Registro.Segmento = sMatch[1]
		Registro.Binario = sMatch[3]
		table.insert( Candidatos, Registro )
		
		-- We are going to add only the Binaries values but we are going to 
		-- use  the number of segments as indicator.
		--if RangoSegmentos == nil then -- all the possibles words! 
		--	table.insert(Candidatos,sMatch[3])
		--elseif ( tonumber(sMatch[1]) <= RangoSegmentos) then 
		--	table.insert(Candidatos,sMatch[3])
		--	end
			
	end
	
	-- print(" Candidatos ")
	-- reg = {}
	-- for index, reg in pairs(Candidatos) do
		-- print  ("[" ..  index .. "]  "  .. reg.Binario)
	-- end	
	
	return Candidatos, ""

end


--  This is  very simple actually, we get the info we need from the user and other scripts
--- then we add them to our file! (So easy that seem we need to make them obscure)
local Prescanning = function ()
	local bSalida, tSalida = false , { Nodos={}, Error=""}
	local IPv6PRefijoUsuario  = stdnse.get_script_args("itsismx-subnet")
	local IPv6PRefijoScripts  = nmap.registry.itsismx.PrefixesKnown
	local  TablaPalabras, sError, IPv6refijosTotales  = {}, "",{}
	local PrefixAux, Prefijo,  Direccion
	local Hosts = {}
	-- First we get the info from known prefixes because we need those Prefixes
	stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Pre-scanning work... "    )
	
	-- Second, we read our vital table
	 TablaPalabras = LeerArchivo()
	
	if TablaPalabras == nil then
		tSalida.Error = sError
		return bSalida, tSalidas
	end
	
	-- We pass all the prefixes to one single table (health for the eyes)
	if IPv6PRefijoUsuario == nil and IPv6PRefijoScripts == nil then 
		tSalida.Error = "There is not IPv6 subnets to try to scan!. You can run a script for discovering or adding your own" ..  
							"  with the arg: itsismx-subnet."
		return bSalida, tSalida
	end
	
	if IPv6PRefijoScripts ~= nil then
		stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"	Number of Prefixes Known from other sources: " .. #IPv6PRefijoScripts    )		
		for _ , PrefixAux in ipairs(IPv6PRefijoScripts) do 
			table.insert(IPv6refijosTotales,PrefixAux )	
		end		
	end
	
	if IPv6PRefijoUsuario ~= nil then
		if type(IPv6PRefijoUsuario) ==  "string" then 
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"	Number of Prefixes Known from other sources: 1 "     )
			table.insert(IPv6refijosTotales,IPv6PRefijoUsuario )
		elseif type(IPv6PRefijoUsuario) ==  "table" then
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				"	Number of Prefixes Known from other sources: " .. #IPv6PRefijoUsuario    )		
			for _ , PrefixAux in ipairs(IPv6PRefijoUsuario) do -- This is healthy for my mind...
				table.insert(IPv6refijosTotales,PrefixAux )	
			end	
		end
			
	end
	
	stdnse.print_debug(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..  
			 " Will be calculated a total of " ..  #IPv6refijosTotales *  #TablaPalabras .. " hosts") 
	
	-- We begin to explore all thoses prefixes and retrieve our work here
	for _, PrefixAux in ipairs(IPv6refijosTotales) do
		 Direccion, Prefijo = itsismx.Extract_IPv6_Add_Prefix(PrefixAux)
		 bSalida, Hosts, sError  = CrearRangoHosts (Direccion, Prefijo, TablaPalabras ) 
	end
	
	
	
	
end

-- The script need to be working with IPv6
prerule = function() return ( nmap.address_family() == "inet6") end

---
-- We need to confirm the host is one of the previous pre-scanning phase nodes  
-- and return true.
hostrule = function(host) 
	--Debug
	 -- local key, elemento 
	  -- for key, elemento in pairs(nmap.registry.args) do
		  -- print(key, elemento)
	 -- end

	local  Totales, Objetivo, bMatch, sMatch  = nmap.registry.wordis_PreHost	
	
	
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

action = function(host)
	
	--Vars for created the final report
	local tOutput = {} 
	tOutput = stdnse.output_table()
	local bExito = false
	local tSalida =  { Nodos={}, Error=""}
	local  bHostsPre, sHostsPre 
	local Nodes = {} -- Is a Auxiliar 
	
	itsismx.Registro_Global_Inicializar("wordis") -- Prepare everything!
	
	-- The aciton is divided in two parts: Pre-scanning and host scanning.
	-- The first choice the tentative hosts to scan and the second only 
	-- confirm which are truly up.
	if ( SCRIPT_TYPE== "prerule" ) then
		
		bExito , tSalida = Prescanning()
		
		-- Now we adapt the exit to tOutput and add the hosts to the target!
		tOutput.warning = tSalida.Error 
		
		if bExito then
			for _,  sHostsPre in ipairs(tSalida.Nodos) do
				bHostsPre, sTarget = target.add(sHostsPre)
				if bHostsPre then --We add it!
					table.insert(Nodes, sHostsPre)
				else -- Bad luck  
					tOutput.warning = tOutput.warning .. " \n" .. sTarget
				end
			end
		
			--Final report of the Debug Lvl of Prescanning
			stdnse.print_debug(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
								" Temptative address based on SLAAC added to the scan:" ..  #tSalida.Nodos .. 
								"\n Succesful address based on SLAAC added to the scan:" ..  #Nodes )
			
			-- We don't add those nodes to the standard exit BECAUSE ARE TEMPTATIVE ADDRESS
			nmap.registry.wordis_PreHost = Nodes 
			table.insert(tOutput, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ":  Were added " .. #Nodes .. 
							" nodes to the host scan phase" )
		
		end
	end
	
end
