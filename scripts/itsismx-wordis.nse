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
--	Pre-scan script results:
--	| itsismx-wordis:
--	|_  itsismx-wordis.prerule:  Were added 4 nodes to the host scan phase

--	Host script results:
--	| itsismx-wordis:
--	| Host online - IPv6 address SLAAC
--	|_  2001:db8:c0ca::dead

-- @args newtargets  				MANDATORY Need for the host-scaning to success 
-- @args itsismx-wordis.nsegments	(Optional) Number  - User can indicate exactly 
--									how big the word must be (Segments of 16 bits) 
-- @args itsismx-wordis.fillright	(Optional) With this argument the script will fill 
--									remaining zeros to the right instead of left 
--									(2001:db8:c0a:dead:: instead of 2001:db8:c0ca::dead)

-- @args itsismx-subnet 	(Optional)	IT's table/single  IPv6 address with prefix
--	   (Ex. 2001:db8:c0ca::/48 or { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )

-- Version 1.0
-- 	Created 29/04/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam@gmail.com>
--

author = "Raul Fuentes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

dependencies = {"itsismx-dhcpv6"}

--- 
-- Get a Prefix and for that one will add all the valid  words  we known.
-- However two arguments from the user can affect how calculated the hosts.
-- n-segments fix to pick a number of segments (by default is any segment
-- enough small for be inside of the subnet prefix) and  fill-right
-- which alter where we place the remaining zeros (DEfault the left).
-- @args Direccion		String	IPv6 address (Subnet)
-- @args Prefijo		Number	Prefix value of subnet
-- @args TablaPalabras	Table containing all the elements to search.
-- @return	Boolean		True if was successful the operation
-- @return	Table		The table with the valid host for the prefix.
-- @return	Error		Any error OR problem will be here (Default: "" not nil ) 
local CrearRangoHosts = function (Direccion, Prefijo, TablaPalabras, User_Segs, User_Right ) 
	
	local IPv6Bin, Error   = ipOps.ip_to_bin (Direccion )
	local Candidatos, sError = {} , ""
	local Indice, Palabras, MaxRangoSegmentos, Filler, Host

	
	if IPv6Bin == nil then	--Niagaras!
		return false, {}, Error
	end
	
	-- Its simple, we have (128 -  n ) / ( 16 )
	-- The first part are how many bits are left to hosts portion 
	-- the Second are the size of the segments ( 16 bits). 
	-- We need to use Ceiling because 4.3  don't have sense... 
	if (User_Segs == nil  ) then
		MaxRangoSegmentos  = math.ceil( (128 - Prefijo)/16 )
		User_Segs = false
	else 
		MaxRangoSegmentos  = tonumber(User_Segs) 
	end
		
	stdnse.print_verbose(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
					":  Will be calculted " .. #TablaPalabras .. "  hosts for the subnet: " .. Direccion .. "/" .. Prefijo  )
	
	-- Palabras is a table with two elements Segmento & Binario
	for  Indice , Palabras in ipairs(TablaPalabras ) do

		if ((tonumber( Palabras.Segmento) <= MaxRangoSegmentos ) and User_Segs == false )  or 
			(User_Segs and  (tonumber( Palabras.Segmento) == MaxRangoSegmentos )  )then
			-- We are going to add binaries values but the question is 
			-- whene must fill with zeros?
			Filler = ""
			while (Prefijo + #Filler + #Palabras.Binario  ) < 128 do
				Filler = "0" ..Filler
			end
					
			if (User_Right ~= nil ) then
				Host = IPv6Bin:sub(1, Prefijo)  .. Palabras.Binario .. Filler
			else
				Host = IPv6Bin:sub(1, Prefijo) .. Filler .. Palabras.Binario
			end
				
			-- We pass the binaries to valid IPv6
			Host, Error = ipOps.bin_to_ip(Host)
			if Host == nil then	-- Something is very wrong but we don-t stop
				sError = sError .. "\n" .. Error
			else 
				table.insert(Candidatos , Host )
				--stdnse.print_verbose(5, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				--	":  Added IPv6 address " .. Host .. " to the host scanning list...")	
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

	if bBoolean ~= true  then
		return nil , Archivo
	end
	
	for index, reg in pairs(Archivo) do		
		-- The structure is very well'known:  Digit  Word  Binary
		sMatch = {}
		Registro  = { ["Segmento"]=0, ["Binario"]="0"}
		for token in  reg:gmatch("%w+" ) do  
			sMatch[#sMatch+1] = token
		end

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
	
	return Candidatos, ""

end

---
--  This is  very simple actually, we get the info we need from the user and other scripts
-- then we add them to our file! (So easy that seem we need to make them obscure)
local Prescanning = function ()
	local bSalida, tSalida = false , { Nodos={}, Error=""}
	local IPv6PRefijoUsuario  = stdnse.get_script_args("itsismx-subnet")
	local IPv6PRefijoScripts  = nmap.registry.itsismx.PrefixesKnown
	local  TablaPalabras, sError, IPv6refijosTotales  = {}, "",{}
	local PrefixAux, Prefijo,  Direccion
	local Hosts, Nodo, Indice = {}
	local User_Segs, User_Right = stdnse.get_script_args("itsismx-wordis.nsegments","itsismx-wordis.fillright" )
	
	-- First we get the info from known prefixes because we need those Prefixes
	stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
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
		stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				":	Number of Prefixes Known from other sources: " .. #IPv6PRefijoScripts    )		
		for _ , PrefixAux in ipairs(IPv6PRefijoScripts) do 
			table.insert(IPv6refijosTotales,PrefixAux )	
		end		
	end
	
	if IPv6PRefijoUsuario ~= nil then
		if type(IPv6PRefijoUsuario) ==  "string" then 
			stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				":	Number of Prefixes Known from other sources: 1 "     )
			table.insert(IPv6refijosTotales,IPv6PRefijoUsuario )
		elseif type(IPv6PRefijoUsuario) ==  "table" then
			stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				":	Number of Prefixes Known from other sources: " .. #IPv6PRefijoUsuario    )		
			for _ , PrefixAux in ipairs(IPv6PRefijoUsuario) do -- This is healthy for my mind...
				table.insert(IPv6refijosTotales,PrefixAux )	
			end	
		end
			
	end
	
	-- stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..  
			 -- " Will be calculated a total of " ..  #IPv6refijosTotales *  #TablaPalabras .. " hosts") 
	
	-- We begin to explore all thoses prefixes and retrieve our work here
	for _, PrefixAux in ipairs(IPv6refijosTotales) do
		 Direccion, Prefijo = itsismx.Extract_IPv6_Add_Prefix(PrefixAux)
		 bSalida, Hosts, sError  = CrearRangoHosts (Direccion, Prefijo, TablaPalabras, User_Segs, User_Right ) 
		 
		 if bSalida ~= true then
			stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
				":	There was a error for the prefix: " .. PrefixAux .. " Message:"  ..  sError )
		 end
		 
		 if sError ~= "" then -- Not all the error are fatal for the script.
			tSalida.Error = tSalida.Error .. "\n" .. sError
		 end
		 
		 -- Now we add the discovered hosts to the final list. 
		 for Indice, Nodo in ipairs(Hosts) do
			table.insert( tSalida.Nodos, Nodo)
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
	stdnse.print_verbose(4, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
			": Begining the Host-scanning results... " )    
	
	-- Should be impossible, but better be sure and cover this
	if nmap.registry.itsismx == nil then 
		tSalida.Error = "You must first initialize the global register Itsismx (There is a global function for that!)"
		return false, tSalida
	end	
	
	aux = nmap.registry.itsismx.wordis
	if aux == nil then 
		tSalida.Error = "The global register Itsismx wasn't initialzed correctly (There is a global function for that!)"
		return false, tSalida
	end
	
	--We use the aux for be able to add a new element to the table
	aux[#aux +1] = host.ip
	nmap.registry.itsismx.wordis = aux
	
	tSalida.Nodos = host.ip 	-- This rule ALWAY IS ONE ELEMENT!
	
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
	
	return true
end

---
-- We need to confirm the host is one of the previous pre-scanning phase nodes  
-- and return true.
hostrule = function(host) 
	local  Totales, Objetivo, bMatch, sMatch  = nmap.registry.wordis_PreHost	

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
	local Nodes = {} -- Is a Auxiliar 
	
	itsismx.Registro_Global_Inicializar("wordis") -- Prepare everything!
	
	-- The action is divided in two parts: Pre-scanning and host scanning.
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
			stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
								" Temptative address based on words added to the scan:" ..  #tSalida.Nodos .. 
								"\n Succesful address based on words added to the scan:" ..  #Nodes )
			
			-- We don't add those nodes to the standard exit BECAUSE ARE TEMPTATIVE ADDRESS
			nmap.registry.wordis_PreHost = Nodes 
			table.insert(tOutput, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ":  Were added " .. #Nodes .. 
							" nodes to the host scan phase" )
		
		end
	end
	
	if SCRIPT_TYPE== "hostrule" then 
		bExito , tSalida = Hostscanning(host)
		 tOutput.warning = tSalida.Error
		 
		 if ( bExito ~= true) then
			stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
								" Error: " .. tSalida.Error)
		 end
		 
		 tOutput.name = "Host online - IPv6 address SLAAC"
		table.insert(tOutput,tSalida.Nodos) --This will be alway one single host.
	end
	
	return stdnse.format_output(bExito, tOutput);
	
end
