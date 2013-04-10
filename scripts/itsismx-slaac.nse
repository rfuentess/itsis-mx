local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local target = require "target"
local itsismx = require "itsismx"
local datafiles = require "datafiles"


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

--
-- Version 0.1
--	
-- 	Created 10/04/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam@gmail.com>
--

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

	
	local MacList
	local bSalida, tSalida = false , { Nodos={}, Error=""}
	local MacUsers  = stdnse.get_script_args("itsismx.slaac.vendors")
	local PrefixHigh = {}
	-- Actu
	
	
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
		PrefixHigh = getMacPrefix( "quanta",MacList  )
	else
		PrefixHigh = getMacPrefix( MacUsers,MacList  )
	end
	
	-- Now we must retrieve the total number of host we are to calculate 
	
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