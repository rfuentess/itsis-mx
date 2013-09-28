--local bin = require "bin"
--local nmap = require "nmap"
--local packet = require "packet"
local stdnse = require "stdnse"
local itsismx = require "itsismx"
--local ipOps = require "ipOps"

description = [[
  A general overview of the previews 6 scripts will be displayed.  Only work on the last phase of Nmap and 
  work only with the final variables made by each one of the scripts.
]]

---
-- @usage
-- nmap -6 --script  itsismx-report -d
--
-- @output
-- Post-scan script results:
--	| itsismx-report:
--	|   Subnets:
--	|     No Subnets were discovered using this series of script.
--	|   Hosts:
--	|      SLAAC            : Discovered 3 nodes online which are 17.647058823529% Of total nodes discovered.
--	|      MAP 6 to 4       : Discovered 8 nodes online which is 47.058823529412 Of total nodes discovered.
--	|      Low Bytes        : Discovered 5 nodes online which is 29.411764705882 Of total nodes discovered.
--	|_     Words            : Discovered 1 nodes online which is 5.8823529411765 Of total nodes discovered.
--

-- Version 0.1
-- 	Created 28/09/2013	- v0.1 - created by Ing. Raul Fuentes <ra.fuentess.sam@gmail.com>
--

author = "Raul Fuentes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

postrule  = function()

	if ( not(nmap.address_family() == "inet6") ) then
		stdnse.print_verbose("%s Need to be executed for IPv6.", SCRIPT_NAME)
--		return false
	end

	local Global = nmap.registry.itsismx
	
	if ( Global == nil) then
		stdnse.print_verbose("%s Need to be executed after the other itsismx scripts. \n or there wasn't reports. ", SCRIPT_NAME)
--		return false
	end
	
	return true
end


action = function()

	--DEBUG
	nmap.registry.itsismx = {}
	
	local lSlaac = nmap.registry.itsismx.sbkmac
	local lMap64 = nmap.registry.itsismx.Map4t6
	local lLwByt = nmap.registry.itsismx.LowByt
	local lWords = nmap.registry.itsismx.wordis
	local lDhcp6 = nmap.registry.itsismx.PrefixesKnown

--local lSlaac = {"a", "b" , "c"}
--local lMap64 = {"a", "b" , "c", "", "", "", "", ""}
--local lLwByt = {"a", "b" , "c", "", ""}
--local lWords = {"a"}
--local lDhcp6 = {}
	
	local Total , SubRedes = 0 , 0 ;
	local tOutput = stdnse.output_table()
	-- The subnets
	if lDhcp6 ~= nil then 
		SubRedes = SubRedes + #lDhcp6
	else
		lDhcp6 = {}
	end
	
	
	-- The hosts
	if lSlaac ~= nil then
		Total = Total + #lSlaac
	else 
		lSlaac = {}
	end	
	if lMap64 ~= nil then
		Total = Total + #lMap64
	else 
		lMap64 = {}
	end
	if lLwByt ~= nil then
		Total = Total + #lLwByt
	else 
		lLwByt = {}
	end
	if lWords ~= nil then
		Total = Total + #lWords
	else 
		lWords = {}
	end
	
	--Now the report... 
	tOutput.Subnets={}
	tOutput.Hosts={}
	
	if SubRedes == 0  then
		table.insert(tOutput.Subnets, "No Subnets were discovered using this series of script. ")
	else
		if #lDhcp6 ~= 0 then 
			table.insert( tOutput.Hosts, #lDhcp6  .. " Were confirmed to exits using  the  spoofing technique with DHCPv6"    )
		end
		
	end
	
	if Total == 0 then
		table.insert(tOutput.Hosts, "No Hosts were discovered using this series of script. ")
	else 
		if #lSlaac ~= 0 then 
			table.insert( tOutput.Hosts, " SLAAC		: Discovered " ..  #lSlaac .. " nodes online which are "  .. #lSlaac/Total * 100 .. "% Of total nodes discovered."   )
		end
		if #lMap64 ~= 0 then 
			table.insert( tOutput.Hosts, " MAP 6 to 4	: Discovered " ..  #lMap64 .. " nodes online which is "  .. #lMap64/Total * 100 .. " Of total nodes discovered."   )
		end
		if #lLwByt ~= 0 then 
			table.insert( tOutput.Hosts, " Low Bytes	: Discovered " ..  #lLwByt .. " nodes online which is "  .. #lLwByt/Total * 100 .. " Of total nodes discovered."   )
		end
		if #lWords ~= 0 then 
			table.insert( tOutput.Hosts, " Words 		: Discovered " ..  #lWords .. " nodes online which is "  .. #lWords/Total * 100 .. " Of total nodes discovered."   )
		end
	end
	
	return tOutput
	--return stdnse.format_output(false, tOutput);
end