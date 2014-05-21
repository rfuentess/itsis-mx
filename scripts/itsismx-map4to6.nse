local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local target = require "target"
local itsismx = require "itsismx"
local tab = require "tab"

description = [[
  This script SHOULD run a typical Nmap on IPv4   and for each host up try to map the
  address to IPv6 (IPv6 subnets provided by user or by other script ).
 
  HOWEVER, There is a problem with nmap 6.25 architecture:  OR only  IPv4   OR only
  IPv6 by run. This mean we can't check first for IPv4 address to be up so, the user
  must provided the IPv4 hosts   to check. We have two way to do it: The User provide 
  IPv4 hosts address   or provide IPv4 Subnet Address ( X.X.X.X/YY ).
 
  The script run at pre-scanning phase and script phase (The first for create 
  tentative 4to6 address and the second for put the living nodes on the list of discovered
  nodes).
]]

---
-- @usage
-- nmap -6 --script itsismx-Map4to6 --script-args newtargets,itsismx-Map4t6.IPv4Hosts={192.168.1.0/24},itsismx-subnet={2001:db8:c0ca::/64}
--
--

-- @output
-- Pre-scan script results:
-- | itsismx-map4to6:
-- |_  itsismx-map4to6.prerule:  Were added 254 nodes to the host scan phase
--
-- Host script results:
-- | itsismx-map4to6:
-- | Host online - Mapped IPv4 to IPv6
-- |_  2001:db8:c0ca:1::C0A8:01b1

-- @args nmap.registry.itsismx.Map4t6  Is a global Registry (the final objective
--                                     of this script) will have all the valid IPv6
--                                     address discovered with this Script.


-- @args nmap.registry.map6t4_PreHost  Is a global registry which will used by the
--                                     script for the host rule (detect new targets
--                                     from previous).

-- @args itsismx-Map4t6.IPv4Hosts      This must have at least one IPv4 Host  for the
--                                     script be able to work (Ex. 192.168.1.1 or
--                                     { 192.168.1.1, 192.168.2.2 } ) or Subnet
--                                     Addresses ( 192.168.1.0/24 or
--                                     { 192.168.1.0/24, 192.168.2.0/24 } )


-- @args itsismx-SaveMemory  (Optional) This will avoid to create registries for the
--                                      final report. This is very useful if the host
--                                      do not have enough memory for the search.

-- @args itsismx-subnet                 It's table/single  IPv6 address with prefix
--                                      (Ex. 2001:db8:c0ca::/48 or
--                                      { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )

-- @args newtargets          MANDATORY  Need for the host-scanning to success

--
-- Version 1.2
-- Update  05/05/2014 - V 1.2 Minor corrections and standardization.
-- Update  18/10/2013 - V 1.1 Added     SaveMemory option
-- Update  29/03/2013 - V 1.0 Functional script
-- Created 28/03/2013 - v0.1  Created by Raul Fuentes <ra.fuentess.sam+nmap@gmail.com>
--

author = "Raul Armando Fuentes Samaniego"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {
  "discovery",
  "dos",
}

dependencies = {
  "itsismx-dhcpv6",
}

---
-- This function will add all the list of IPv4 host to IPv6
--
-- The most normal is returning X:X:X:X::Y.Y.Y.Y/96
-- The conversion is going to be totally IPv6 syntax (we are going to
-- concatenate strings).
-- @param  IPv6_Network  A IPv6 Address  ( X:X:X:X:: )
-- @param  IPv6_Prefix   A IPv6 Prefix, for this we are waiting 64-96 more will
--             cancel the conversion because there are not more space
--             for  Map 4-to-6.
-- @param  IPv4SHosts  A IPv4 String can be: X.X.X.X or X.X.X.X/YY
-- @return  Table    A table of IPv6 hosts (NO prefix)
-- @return  Error    A warning if something happened. (Nil otherwise)
local From_4_to_6 = function (IPv6_Network, IPv6_Prefix, IPv4SHosts)
  local sError, Listado = nil, 0

  local _, Host -- _ Can give problem
  local sBin6, sBin4, tTabla = nil, nil, {}
  local SaveMemory, bool, err = stdnse.get_script_args "itsismx-SaveMemory"


  --We check if the PRefix are OK, anything less than 96 is fine
  if IPv6_Prefix > 96 then
    return nil, " The IPv6 subnet: " .. IPv6_Network .. "/" .. IPv6_Prefix ..
                " can't support a direct Mapping 4 to 6."
  end

  sBin6, sError = ipOps.ip_to_bin(IPv6_Network) -- We don't left dangerous operation
  if sBin6 == nil then
    return nil, sError
  end

  --Ok, we have two options: String or Table... the bes thing...  make string Table
  -- and don't add more lines doing the same!
  if type(IPv4SHosts) == "table" then
    tTabla = IPv4SHosts
  else
    table.insert(tTabla, IPv4SHosts)
  end

  stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ".Map4to6: " ..
             " Total IPv4 objects to analyze: " .. #tTabla .. " for IPv6 subnet: " ..
             IPv6_Network .. "/" .. IPv6_Prefix)

  for _, Host in ipairs(tTabla) do


    stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ".Map4to6: " ..
                           " IPv4 Object: " .. Host)

    sBin4, sError = ipOps.ip_to_bin(Host) -- We have two options ..
    if sBin4 == nil then

      -- Posible  X.X.X.X/YY
      local IPv4_First, IPv4_Last, IPv4_Next, SErr2, IPAux
      IPv4_First, IPv4_Last, SErr2 = ipOps.get_ips_from_range(Host)

      if IPv4_First ~= nil and IPv4_Last ~= nil then
        -- Sweep Subnet,  we must do

        --First IPv4 addresses is invalid
        IPv4_Next = itsismx.GetNext_AddressIPv4(IPv4_First)
        while ipOps.ip_in_range(IPv4_Next, Host) do
          --  last addresses is invalid (Broadcast)!
          if ipOps.compare_ip(IPv4_Next, "lt", IPv4_Last) then

            IPAux = sBin6:sub(1, 96) .. ipOps.ip_to_bin(IPv4_Next)
            IPAux = ipOps.bin_to_ip(IPAux)
            stdnse.print_verbose(5, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                                 ".Map4to6: " .. " \t IPv6 address: " .. IPAux)


            bool, err = target.add(IPAux)
            if bool and not SaveMemory then
              table.insert(nmap.registry.map6t4_PreHost, IPAux)

            elseif not bool then
              stdnse.print_verbose(6, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                                  ": Had been a error adding the node " .. IPAux ..
                                  " which is: " .. err)

            end


          end
          IPv4_Next = itsismx.GetNext_AddressIPv4(IPv4_Next)
        end

      else
        -- This entry of host IS WRONG! WRONG!
        return #nmap.registry.map6t4_PreHost, 
               "At least one  Host/Subnet was wrong passed: " .. Host
      end

    else
      -- Format: X.X.X.X
      Host = sBin6:sub(1, 96) .. sBin4
      Host = ipOps.bin_to_ip(Host)
      stdnse.print_verbose(5, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. ".Map4to6: " ..
                             " \t IPv6 address: " .. Host)


      bool, err = target.add(Host)
      if bool and not SaveMemory then
        table.insert(nmap.registry.map6t4_PreHost, Host)
      elseif not bool then
        stdnse.print_verbose(5, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
                            ": Had been a error adding the node " .. Host .. " which is: " .. err)
      end

    end
  end

  return #nmap.registry.map6t4_PreHost
end

---
-- We populated the host discovery list.
local Prescanning = function ()

  local bSalida = false
  local tSalida = {
    Nodos = 0,
    Error = "",
  }
  local IPv6_Subnet, IPv6_Add, IPv6_Prefix
  local IPv6Host, sError, Grantotal = nil, nil, 0
  local IPv4Subnets, IPv6User = stdnse.get_script_args("itsismx-Map4t6.IPv4Hosts",
                                                       "itsismx-subnet")
  local IPv6Knowns = nmap.registry.itsismx.PrefixesKnown
  local iIndex


  stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. 
                          ": Begining the Pre-scanning work... ")


  -- Because Nmap current limitation of working ONE single IP family we must be sure to have everything
  -- for work the Mapped IPv4 to IPv6
  if IPv4Subnets == nil then
    tSalida["Error"] = "There is not IPv4 subnets to scan!. You must provide" .. 
                       " it using the argument: itsismx.Map4t6.IPv4Nets."
    return bSalida, tSalida
  end

  -- Now we need to have based IPv6 Prefix, the most important is the previous known but we have
  -- a last-option too .
  if IPv6User == nil and IPv6Knowns == nil then
    tSalida["Error"] = "There is not IPv6 subnets to try to scan!. You can run" ..
                       " a script for discovering or adding your own" ..
                       "  with the arg: itsismx.PrefixesKnown."
    return bSalida, tSalida
  end

  if IPv6Knowns ~= nil then

    stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                   "  Number of Subnets Known from other sources: " .. #IPv6Knowns)

    for _, IPv6_Subnet in ipairs(IPv6Knowns) do
      --We need to extract the data
      IPv6_Add, IPv6_Prefix = itsismx.Extract_IPv6_Add_Prefix(IPv6_Subnet) 

      IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix, IPv4Subnets)
      if sError ~= nil then
        stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                               " ERROR: One IPv6 subnet wasnt translate")
        tSalida["Error"] = tSalida["Error"] .. "\n" .. sError
      end
      if IPv6Host then
        -- We need to concatenate the new nodes
        Grantotal = Grantotal + IPv6Host
      end
    end
  end

  if IPv6User ~= nil then
    -- We got tww options with this.
    if type(IPv6User) == "string" then

      stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                             "  Number of Subnets  provided by the user:  1")

      IPv6_Add, IPv6_Prefix = itsismx.Extract_IPv6_Add_Prefix(IPv6User)
      IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix, IPv4Subnets)

      if sError ~= nil then
        stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                                " ERROR: One IPv6 subnet wasnt translate")
        tSalida["Error"] = tSalida["Error"] .. "\n" .. sError
      end
      if IPv6Host then
        -- We need to concatenate the new nodes
        Grantotal = Grantotal + IPv6Host
      end
    elseif type(IPv6User) == "table" then
      stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                          "  Number of Subnets provided by the user: " .. #IPv6User)

      for _, IPv6_Subnet in ipairs(IPv6User) do
        --We need to extract the data
        IPv6_Add, IPv6_Prefix = itsismx.Extract_IPv6_Add_Prefix(IPv6_Subnet)
        IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix, IPv4Subnets)
        if sError ~= nil then
          --print("Problema  detectado")
          stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                                 " ERROR: One IPv6 subnet wasnt translate")
          tSalida["Error"] = tSalida["Error"] .. "\n" .. sError
        end

        if IPv6Host then
          -- We need to concatenate the new nodes
          Grantotal = Grantotal + IPv6Host
        end
      end
    else
      -- This only mean the user pass something odd...
      stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                    " WARNING:  The itsismx-subnet was ignored because wrong values")
    end


  end

  tSalida.Nodos = Grantotal
  return true, tSalida -- We got to this point everything was fine (Or don't crash)!
end

---
-- We add each one of the hosts in the final register.
local Hostscanning = function (host)

  local tSalida = {
    Nodos = nil,
    Error = "",
  }
  local aux

  --Each host is too much!
  --  stdnse.print_verbose(3, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
  --      ": Begining the Host-scanning results... "  )

  -- We are going to be sure don't do stupid thing on wrong register (Because we 
  -- don't have handlres for working with registers)
  if nmap.registry.itsismx == nil then
    tSalida.Error = "You must first initialize the global register Itsismx (There" ..
                    "  is a global function for that)"
    return false, tSalida
  end
  aux = nmap.registry.itsismx.Map4t6
  if aux == nil then
    tSalida.Error = "The global register Itsismx wasn't initialzed correctly" ..
                     " (There is a global function for that)"
    return false, tSalida
  end

  --We use the aux for be able to add a new element to the table
  aux[#aux + 1] = host.ip
  nmap.registry.itsismx.Map4t6 = aux

  -- This rule ALWAY IS ONE ELEMENT!
  tSalida.Nodos = host.ip

  return true, tSalida
end

---
-- The script need to be working with IPv6
--
--(To bad can't do it with both at same time )
function prerule ()
  if not (nmap.address_family() == "inet6") then
    stdnse.print_verbose("%s Need to be executed for IPv6.", SCRIPT_NAME)
    return false
  end

  if stdnse.get_script_args 'newtargets' == nil then
    stdnse.print_verbose(1, "%s Will only work on pre-scanning. The argument" ..
                 "newtargets is needed for the host-scanning to work.", SCRIPT_NAME)
  end

  return true
end

---
-- We are going to check if the host up was discovered by a list generated in the
-- pre-scanning phase ( Registry nmap.registry.map6t4_PreHost ).
function hostrule (host)

  local Totales, Objetivo, bMatch, sMatch = nmap.registry.map6t4_PreHost

  if Totales == nil then
    return false
  end

  for _, Objetivo in pairs(Totales) do
    bMatch, sMatch = ipOps.compare_ip(host.ip, "eq", Objetivo)
    if bMatch == nil then
      stdnse.print_verbose(1, "\t hostrule  had a error with " .. host.ip ..
                               "\n Error:" .. sMatch)
    elseif bMatch then
      return true
    end
  end

  return false
end


function action (host)
  --Vars for created the final report
  local tOutput = stdnse.output_table()
  local bExito = false
  local tSalida = {
    Nodos = {},
    Error = "",
  }
  local sHostsPre, bTarget, sTarget
  local Nodes = {} -- Is a Auxiliar
  tOutput.Nodes = {}
  itsismx.Registro_Global_Inicializar "Map4t6" -- We prepare our work!

  -- The aciton is divided in two parts: Pre-scanning and host scanning.
  if SCRIPT_TYPE == "prerule" then
    nmap.registry.map6t4_PreHost = {}
    bExito, tSalida = Prescanning()

    -- Now we adapt the exit to tOutput and add the hosts to the target!
    tOutput.warning = tSalida.Error

    if bExito then
      --Final report of the Debug Lvl of Prescanning
      stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
              ": Succesful Mapped IPv4 to IPv6 added to the scan:" .. #tSalida.Nodos)
      -- We don't add those nodes to the standard exit BECAUSE ARE TEMPTATIVE ADDRESS
      if tSalida.Error ~= "" then
        stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                                        ".Warnings:  " .. tSalida.Error)
      end
    else
      stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
      ": Was unable to add nodes to the scan list due this error: " .. tSalida.Error)

    end
  end

  if SCRIPT_TYPE == "hostrule" then

    bExito, tSalida = Hostscanning(host)
    tOutput.warning = tSalida.Error

    if bExito ~= true then
      stdnse.print_verbose(1, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. " Error: " ..
                                                                    tSalida.Error)
    end

    tOutput.name = "Host online - Mapped IPv4 to IPv6"
    --tSalida.Nodos is one single entry not a table (Hostscanning trick)
    table.insert(tOutput, tSalida.Nodos)

  end

  return stdnse.format_output(bExito, tOutput)
end
