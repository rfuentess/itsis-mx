local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local target = require "target"
local itsismx = require "targets-ipv6-recon"
local tab = require "tab"

description = [[
  The script run at pre-scanning phase and script phase (The first for create 
  tentative 4to6 address and the second for put the living nodes on the list
  of discovered nodes).

  This script SHOULD run a typical Nmap on IPv4   and for each host up try to
  map the address to IPv6 (IPv6 subnets provided by user or by other script).
 
  HOWEVER, There is a problem with nmap 6.25 architecture:  OR only  IPv4 OR
  only IPv6 by run. This mean we can't check first for IPv4 address to be
  up so, the user must provided the IPv4 hosts to check. We have two way to
  do  it: The User provide IPv4 hosts address or provide IPv4 Subnet Address. 
]]

---
-- @usage
-- nmap -6 -p 80 --script targets-ipv6-recon-Map4to6 --script-args newtargets,targets-ipv6-recon-Map4t6.IPv4Hosts={192.168.1.0/24},targets-ipv6-recon-subnet={2001:db8:c0ca::/64}
--
--

-- @output
-- Pre-scan script results:
-- | targets-ipv6-recon-Map4to6:
-- |_  Were added 254 nodes to the host scan phase
-- Nmap scan report for  (2001:db8:c0ca::c0a8:101)
-- Host is up.
-- PORT   STATE   SERVICE
-- 80/tcp unknown http

-- @args targets-ipv6-recon-Map4t6.IPv4Hosts  This must have at least one IPv4
--                                   Host  for the script be able to work 
--                                   (Ex. 192.168.1.1 or
--                                   { 192.168.1.1, 192.168.2.2 } ) or Subnet
--                                   Addresses ( 192.168.1.0/24 or
--                                   { 192.168.1.0/24, 192.168.2.0/24 } )

-- @args targets-ipv6-recon-subnet  Table/single  IPv6 address with prefix
--                                  (Ex. 2001:db8:c0ca::/48 or
--                                  { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 })

-- @args newtargets          MANDATORY  Need for the host-scanning to success.

--
-- Version 1.3
-- Update  05/05/2014 - V 1.3 Eliminate the Host phase.
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
  "targets-ipv6-recon-dhcpv6",
}

---
-- This function will add all the list of IPv4 host to IPv6
--
-- The most normal is returning X:X:X:X::Y.Y.Y.Y/96
-- The conversion is going to be totally IPv6 syntax (we are going to
-- concatenate strings).
-- @param  IPv6_Network A IPv6 Address  ( X:X:X:X:: )
-- @param  IPv6_Prefix  A IPv6 Prefix, for this we are waiting 64-96 more will
--             cancel the conversion because there are not more space
--             for  Map 4-to-6.
-- @param  IPv4SHosts   A IPv4 String can be: X.X.X.X or X.X.X.X/YY
-- @return  Number   Total succesfuly nodes added to the scan.
-- @return  Error    A warning if something happened. (Nil otherwise)
local From_4_to_6 = function (IPv6_Network, IPv6_Prefix, IPv4SHosts)
  local sError, Listado = nil, 0

  local _, Host -- _ Can give problem
  local sBin6, sBin4, tTabla = nil, nil, {}
  local iTotal, bool, err = 0, false, "" 
  local IPAux

  --We check if the PRefix are OK, anything less than 96 is fine
  if IPv6_Prefix > 96 then
    return 0, " The IPv6 subnet: " .. IPv6_Network .. "/" .. IPv6_Prefix ..
                " can't support a direct Mapping 4 to 6."
  end

  sBin6, sError = ipOps.ip_to_bin(IPv6_Network) 
  if sBin6 == nil then
    return 0, sError
  end

  -- two options: String or Table,  the bes thing to do:  make string Table
  if type(IPv4SHosts) == "table" then
    tTabla = IPv4SHosts
  else
    table.insert(tTabla, IPv4SHosts)
  end

  stdnse.print_verbose(2, SCRIPT_NAME  .. ".Map4to6: " ..
             " Total IPv4 objects to analyze: " .. #tTabla ..
			 " for IPv6 subnet: " .. IPv6_Network .. "/" .. IPv6_Prefix)

  for _, Host in ipairs(tTabla) do


    stdnse.print_verbose(2, SCRIPT_NAME  .. ".Map4to6: " ..
                           " IPv4 Object: " .. Host)

    sBin4, sError = ipOps.ip_to_bin(Host) -- We have two options ..
    if sBin4 == nil then

      -- Possible  X.X.X.X/YY
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
                                 ".Map4to6: " .. "\t IPv6 address: " .. IPAux)

            bool, err = target.add(IPAux)
            if  bool then
        iTotal = iTotal + 1
      else
              stdnse.print_verbose(5, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                                  ": Had been a error adding the node " ..
                                   IPAux .. " which is: " .. err)

            end

          end
          IPv4_Next = itsismx.GetNext_AddressIPv4(IPv4_Next)
        end

      else
        -- This entry of host IS WRONG! WRONG!
        return iTotal, 
               "At least one  Host/Subnet was wrong passed: " .. Host
      end

    else
      -- Format: X.X.X.X
      Host = sBin6:sub(1, 96) .. sBin4
      Host = ipOps.bin_to_ip(Host)
      stdnse.print_verbose(5, SCRIPT_NAME ..  ".Map4to6: " ..
                             " \t IPv6 address: " .. Host)

      bool, err = target.add(Host)
      if  bool then
        iTotal = iTotal + 1
      else
              stdnse.print_verbose(5, SCRIPT_NAME ..
                                  ": Had been a error adding the node " .. 
                                  IPAux .. " which is: " .. err)
            end

    end
  end

  return iTotal
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
  local IPv4Sub = stdnse.get_script_args("targets-ipv6-recon-Map4t6.IPv4Hosts")
  local IPv6User = stdnse.get_script_args("targets-ipv6-recon-subnet")

  local IPv6Knowns = itsismx.Registro_Global_Leer("PrefixesKnown")
  
  local iIndex


  stdnse.print_verbose(2, SCRIPT_NAME .. ": Beginning the work.")


  -- Because Nmap current limitation of working ONE single IP family we must
  -- be sure to have everything for work the Mapped IPv4 to IPv6
  if IPv4Sub == nil then
    tSalida["Error"] = "There is not IPv4 subnets to scan! You must provide" ..
                       " it using the argument: itsismx.Map4t6.IPv4Nets."
    return bSalida, tSalida
  end

  -- Now we need to have based IPv6 Prefix, the most important is the previous
  -- known but we have a last-option too .
  if IPv6User == nil and IPv6Knowns == nil then
    tSalida["Error"] = "There is not IPv6 subnets to try to scan!. " ..
                       "You can run a script for discovering or adding " ..
                       "your own with the arg: itsismx.PrefixesKnown."
    return bSalida, tSalida
  end

  if IPv6Knowns ~= nil then

    stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                   "  Number of Subnets Known from other sources: " ..
                                                            #IPv6Knowns)

    for _, IPv6_Subnet in ipairs(IPv6Knowns) do
      --We need to extract the data
      IPv6_Add, IPv6_Prefix = itsismx.Extract_IPv6_Add_Prefix(IPv6_Subnet)

      IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix, IPv4Sub)
      if sError ~= nil then
        stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
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

      stdnse.print_verbose(2, SCRIPT_NAME .. 
                             "  Number of Subnets  provided by the user:  1")

      IPv6_Add, IPv6_Prefix = itsismx.Extract_IPv6_Add_Prefix(IPv6User)
      IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix, IPv4Sub)

      if sError ~= nil then
        stdnse.print_verbose(2, SCRIPT_NAME .. 
                                " ERROR: One IPv6 subnet wasnt translate")
        tSalida["Error"] = tSalida["Error"] .. "\n" .. sError
      end
      if IPv6Host then
        -- We need to concatenate the new nodes
        Grantotal = Grantotal + IPv6Host
      end
    elseif type(IPv6User) == "table" then
      stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                          "  Number of Subnets provided by the user: " ..
                                                                  #IPv6User)

      for _, IPv6_Subnet in ipairs(IPv6User) do
        --We need to extract the data
        IPv6_Add, IPv6_Prefix = itsismx.Extract_IPv6_Add_Prefix(IPv6_Subnet)
        IPv6Host, sError = From_4_to_6(IPv6_Add, IPv6_Prefix, IPv4Sub)
        if sError ~= nil then
          --print("Problema  detectado")
          stdnse.print_verbose(2, SCRIPT_NAME .. 
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
      stdnse.print_verbose(2, SCRIPT_NAME .. 
                    " WARNING:  The targets-ipv6-recon-subnet was ignored" .. 
                                                       " because wrong values")
    end


  end

  tSalida.Nodos = Grantotal
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
    stdnse.print_verbose(2, SCRIPT_NAME .. " Will only work on " ..
    "pre-scanning. The argument newtargets is needed for the host-scanning" ..
	" to work.")
  end

  return true
end



function action ()
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
  
--  itsismx.Registro_Global_Inicializar "Map4t6" -- We prepare our work!

  -- The aciton is divided in two parts: Pre-scanning and host scanning.
  if SCRIPT_TYPE == "prerule" then
    nmap.registry.map6t4_PreHost = {}
    bExito, tSalida = Prescanning()

    -- Now we adapt the exit to tOutput and add the hosts to the target!
    tOutput.warning = tSalida.Error

    if bExito then
      --Final report of the Debug Lvl of Prescanning
     stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
             ": Succesful Mapped IPv4 to IPv6 added to the scan:" ..
                                                        tSalida.Nodos)

    table.insert(tOutput, "Were added " ..
            tSalida.Nodos .. " nodes to the host scan phase")
      
      if tSalida.Error ~= "" then
        stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                                        ".Warnings:  " .. tSalida.Error)
      end
    else
      stdnse.print_verbose(2, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
      ": Was unable to add nodes to the scan list due this error: " ..
                                                            tSalida.Error)

    end
  end

  return stdnse.format_output(bExito, tOutput)
end
