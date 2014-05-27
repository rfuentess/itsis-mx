local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local target = require "target"
local itsismx = require "itsismx"

description = [[
 Explore the network trying to find IPv6 Nodes using low-bytes. 
 
 The script run at pre-scanning phase and script phase (The first for create 
 tentative low-bytes address and the second for put the living nodes on the list 
 of discovered nodes).
 
 The new version search by default on the range X:X:X:X::WWWW:UUUU/YY.
 Where WWWW by defualt is treated as decimal number (0000 - 9999) instead of 
 hexadecimal values.
 A default search will search by nodes as: 
  2001:db8:bee::0:0 - 2001:db8:bee::0:100
  2001:db8:bee::1:1 - 2001:db8:bee::1:100
  .
  .
  .
  2001:db8:bee::1000:1 - 2001:db8:bee::1000:100
  
]]

---
-- @usage
-- nmap -6 --script itsismx-LowByt --script-args newtargets,itsismx-subnet={2001:db8:c0ca:1::/64}
--
-- @output
-- Pre-scan script results:
-- | itsismx-LowByt:
-- |_  itsismx-LowByt.prerule:  Were added 256 nodes to the scan
-- Nmap scan report for Device (2001:db8:c0ca:1::a)
-- Host is up.


-- @args newtargets            MANDATORY Need for the host-scanning to success

-- @args itsismx-subnet        (Optional) IT's table/single IPv6 address with
--                                prefix(Ex. 2001:db8:c0ca::/48 or
--                                { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 })

-- @args itsismx-lowbyt.wseg   (Optional) Number of number/bits to use on the 
--                             WWWW segment

-- @args itsismx-lowbyt.wdec   (Optional) false (Default) the WWWW segment is treated
--                              as decimal number instead of hexadecimal.

-- @args itsismx-subnet.useg   (Optional) Number of number/bits to use on the
--                             UUUU segment

-- @args itsismx-subnet.udec   (Optional) false (Default) the WWWW segment is treated
--                              as HEXAdecimal number instead of decimal.


--
-- Version 2.0
-- Updated 20/05/2014 - V2.0 Major upgrade on the script (X:X:X:X::WWWW:UUUU/YY)
-- Updated 06/05/2014 - V1.2 Minor corrections and standardization.
-- Update 27/03/2013  - v 1.0
-- Created 26/02/2013 - v0.1  Created by Raul Fuentes <ra.fuentess.sam+nmap@gmail.com>
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
-- Will get X:X:X:X::WWWW:0 and will generate the last 16 bits.
--
--
-- @param  SubRed  Table with the 8 segments of the IPv6 Addresses
-- @param   nHost  Number of address to add.
-- @param  Dec    Boolean True: Decimal False: Hexadecimal
-- @return  Boolean  True if no error happened with the full block.
-- @return  Number  Total nodes successfuly added to the host list.
local Create_LowBytes = function (SubRed, nHost, Dec)

  -- We already have everything,  just need to execute nHost times
  local iCont, iTotal = 0, 0
  local Segmento, bExito = "", true
  local bool, sErr
  local IPv6Add = ""
  repeat
    -- Pass iCont to a hexadecimal value (with 4 Characters)
    -- BUT! SubRed always is going to have the decimal value
    -- So, we need to cast the dec to hex and then convert the
    -- hex to decimal. (10 is not 0x0010 but 0x000A)
    if Dec then
      SubRed[8] = tonumber(tostring(iCont), 16)
    else
      SubRed[8] = iCont
    end

    -- Now we re-cast the table to a IPv6 address
    -- uh... nasty ipOPs which don't have that function!!!
    IPv6Add = itsismx.DecToHex(SubRed[1]) .. ":" .. itsismx.DecToHex(SubRed[2]) ..
              ":" .. itsismx.DecToHex(SubRed[3]) .. ":" ..
              itsismx.DecToHex(SubRed[4]) .. ":" .. itsismx.DecToHex(SubRed[5]) ..
              ":" .. itsismx.DecToHex(SubRed[6]) .. ":" ..
              itsismx.DecToHex(SubRed[7]) .. ":" .. itsismx.DecToHex(SubRed[8])

    stdnse.print_verbose(5, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. "Adding Host" ..
                                                                          IPv6Add)

    -- Add the host to scan phase, look for any problem
    bool, sErr = target.add(IPv6Add)
    if bool == false then
      stdnse.print_verbose(5, SCRIPT_NAME .. "." .. SCRIPT_TYPE .. "Error" .. sErr)


      bExito = false
    else
      iTotal = iTotal + 1
    end

    iCont = iCont + 1
  until iCont >= nHost

  return bExito, iTotal
end

---
-- Will generate the last two segments for the Subnetwork.
--
-- Remember, WE are to scan the range X:X:X:X::WWWW:00UU/YY
-- where by defualt WWWW it's going to be 0000 to 1000 but seen as decimal values
-- (a,b,c,d and F will not be displayed) meanwhile the UUUU will be seen as
-- hexadecimal values.
-- Defualt values are:  2560,00 address (100 x 256)
-- @param  Subnet  Table with the 8 segments of the IPv6 Addresses
-- @param  iWseg  (Optional) Total of WWWW to use on the segment.
-- @param  bWseg   (Optional) We see iWseg as decimal (false) or hexadecimal?
-- @param  iUseg  (Optional) Total of UUU to use on the segment.
-- @param  bUseg   (Optional) We see bUseg as decimal (true) or hexadecimal?
-- @return  Boolean  TRUE: ALL the tentative nodes were added
-- @return  Table    Basic standard output
local Crear_2Segmentos = function (Subnet, Prefijo, iWseg, bWseg, iUseg, bUseg)

  local iCont, iRem, iAux = 0, 0, 0
  local iTotal, bExito = 0, true
  local sSegmento, bAux
  -- Default: 100x100 = 10,000
  if iWseg == nil then
    iWseg = 100
  end
  if iUseg == nil then
    iUseg = 100
  end

  -- We placed the default values, however we are working with subnet with custom
  -- prefix. If those prefix are higher than the possible values, then we need to
  -- adjust. We modify the last 32 bits (half here, the other half later)
  if Prefijo > 112 then
    -- We ignore the 7-segment

    -- We pass to work the 8-segment
    iWseg = 0

    -- And there is no doubt, we need to check how affected is the 8-segment
    -- But as with the 7-segment, the bits can have hexadecimal value (default)
    -- or decimal value.
    iRem = Prefijo - 112
    if not bUseg then
      --hexadecimal representation (0x0000 - 0xFFFFF)


      if math.pow(2, 16 - iRem) < iUseg then
        --Each bits count as 2
        iUseg = math.pow(2, 16 - iRem)


      end
    else
      -- decimal representation (0 - 9999)
      if (iRem <= 4) and iUseg > 999 then
        iUseg = 999
      elseif iRem <= 8 and iUseg > 99 then
        iUseg = 99
      elseif (iRem <= 12) and iUseg > 9 then
        iUseg = 9
      else
        iUseg = 0
      end --No sense at all!
    end

    stdnse.print_verbose(4, SCRIPT_NAME ..
    "WARNING: The sub-net has a higher prefix than the number" ..
    "for UUUU segment. Has been limited to " .. iUseg)


  elseif (Prefijo > 96) and (Prefijo <= 112) then
    -- Probably we need to update iWseg to the remaining bits available
    iRem = Prefijo - 96

    if bWseg then
      -- Hexadecimal representation (0x0000 - 0xFFFFF)
      if math.pow(2, 16 - iRem) < iWseg then
        --Each bits count as 2
        iWseg = math.pow(2, 16 - iRem)

      end
    else
      -- Decimal representation (0 - 9999)

      -- This is tricky, we have 16 bits, but we only work on multiple
      -- of 4 (round down). So, at least we lost one part


      -- Only 4 possible values: 999, 99, 9 or 0
      if iRem <= 4 and iWseg > 999 then
        iWseg = 999 -- This is suicide however
      elseif iRem <= 8 and iWseg > 99 then
        iWseg = 99
      elseif iRem <= 12 and iWseg > 9 then
        iWseg = 9
      else
        -- -- We pass to work the 8-segment
        iWseg = 0
      end
    end

    stdnse.print_verbose(4, SCRIPT_NAME ..
    "WARNING: The sub-net has a higher prefix with conflict with WWWW" ..
    " value provided. Has been limited accord to: " .. iWseg)
  end -- The 7-segment is untouched so, normal operation


  -- The booleans don't care as nil is taken as false (though bUseg will always be
  -- negated for have easy time with our code.

  repeat

    -- We are to calculate the current Segment
    if bWseg then
      -- Hexadecimal representation
      Subnet[7] = iCont
    else
      -- Decimal representation
      Subnet[7] = tonumber(tostring(iCont), 16)
    end

    bAux, iAux = Create_LowBytes(Subnet, iUseg, bUseg)

    iTotal = iTotal + iAux
    bExito = bExito and bAux
    iCont = iCont + 1

  until iCont >= iWseg

  return bExito, iTotal
end

---
-- This is the core of the script. Is here where we are adding groups of host by
-- each prefix
-- @return Boolean   TRUE  If there were no problem, otherwise FALSE.
-- @return Number    Total number of nodes added to the host phase scan.
local PreScanning = function ()

  local IPv6PRefijoUsuario = stdnse.get_script_args "itsismx-subnet"
  local IPv6PRefijoScripts = nmap.registry.itsismx.PrefixesKnown

  local WSegmento = stdnse.get_script_args "itsismx-lowbyt.wseg"
  local WDec = stdnse.get_script_args "itsismx-lowbyt.wdec"

  local USegment = stdnse.get_script_args "itsismx-subnet.useg"
  local UDec = stdnse.get_script_args "itsismx-subnet.udec"

  local Subredes, PrefixAux = {}
  local Direccion, Prefijo
  local bAux, iAux = true, 0
  local IPv6Segmentada, sErr

  local bSalida, tSalida = true, {
    Nodos = 0,
    Error = "",
  }
  stdnse.print_verbose(2, SCRIPT_NAME .. ": Beginning the Pre-scanning work...")

  -- We create a unique table from IPv6PRefijo(Usuario, Scripts)
  if IPv6PRefijoUsuario == nil and IPv6PRefijoScripts == nil then
    tSalida.Error = "There is not IPv6 subnets to try to scan!. You can run a" ..
    " script for discovering or adding your own with the arg: itsismx-subnet."
    return false, tSalida
  end

  if IPv6PRefijoScripts ~= nil then
    stdnse.print_verbose(2, SCRIPT_NAME ..
    ": Number of Prefixes Known from other sources: " .. #IPv6PRefijoScripts)
    for _, PrefixAux in ipairs(IPv6PRefijoScripts) do
      table.insert(Subredes, PrefixAux)
    end
  end

  if IPv6PRefijoUsuario ~= nil then
    if type(IPv6PRefijoUsuario) == "string" then
      stdnse.print_verbose(2, SCRIPT_NAME ..
                          ":  Number of Prefixes Known from other sources: 1 ")
      table.insert(Subredes, IPv6PRefijoUsuario)
    elseif type(IPv6PRefijoUsuario) == "table" then
      stdnse.print_verbose(2, SCRIPT_NAME ..
         ":  Number of Prefixes Known from other sources: " .. #IPv6PRefijoUsuario)
      for _, PrefixAux in ipairs(IPv6PRefijoUsuario) do
        table.insert(Subredes, PrefixAux)
      end
    end
  end

  -- Now we validate the 2 pairs of optional variables. (All is string by default)
  -- Actually, only the XSegment, the other are booleans, nil==false otherwise true
  -- WSegmento WDec USegment UDec
  if WSegmento ~= nil then
    WSegmento = tonumber(WSegmento)
    if WSegmento < 0 then
      -- NOPE!
      WSegmento = nil
      tSalida.Error = tSalida.Error .. "\n the variable itsismx-lowbyt.wseg" ..
                                      " has been ignored as have negative value"
    end
  end
  if USegment ~= nil then
    USegment = tonumber(USegment)
    if USegment < 0 then
      -- NOPE!
      USegment = nil
      tSalida.Error = tSalida.Error .. "\n the variable itsismx-lowbyt.useg" ..
                                       " has been ignored as have negative value"
    end
  end

  -- Now we begin the work for each network
  for _, PrefixAux in ipairs(Subredes) do
    Direccion, Prefijo = itsismx.Extract_IPv6_Add_Prefix(PrefixAux)

    IPv6Segmentada, sErr = ipOps.get_parts_as_number(Direccion)

    if IPv6Segmentada == nil then
      bSalida = false
      tSalida.sError = tSalida.sError .. "\n The prefix " .. Direccion ..
                                                 "was provided erroneous: " .. sErr
    else
      bAux, iAux = Crear_2Segmentos(IPv6Segmentada, Prefijo, WSegmento, WDec,
                                                                USegment, UDec)

      if bAux ~= true then
        bSalida = false
        tSalida.sError = tSalida.sError ..
        "\n Was not possible to one or more of the host for the prefix " .. Direccion
      end
      tSalida.Nodos = iAux + tSalida.Nodos
    end
  end
  return bSalida, tSalida
end

---
-- The script need to be working with IPv6
function prerule ()

  if not (nmap.address_family() == "inet6") then
    stdnse.print_verbose("%s Need to be executed for IPv6.", SCRIPT_NAME)
    return false
  end

  if stdnse.get_script_args 'newtargets' == nil then
    stdnse.print_verbose(2, "%s Will only work on pre-scanning. The argument" ..
    " newtargets is needed for the host-scanning to work.", SCRIPT_NAME)
  end

  return true
end


function action ()

  --Vars for created the final report
  local tOutput = stdnse.output_table()
  local bExito, tSalida = false, {
    Error = "",
    Nodos = 0,
  }

  tOutput.Nodes = 0

  -- We get the prefix ready!
  itsismx.Registro_Global_Inicializar "LowByt"

  bExito, tSalida = PreScanning()

  -- Adapt the exit to tOutput
  tOutput.warning = tSalida.Error

  if tSalida.Nodos > 0 then
    -- --Final report of the Debug Lvl of Prescanning
    stdnse.print_verbose(2, SCRIPT_NAME ..
    ": Successful Low-Bytes to IPv6 added to the scan: " .. tSalida.Nodos)
    
    table.insert(tOutput, "Successful Low-Bytes to IPv6 added to the scan: " ..
                                                                    tSalida.Nodos)

    tOutput.Nodes = tSalida.Nodos
  else
    stdnse.print_verbose(2, SCRIPT_NAME ..
    ": Was unable to add nodes to the scan list due this error: " .. tSalida.Error)
  end

  if tSalida.Error ~= "" then
    stdnse.print_verbose(3, SCRIPT_NAME .. " Warnings: " .. tSalida.Error)
  end

  return stdnse.format_output(bExito, tOutput)
end
