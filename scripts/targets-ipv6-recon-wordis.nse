local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local target = require "target"
local itsismx = require "targets-ipv6-recon"
local datafiles = require "datafiles"
local bin = require "bin"
local table = require "table"
local math = require "math"

description = [[
  This is the most simple and easier of all the scripts. The objective is
  to do a discovery based on dictionary.
  
  For each prefix we discover, we are going to check against known hex-words.
  ( EX. 2001:db8:c0ca::beef )
  
  P.d. The dictionary still need more entries for this script become very
  useful.  
]]

---
-- @usage
-- nmap -6 -p 80 --script targets-ipv6-recon-wordis --script-args newtargets,targets-ipv6-recon-subnet={2001:db8:c0ca::/64}
--
-- @output
-- Pre-scan script results:
-- | targets-ipv6-recon-wordis:
-- |_  Were added 9 nodes to the host scan phase
--
-- Nmap scan report for  (2001:db8:c0ca::dead)
-- Host is up.
-- PORT   STATE   SERVICE
-- 80/tcp unknown http

-- @args newtargets          MANDATORY Need for the host-scaning to success.

-- @args targets-ipv6-recon-wordis.nsegments  (Optional) Number User can
--                           indicate exactly how big the word must be on 
--                           Segments of 16 bits.

-- @args targets-ipv6-recon-wordis.fillright  (Optional) With this argument
--                          the script will fill remaining zeros to the right
--                          instead of left (2001:db8:c0a:dead:: instead of 
--                          2001:db8:c0ca::dead)

-- @args targets-ipv6-recon-subnet           (Optional) table/single IPv6
--                         address with prefix (Ex. 2001:db8:c0ca::/48 or
--                         { 2001:db8:c0ca::/48, 2001:db8:FEA::/48 } )

-- Version 1.3
--  Updated 21/05/2014 - V1.3 Eliminate the host phase.
--  Updated 06/05/2014 - V1.2 Minor corrections and standardization.
--  Created 29/04/2013 - v1.0 Created by Raul Fuentes <ra.fuentess.sam+nmap@gmail.com>
--

author = "Raul Fuentes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {
  "discovery"
}

dependencies = {
  "targets-ipv6-recon-dhcpv6",
}

---
-- Get a Prefix and for that one will add all the valid  words  we known.
--
-- However two arguments from the user can affect how calculated the hosts.
-- n-segments fix to pick a number of segments (by default is any segment
-- enough small for be inside of the subnet prefix) and  fill-right which alter
-- where we place the remaining zeros (Default the left).
-- @param   Direccion      String  IPv6 address (Subnet)
-- @param   Prefijo        Number  Prefix value of subnet
-- @param   TablaPalabras  Table containing all the elements to search.
-- @param   User_Segs      Number of segments to search.
-- @param   User_Right     Boolean for fill right or left (Default)
-- @return  Boolean        True if was successful the operation
-- @return  Number         Total of successfuly nodes added to the scan list.
-- @return  Error          Any error generated, default: "" not nil.
local CrearRangoHosts = function (Direccion, Prefijo, TablaPalabras,
                                                       User_Segs, User_Right)

  local IPv6Bin, Error = ipOps.ip_to_bin(Direccion)
  local Candidatos, sError = {}, ""
  local Indice, Palabras, MaxRangoSegmentos, Filler, Host

  local iTotal, bAux, sAux = 0, false, ""

  if IPv6Bin == nil then
    --Niagaras!
    return false, 0, Error
  end

  -- We have (128 -  n ) / ( 16 )
  -- The first part are how many bits are left to hosts portion
  -- The Second part is the size of the segments (16 bits). 
  if User_Segs == nil then
    MaxRangoSegmentos = math.ceil((128 - Prefijo) / 16)
    User_Segs = false
  else
    MaxRangoSegmentos = tonumber(User_Segs)
  end

  stdnse.print_verbose(3, SCRIPT_NAME .. ": Will be calculted " .. 
   #TablaPalabras .. " hosts for the subnet: " .. Direccion .. "/" .. Prefijo)

  -- Palabras is a table with two elements Segmento & Binario
  for Indice, Palabras in ipairs(TablaPalabras) do

    if ((tonumber(Palabras.Segmento) <= MaxRangoSegmentos) and 
        User_Segs == false) or
        (User_Segs and (tonumber(Palabras.Segmento) == MaxRangoSegmentos)) then

      -- We are going to add binaries values but the question is
      -- whenever must fill with zeros?
      Filler = ""
      while (Prefijo + #Filler + #Palabras.Binario) < 128 do
        Filler = "0" .. Filler
      end

      if User_Right ~= nil then
        Host = IPv6Bin:sub(1, Prefijo) .. Palabras.Binario .. Filler
      else
        Host = IPv6Bin:sub(1, Prefijo) .. Filler .. Palabras.Binario
      end

      -- We pass the binaries to valid IPv6
      Host, Error = ipOps.bin_to_ip(Host)
      if Host == nil then
        -- Something is very wrong but we don-t stop
        sError = sError .. "\n" .. Error
      else
        bAux, sAux = target.add(Host)
        if(bAux) then
           iTotal = iTotal + 1
        else
           stdnse.print_verbose(5, SCRIPT_NAME .. "." .. SCRIPT_TYPE ..
                              ": Had been a error adding the node " .. Host ..
                              " which is: " .. sAux)
        end
      end
    end
  end

  return true, iTotal, sError
end

---
-- Parsing process of concatenate each word on the dictionary with subnetworks.
--
-- (for now is very crude) will search for the file and  return only the
-- binaries numbers (String) that matches with the number of segments we
-- want to use. 
-- @return  Table     Table of elements returned (Nil if there was a error)
-- @return  String    Empty if there is no error, otherwise the error message.
local LeerArchivo = function ()
  -- [ "^%s*(%w+)%s+[^#]+" ] = "^%s*%w+%s+([^#]+)" }
  local bBoolean, Archivo = datafiles.parse_file("nselib/targets-ipv6-recon-words-known",
  {"^[^#]+%d",})
  local index, reg, token
  local Candidatos = {}
  local Registro = {
    ["Segmento"] = 0,
    ["Binario"] = "0",
  }
  local sMatch = {}

  if bBoolean ~= true then
    return nil, Archivo
  end

  for index, reg in pairs(Archivo) do
    -- The structure is very well known:  Digit  Word  Binary
    sMatch = {}
    Registro = {
      ["Segmento"] = 0,
      ["Binario"] = "0",
    }
    for token in reg:gmatch "%w+" do
      sMatch[#sMatch + 1] = token
    end

    Registro.Segmento = sMatch[1]
    Registro.Binario = sMatch[3]
    table.insert(Candidatos, Registro)

  end

  return Candidatos, ""
end

---
--  We get the info we need from the user and other scripts then we add them to
--  our file!
--
-- (So easy that seem we need to make them obscure)
local Prescanning = function ()
  local bSalida, tSalida = false, {
    Nodos = 0,
    Error = "",
  }
  local IPv6PRefijoUsuario = stdnse.get_script_args "targets-ipv6-recon-subnet"
  local IPv6PRefijoScripts = itsismx.Registro_Global_Leer("PrefixesKnown")
  local TablaPalabras, sError, IPv6refijosTotales = {}, "", {}
  local PrefixAux, Prefijo, Direccion
  local Hosts, Nodo, Indice = 0
local User_Segs = stdnse.get_script_args "targets-ipv6-recon-wordis.nsegments"
local User_Right = stdnse.get_script_args "targets-ipv6-recon-wordis.fillright"
  
  -- First we get the info from known prefixes because we need those Prefixes
  stdnse.print_verbose(2, SCRIPT_NAME .. ": Beginning the script... ")

  -- Second, we read our vital table
  TablaPalabras = LeerArchivo()

  if TablaPalabras == nil then
    tSalida.Error = sError
    return bSalida, tSalida
  end

  -- We pass all the prefixes to one single table (health for the eyes)
  if IPv6PRefijoUsuario == nil and IPv6PRefijoScripts == nil then
    tSalida.Error = "There is not IPv6 subnets to try to scan!." .. 
    " You can run a script for discovering or adding your own" .. 
	" with the arg: targets-ipv6-recon-subnet."
    return bSalida, tSalida
  end

  if IPv6PRefijoScripts ~= nil then
    stdnse.print_verbose(2, SCRIPT_NAME ..
    ": Number of Prefixes Known from other sources: " .. #IPv6PRefijoScripts)
    for _, PrefixAux in ipairs(IPv6PRefijoScripts) do
      table.insert(IPv6refijosTotales, PrefixAux)
    end
  end

  if IPv6PRefijoUsuario ~= nil then
    if type(IPv6PRefijoUsuario) == "string" then
      stdnse.print_verbose(2, SCRIPT_NAME ..
      ": Number of Prefixes Known from other sources: 1 ")
      table.insert(IPv6refijosTotales, IPv6PRefijoUsuario)
    elseif type(IPv6PRefijoUsuario) == "table" then
      stdnse.print_verbose(2, SCRIPT_NAME ..
      ": Number of Prefixes Known from other sources: " .. #IPv6PRefijoUsuario)
      for _, PrefixAux in ipairs(IPv6PRefijoUsuario) do
        table.insert(IPv6refijosTotales, PrefixAux)
      end
    end
  end

  -- We begin to explore all thoses prefixes and retrieve our work here
  for _, PrefixAux in ipairs(IPv6refijosTotales) do
    Direccion, Prefijo = itsismx.Extract_IPv6_Add_Prefix(PrefixAux)
    bSalida, tSalida.Nodos, sError = CrearRangoHosts(Direccion, Prefijo, 
                                          TablaPalabras, User_Segs, User_Right)

    if bSalida ~= true then
      stdnse.print_verbose(2, SCRIPT_NAME ..
      ": There was a error for the prefix: " .. PrefixAux ..
      " Message:" .. sError)
    end

    if sError ~= "" then
      -- Not all the error are fatal for the script.
      tSalida.Error = tSalida.Error .. "\n" .. sError
    end

  end


  return true, tSalida
end


---
-- The script need to be working with IPv6
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
  local tOutput = {}
  tOutput = stdnse.output_table()
  local bExito = false
  local tSalida = {
    Nodos = 0,
    Error = "",
  }

 -- itsismx.Registro_Global_Inicializar "wordis" -- Prepare everything!

  bExito, tSalida = Prescanning()

  -- Now we adapt the exit to tOutput and add the hosts to the target!
  tOutput.warning = tSalida.Error

  if bExito then
    if tSalida.Nodos == 0 then
    stdnse.print_verbose(2, SCRIPT_NAME .. "No nodes were added " ..
    " to scan list! You can increase verbosity for more information" ..
	" (maybe not newtargets argument?) ")
    end
  end

  table.insert(tOutput, "Were added " ..
            tSalida.Nodos .. " nodes to the host scan phase")




  return stdnse.format_output(bExito, tOutput)
end
