---
-- This library implements common tools for all the  NSE scripts of:
-- targets-ipv-6recon (Aka: Itsismx for global registry)

--@author Raul Fuentes <ra.fuentes.sam+nmap@gmail.com>
--@copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--

-- Version 1.2
-- Updated 06/05/2014 - V1.2 Minor corrections and standardization. 
-- Updated: 08/08/2013   V 1.0
-- Created 01/03/2013 - v0.1 - created by Raul Fuentes <ra.fuentes.sam@gmail.com>
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local strict = require "strict"
local math = require "math"
_ENV = stdnse.module("targets-ipv6-recon", stdnse.seeall)


--[[ Tools for  brute sweep of IPv6 Address

  There are two  different methods: 
  1 - Strings  representing bits 
  2- 4 numbers of 32 bits
  
  Originally  were to use classes for those but  had problems creating
  independently instances of the class (because LUA it's  not a oriented 
  object language) so, the classical approach of functions was used.
–]]


---; 
--Return a number from a binary value represented on string
--
-- Curiosity: "Mordidas" is a VERY BAD Translation to spanish of bits
--  @param  A string of 32 characters that area binary (0 | 1 )
--  @returns  Numeric value of those 32 bits
local Bits32_BinToNumber = function ( Mordidas ) 
  local iValor,iPos = 0,0
  
  if string.len(Mordidas) ~= 32 then -- We only work with 32 bits 
    return iValor
  end 
  
  
  --There is something odd how Nmap use Dword for IP address of 32
  --bits making me  choice a more "pure" way to do it
  Mordidas:reverse() --More easy to my head 
  for iPos=1, 32 ,  1 do 
  iValor = iValor + tonumber( Mordidas:sub(iPos,iPos) ) * math.pow(2,32 - iPos)
  end
  return iValor
end
 
---;
--  Return binary value (on strings) of a number.
--  @param    Numeric value of 32 bits (Actually more than that)
--  @returns  A string of 32 characters that are binary (0 | 1 ) 
--            The first 32 bits of the args given.
local Bits32_NumberToBin= function ( Decimal )
    local Mordidas,iPos = "",0
    
    --Lua 5.2 give us a easy time doing this!
    for iPos=31,0, -1 do
      Mordidas = Mordidas ..  tostring ( bit32.extract (Decimal, iPos, 1 ) )
    end
    
    return Mordidas
end  

---; 
--  We sum our number of 128 bits, against another number of 128 bits  using a
--  special structure.
--  @param    NumberA  A table having 4 variables
--  @param    NumberX  A table having 4 variables
--  @returns  A table having 4 variables
--            If there is a error or Overflow will return all bits set to one
local Bits32_suma128 = function ( NumberA, NumberX)

  -- We sum the parts
  NumberA.ParteAltaH = NumberA.ParteAltaH + NumberX.ParteAltaH
  NumberA.ParteAltaL = NumberA.ParteAltaL + NumberX.ParteAltaL
  NumberA.ParteBajaH = NumberA.ParteBajaH + NumberX.ParteBajaH
  NumberA.ParteBajaL = NumberA.ParteBajaL + NumberX.ParteBajaL
  
  
  --We validate  Zero Overflow!
  if (NumberA.ParteBajaL >= math.pow(2,32) ) then
    NumberA.ParteBajaL = 0
    NumberA.ParteBajaH = NumberA.ParteBajaH + 1
    if (NumberA.ParteBajaH >= math.pow(2,32) ) then
      NumberA.ParteBajaH = 0
      NumberA.ParteAltaL = NumberA.ParteAltaL + 1
      if (NumberA.ParteAltaL >= math.pow(2,32) ) then
        NumberA.ParteAltaL = 0;
        NumberA.ParteAltaH = NumberA.ParteAltaH + 1
        if (NumberA.ParteAltaH >= math.pow(2,32) ) then
          --SCREW THIS!  Overflow
          NumberA.ParteAltaH = 0xFFFFFFFF
          NumberA.ParteAltaL = 0xFFFFFFFF
          NumberA.ParteBajaH = 0xFFFFFFFF
          NumberA.ParteBajaL = 0xFFFFFFFF
        end
      end
    end
  end
  
  return NumberA
end

---;
-- 1-bit Binary adder with Carry. 
--
-- Actually it's pseudo-bit because got strings and 
-- return strings (Only 1 and 0) . It's slower 
-- than using real numbers but it's a good option for 
-- IPv6.
-- @param  A  A String of 1 bits
-- @param  B  A String of 1 bits
-- @param  Cin  A String of 1 bit - Carry In
-- @return String  A string of 1 bits
-- @return String  A string of 1 bit ( Carry out)
local Sumador =  function (A, B, Cin )
  --Bless coercion
  local S, Cout = 0,0
  S = bit32.bxor( A, B, Cin ) 
  Cout =  bit32.bor (bit32.band(A, B),bit32.band(Cin ,bit32.bor( A, B ) ))
  
  return  tostring( S),  tostring(Cout)
  
 end

---; 
-- 8-bits Binary adder with Carry. 
--
-- Actually it's pseudo-bit because got strings and  return strings
--(Only 1 and 0). Is slower than using real numbers but it's a good option
-- for IPv6. 
-- @param  A  A String of 8 bits
-- @param  B  A String of 8 bits
-- @param  Cin  A String of 1 bit - Carry In
-- @return String  A string of 8 bits
-- @return String  A string of 1 bit ( Carry out)
local Sumador8bits = function ( A, B, Cin)
  
  local  S, Cout, Caux = {}, "0","0" 
  local  aA, aB = "", ""
  local Sstring = ""
  
  -- DANGER: No leer al reves el numero
  -- Bless "Class" mechanism of Lua
  aA = A:sub(8,8)
  aB = B:sub(8,8)
    
  S[8], Caux = Sumador(aA, aB, Cin)
  Caux = tostring(Caux)
  
  for I = 7,2,-1 do 
    aA = A:sub(I,I)
    aB = B:sub(I,I)
    S[I],Caux = Sumador(aA, aB, Caux)

    Caux = tostring(Caux)
  end
  
  aA = A:sub(1,1)
  aB = B:sub(1,1)
  
  S[1],Cout = Sumador(aA, aB, Caux)

  for  I= 1,8 do
    Sstring = Sstring .. tostring( S[I])
  end
  
  return Sstring,  tostring(Cout)
end

---;
-- 16-bits Binary adder with Carry. 
--
-- Actually it's pseudo-bit because got strings and  return strings
--(Only 1 and 0). Is slower than using real numbers but it's a good option
-- for IPv6. 
-- @param  A  A String of 16 bits
-- @param  B  A String of 16 bits
-- @param  Cin  A String of 1 bit - Carry In
-- @return String  A string of 16 bits
-- @return String  A string of 1 bit ( Carry out)
local Sumador16bits = function ( A, B, Cin)
  
  local  S, Cout, Caux = {}, "0","0" 
  local  aAH,aAL, aBH,aBL = "", "","", ""
  local Sstring = ""
  
  -- Bless "Class" mechanism of Lua
  aAH = A:sub(1,8)
  aAL = A:sub(9,16)
  aBH = B:sub(1,8)
  aBL = B:sub(9,16)
 
  S[2], Caux = Sumador8bits(aAL, aBL, Cin)
  Caux = tostring(Caux)
  
  S[1], Cout= Sumador8bits( aAH,  aBH,  Caux)
  
  Sstring = S[1] .. S[2]
  
  return Sstring,  tostring(Cout)
end

---;
-- 32-bits Binary adder with Carry.
-- 
-- Actually it's pseudo-bit because got strings and  return strings
--(Only 1 and 0). Is slower than using real numbers but it's a good option
-- for IPv6. 
-- Useful for IPv4 (Thought Nmap can do it better)
-- @param  A  A String of 32 bits
-- @param  B  A String of 32 bits
-- @param  Cin  A String of 1 bit - Carry In
-- @return String  A string of 32 bits
-- @return String  A string of 1 bit ( Carry out)
local Sumador32bits = function ( A, B, Cin)
  
  local  S, Cout, Caux = {}, "0","0" 
  local  aAH,aAL, aBH,aBL = "", "","", ""
  local Sstring = ""
  
  -- We divide on blocks of 16 
  aAH = A:sub(1,16)
  aAL = A:sub(17,32)
  aBH = B:sub(1,16)
  aBL = B:sub(17,32)
  
  S[2], Caux = Sumador16bits(aAL, aBL, Cin)
  Caux = tostring(Caux)
  
  S[1], Cout= Sumador16bits( aAH,  aBH,  Caux)
  
  Sstring = S[1] .. S[2]
  
  return Sstring,  tostring(Cout)
end

---;
-- 64-bits Binary adder (String) with Carry.
-- Useful for when using the Node Portion of IPv6
-- @param  A  A String of 64 bits
-- @param  B  A String of 64 bits
-- @param  Cin  A String of 1 bit - Carry In
-- @return String  A string of 64 bits
-- @return String  A string of 1 bit ( Carry out)
local Sumador64bits = function ( A, B, Cin)
  
  local  S, Cout, Caux = {}, "0","0" 
  local  aAH,aAL, aBH,aBL = "", "","", ""
  local Sstring = ""
  
  -- We divide on blocks of 16 
  aAH = A:sub(1,32)
  aAL = A:sub(33,64)
  aBH = B:sub(1,32)
  aBL = B:sub(33,64)
    
  S[2], Caux = Sumador32bits(aAL, aBL, Cin)
  Caux = tostring(Caux)

  S[1], Cout= Sumador32bits( aAH,  aBH,  Caux)
  
  Sstring = S[1] .. S[2]
  
  return Sstring,  tostring(Cout)
end

---;
-- 128-bits Binary adder with Carry. 
-- Actually it's pseudo-bit because got strings and  return strings
--(Only 1 and 0). Is slower than using real numbers but it's a good option
-- for IPv6. 
-- Useful for when using the Node Portion of IPv6
-- @param  A  A String of 128 bits
-- @param  B  A String of 128 bits
-- @param  Cin  A String of 1 bit - Carry In
-- @return String  A string of 128 bits
-- @return String  A string of 1 bit ( Carry out)
local Sumador128bits = function ( A, B, Cin)
  
  local  S, Cout, Caux = {}, "0","0" 
  local  aAH,aAL, aBH,aBL = "", "","", ""
  local Sstring = ""
  
  -- We divide on blocks of 16 
  aAH = A:sub(1,64)
  aAL = A:sub(65,128)
  aBH = B:sub(1,64)
  aBL = B:sub(65,128)
  
  S[2], Caux = Sumador64bits(aAL, aBL, Cin)
  Caux = tostring(Caux)
  
  S[1], Cout= Sumador64bits( aAH,  aBH,  Caux)
  
  Sstring = S[1] .. S[2]
  
  return Sstring,  tostring(Cout)
end


---; 
-- This function will always return the next immediately IPv6 address.
--  This work only with String format.
-- @param  IPv6Address  A String IPv6 address X:X:X:X:X:X:X:X
-- @param  Prefix  Optional Prefix. If it-s provided the function will check
--         to do sum with lesser bits (64, 32, 16 or 8)
-- @returns  String 128 bits of a IPv6 Address
local GetNext_AddressIPv6_String = function(IPv6Address, Prefix)

  local UNO
  local Next

  UNO = ipOps.ip_to_bin("::1")    
    
  if (not  Prefix )  then -- nil?
    Next = Sumador128bits( IPv6Address, UNO , "0")
  elseif ( Prefix > 120) then
    Next = Sumador8bits( IPv6Address:sub(121,128), UNO:sub(121,128) , "0")
    Next = IPv6Address:sub(1,120) .. Next
  elseif (  Prefix > 112) then
    Next = Sumador16bits( IPv6Address:sub(113,128), UNO:sub(113,128) , "0")
    Next = IPv6Address:sub(1,112) .. Next
  elseif (  Prefix > 96) then 
    Next = Sumador32bits( IPv6Address:sub(97,128), UNO:sub(97,128) , "0")
    Next = IPv6Address:sub(1,96) .. Next
  elseif (  Prefix > 64) then
    Next = Sumador64bits( IPv6Address:sub(65,128), UNO:sub(65,128) , "0")
    Next = IPv6Address:sub(1,64) .. Next
  else -- Wasn't need the Prefix but anyway...
    Next = Sumador128bits( IPv6Address, UNO , "0")
  end
  
  return Next
end

---; 
-- This function will always return the next immediately IPv6
-- address. This work only with a structure of 4 numbers.
-- @param  IPv6Address  A String IPv6 address  X:X:X:X:X:X:X:X
-- @param  Prefix  Optional Prefix. If its provided the function will 
--                 check to do sum with lesser bits (64, 32, 16 or 8)
-- @returns  String 128 bits of a IPv6 Address
local GetNext_AddressIPv6_4Structure = function(IPv6Address, Prefix)
  local UNO
  local Next, Current
  
  Current = { ParteAltaH = 0, ParteAltaL = 0, ParteBajaH = 0, ParteBajaL = 0 }
  UNO =     { ParteAltaH = 0, ParteAltaL = 0, ParteBajaH = 0, ParteBajaL = 1 }
  
  Current.ParteAltaH =  Bits32_BinToNumber( IPv6Address:sub(1,32)  )
  Current.ParteAltaL =  Bits32_BinToNumber( IPv6Address:sub(33,64)  )    
  Current.ParteBajaH =  Bits32_BinToNumber( IPv6Address:sub(65,96)  )
  Current.ParteBajaL =  Bits32_BinToNumber( IPv6Address:sub(97,128)  )
  
  -- Now we add those numbers and make Casting (abusing a little of Lua)
  Next = Bits32_suma128(Current,UNO )
  Next = Bits32_NumberToBin( Next.ParteAltaH) .. 
       Bits32_NumberToBin( Next.ParteAltaL) .. 
       Bits32_NumberToBin( Next.ParteBajaH) .. 
       Bits32_NumberToBin( Next.ParteBajaL)
  
  return Next
end

--[[ Global Functions

  Those are  global functions  called by any script.

--]]


---
-- This function will always return the next immediately IPv6 address.
-- 
-- We work with 2 very different approach: Strings or Numbers he first make 
-- Boolean operations with strings and the second make math with 4 separated
-- numbers.
-- 
-- Note: By default use the 128 bits for adding but if the the prefix its big
-- can be a waste, that is why  there is a option for reduce the number of bits
-- to sum for the String case. 
-- @param  IPv6Address  A String IPv6 address X:X:X:X:X:X:X:X
-- @param  (Optional) Prefix. If it-s provided the function will check to do
--         sum with  lesser bits(64, 32, 16 or 8) but only work if we are
--         using "String".
-- @param  IPv6_Mech_Operator A string which represent the mechanism for 
--         calculating the next IPv6 Address. Values:
--          string - Use pseudo binary operations 
--          number - Divide the IPv6 in 4 numbers of 32 bits (Mathematical
--                   operations)
--              
-- @return String Formatted full IPv6 X:X:X:X:X:X:X:X)
 GetNext_AddressIPv6 = function(IPv6Address, Prefix, IPv6_Mech_Operator)

  local Next = "::"   
  --First... Which mechanism?  
  IPv6Address = ipOps.ip_to_bin(IPv6Address)     
  if   IPv6_Mech_Operator == nil then  
    --Next = GetNext_AddressIPv6_String(IPv6Address, Prefix)
    Next = GetNext_AddressIPv6_4Structure(IPv6Address, Prefix)
  elseif IPv6_Mech_Operator:lower(IPv6_Mech_Operator) == "string"  then 
    --  We create two specials tables
    Next = GetNext_AddressIPv6_String(IPv6Address, Prefix)
        
  elseif  IPv6_Mech_Operator:lower(IPv6_Mech_Operator) == "number" then  
    
    Next = GetNext_AddressIPv6_4Structure(IPv6Address, Prefix)
  end  -- For the moment are the only cases, if something come wrong Next
       -- is a invalid IPv6 address
    
  return ipOps.bin_to_ip(Next)
end 

---
--  This function will always return the next immediately  IPv4 address.
--
--  We use only Dword operations for calculating so, there is no more options.
-- @param  IPv6Address  A String IPv6 address X:X:X:X:X:X:X:X 
-- @return String Formatted full IPv6 X:X:X:X:X:X:X:X)
GetNext_AddressIPv4 = function (IPv4ddress) 
  
  local Next, aux, Octetos
  local d,c,b,a
  local IPN = ipOps.todword( IPv4ddress ) + 1
  
  aux = ipOps.fromdword (IPN)
  -- Oddly Nmap 6.25 change the octets order instead of  A.B.C.D return 
  -- D.C.B.A
   Octetos = ipOps.get_parts_as_number(aux) 
  if Octetos then d,c,b,a = table.unpack( Octetos ) end
  
  Next = a .. "." .. b .. "." .. c .. "."  .. d 
      
  return Next

end

---
-- Receive X:X:X:X::/YY and return two separated fields: IPv6 Address and
-- Prefix.
--   
--  The lesser prefix that return it's 48 because before usually is IANA Field.
-- @param  IPv6PRefix  A String IPv6 address with Prefix: X:X:X:X::/YY
-- @return String  Formatted full IPv6 ( X:X:X:X:: )
-- @return Number  Prefix number (0-128)
 function Extract_IPv6_Add_Prefix(IPv6PRefix)
  local Campos = {}
  local Dirre6, Prefijo --= "", 0

  Campos = stdnse.strsplit("/",IPv6PRefix )
  
  Dirre6 = Campos[1]
  Prefijo = tonumber( Campos[2] )
  
  if  Prefijo < 48 then
    Prefijo = 48
  end
  
  return Dirre6, Prefijo
end

--- 
-- This function will initialize the global registry nmap.registry.itsismx 
--
-- Will check if was already called by one previous script if not, will
-- create it. In both cases  a sub entry will be generated too.
-- @param String with the prefix for the global registry to check.
  Registro_Global_Inicializar =  function ( Registro )

  local Global = nmap.registry.itsismx
    
  if Global  == nil  then --The first script to run initialize the register
    
    Global = {}
    Global[Registro] = {}
    
    nmap.registry.itsismx = Global
    
  elseif  Global[Registro] == nil then -- Don't overwrite other registry
    nmap.registry.itsismx[Registro]  = {}
    
  end -- This Ok, a previous script, or maybe a previous run of our script 
      -- had already  create. 
end

---
-- This function will read a register from nmap.registry.itsismx 
-- 
-- Originally, all the scripts passed  information to a final
-- post-script and as result there were 5 registers  to read. 
-- Now only DHCPv6 generate a global register accessed by everyone.
-- @param String with the prefix for the global registry to check.
-- @return The element on the registry or NIL 
  Registro_Global_Leer = function ( Registro )
 
   local Global = nmap.registry.itsismx
   -- If no script has initialized the global, then nothing more 
   -- to do.
   if Global == nil then
	return nil
   else 
    return Global[Registro]
  end
end
 
---
-- Convert Decimal number to Hexadecimal. 
--
-- Taken from:
-- http://snipplr.com/view/13086/
-- @param   Number    A Lua number format
-- @return  String    String representing Hexadecimal value 
function DecToHex(Number)
    local hexstr = '0123456789abcdef'
    local s = ''
    while Number > 0 do
        local mod = math.fmod(Number, 16)
        s = string.sub(hexstr, mod+1, mod+1) .. s
        Number = math.floor(Number / 16)
    end
    if s == '' then s = '0' end
    return s
end

---
-- Confirm if a given String is a OUI or not. 
--
-- the OUI are 6 hexadecimal characters.
-- @param   OUI      String representing the potential OUI
-- @return  Boolean  TRUE if a OUI valid format, otherwise false
Is_Valid_OUI = function (  OUI )

  --Robust and simple
  if OUI == nil then 
    return false
  elseif type(OUI )  ~= "string" then
    return false
  elseif #OUI ~= 6 then
    return false
  end
  
  local hexstr = '0123456789abcdef'
  local Index, Caracter = 1, ""

  --Now begin the process 
  for Index = 1, 6 do 
    Caracter = OUI:sub(Index,Index)
    if  hexstr:find(Caracter) == nil then
      return false
    end
  end
  
  return true
end 

---
-- Get a binary number represent with strings. Will check than only have
-- zeroes and ones.
-- @param  Bits  String representing a binary value.
-- @return  Boolean  TRUE if is a valid binary number, otherwise false. 
Is_Binary = function ( Bits )
  local i 
   for i = 1 , #Bits  do 
    if Bits:sub(i,i) ~= "0" and Bits:sub(i ,i) ~= "1" then
      return false
    end
   end
  
  return true
end


--- 
-- This function will do NOTHING but kill time. 
--
-- LUA does not provide something similar. 
-- This only is useful IF WE NEED TO WAIT or KILL TIME for avoid detections
-- on pre-scanning or post-scanning phases. as Nmap provide more powerful
-- tools  for the other two phases.
-- @param micrseconds   Number of microseconds to wait
waitUtime = function ( micrseconds ) 
  
  local start = stdnse.clock_us ()
  repeat until stdnse.clock_us () > start + micrseconds
  
end

---
-- Convert hexadecimal characters (Strings) to binary (Strings).
-- 
-- For some part of the script, I need to work bits separated before be able
-- to use the functions of ipOPs library. So, We need be able to convert from
-- hex to binary.
--  NOTE: THIS NEEDS WORK
-- @param  Number  String  representing hexadecimal number.
-- @return String  String  representing binary number (Nil if there is a error)
HextToBin = function( Number )

  local Bits , hex, index = ""
  Number = Number:lower()
  for index = 1, #Number do
    hex = Number:sub(index,index)
    
    if hex == "0" then
      Bits = Bits .. "0000"
    elseif hex == "1" then
      Bits = Bits .. "0001"
    elseif hex == "2" then
      Bits = Bits .. "0010"
    elseif hex == "3" then
      Bits = Bits .. "0011"
    elseif hex == "4" then
      Bits = Bits .. "0100"
    elseif hex == "5" then
      Bits = Bits .. "0101"
    elseif hex == "6" then
      Bits = Bits .. "0110"
    elseif hex == "7" then
      Bits = Bits .. "0111"
    elseif hex == "8" then
      Bits = Bits .. "1000"
    elseif hex == "9" then
      Bits = Bits .. "1001"
    elseif hex == "a" then
      Bits = Bits .. "1010"
    elseif hex == "b" then
      Bits = Bits .. "1011"
    elseif hex == "c" then
      Bits = Bits .. "1100"
    elseif hex == "d" then
      Bits = Bits .. "1101"
    elseif hex == "e" then
      Bits = Bits .. "1110"
    elseif hex == "f" then
      Bits = Bits .. "1111"
    elseif  hex == "." or hex == ":" then --Nothing bad happens
    --  return nil
    else 
      --return nil
    end
  end
  return Bits
end


---
-- This will get any valid IPv6 address and will expand it WITH all the bytes  
-- returning a string of bytes
-- @param   IPv6_Address  String  representing IPv6 Address
-- @return  String        String representing  16 bytes of  IPv6 Address
Expand_Bytes_IPv6_Address = function ( IPv6_Address )
  
  local Segmentos, HexSeg, linkAdd = {}
  local S1, S2, S3, S4, S5, S6, S7, S8
  Segmentos = ipOps.get_parts_as_number(IPv6_Address)
  S1, S2, S3, S4, S5, S6, S7, S8 = table.unpack( Segmentos )
  linkAdd = ""
  
  HexSeg = DecToHex(S1)
  while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
  linkAdd = linkAdd .. HexSeg
  
  HexSeg = DecToHex(S2)
  while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
  linkAdd = linkAdd .. HexSeg
  
  HexSeg = DecToHex(S3)
  while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
  linkAdd = linkAdd .. HexSeg
  
  HexSeg = DecToHex(S4)
  while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
  linkAdd = linkAdd .. HexSeg
  
  HexSeg = DecToHex(S5)
  while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
  linkAdd = linkAdd .. HexSeg
  
  HexSeg = DecToHex(S6)
  while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
  linkAdd = linkAdd .. HexSeg
  
  HexSeg = DecToHex(S7)
  while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
  linkAdd = linkAdd .. HexSeg
  
  HexSeg = DecToHex(S8)
  while #HexSeg < 4 do HexSeg = "0" .. HexSeg end
  linkAdd = linkAdd .. HexSeg

  return linkAdd
end


return _ENV;