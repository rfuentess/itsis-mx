---
-- This library implements common tools for all the  NSE scripts 
-- of ITSISMX.
-- The library contains the following classes:
--

--@author Raul Fuentes <ra.fuentes.sam@gmail.com>
--@copyright Same as Nmap--See http://nmap.org/book/man-legal.html

--
-- Version 0.2
-- 
-- Created 01/03/2013 - v0.1 - created by Raul Fuentes <ra.fuentes.sam@gmail.com>
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local strict = require "strict"
local math = require "math"
_ENV = stdnse.module("itsismx", stdnse.seeall)




--[[ Tools for  brute sweep of IPv6 Addrss

	There are two  differents methods: 
	1 - Strings  representing bits  
	2- 4 numbers of 32 bits

	Originally think to use class for those bu  have problem 
	creating independently instances of the class (because LUA it-  not 
	a oriented object language)  so at the end choice the use the clasical 
	aproach of functions.
	
--]]


--- Return a number from a binary value reprsent on string
-- Curiosity: "Mordidas" is a VERY BAD Translation of bits
--	@args		A string of 32 characters that area binary (0 | 1 )
--  @returns	Numeric value of those 32 bits
local Bits32_BinToNumber = function ( Mordidas ) 
	local iValor,iPos = 0,0
	--print("Longitud " .. #Mordidas .. " de " .. Mordidas)
	
	if string.len(Mordidas) ~= 32 then -- We only work with 32 bits 
		return iValor
	end 
	
	
	--There is something odd how Nmap use Dword for IP address of 32
	--bits making me  choice a more "pure" way to do it
	Mordidas:reverse() --More easy to my head 
	for iPos=1, 32 ,  1 do 
		--print("\t\t\t" .. #Mordidas:sub(iPos,iPos) .. " " ..Mordidas:sub(iPos,iPos))
		iValor = iValor + tonumber( Mordidas:sub(iPos,iPos) ) * math.pow(2,32 - iPos)
		--print ( "\t\t" .. Mordidas:sub(iPos,iPos) .. " * 2^" .. 32 - iPos )
	end
	--print ("\t BinToNumber: ", iValor)
	return iValor
end
 
--- Return binary value (on strings) of a number.
--	@args		Numeric value of 32 bits (Actually more than that)
--  @returns	A string of 32 characters that area binary (0 | 1 ) 
--				The first 32 bits of the args given.
local Bits32_NumberToBin= function ( Decimal )
		local Mordidas,iPos = "",0
		
		--Lua 5.2 give us a easy time doing this!
		for iPos=31,0, -1 do
			Mordidas = Mordidas ..  tostring ( bit32.extract (Decimal, iPos, 1 ) )
		end
		
		--print ("\t NumberToBin: ", Mordidas )
		return Mordidas
end	

--- We sum our number of 128 bits, against another number of 128 bits  using 
--  special structure.
--	@args	NumberA	A table having 4 variables
--	@args	NumberX	A table having 4 variables
--  @returns	A table having 4 variables
--  			If there is a error or Overflow will return all bits set to one
local Bits32_suma128 = function ( NumberA, NumberX)

	--print(NumberA.ParteAltaH ..  NumberA.ParteAltaL .. NumberA.ParteBajaH  .. NumberA.ParteBajaL)
	--print(NumberX.ParteAltaH ..  NumberX.ParteAltaL .. NumberX.ParteBajaH  .. NumberX.ParteBajaL)
		
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
	
	--print(NumberA.ParteAltaH ..  NumberA.ParteAltaL .. NumberA.ParteBajaH  .. NumberA.ParteBajaL)

	return NumberA
end

---
-- 1-bit Binary adder with Carry. 
-- Actually it.s pseudo-bit because got strings and 
-- return strings (Onlye 1 and 0) . It's slower 
-- than using real numbers but it's a good option for 
-- IPv6.
-- @args			A	A String of 1 bits
-- @args			B	A String of 1 bits
-- @args			Cin	A String of 1 bit - Carry In
-- @return String	A string of 1 bits
-- @return String	A string of 1 bit ( Carry out)
local Sumador =  function (A, B, Cin )
	--Bless coercion
	local S, Cout = 0,0
	S = bit32.bxor( A, B, Cin ) 
	Cout =  bit32.bor (bit32.band(A, B),bit32.band(Cin ,bit32.bor( A, B ) ))
	
	return  tostring( S),  tostring(Cout)
	
 end

---
-- 8-bits Binary adder with Carry. 
-- Actually it.s pseudo-bit because got strings and 
-- return strings (Onlye 1 and 0) . It's slower 
-- than using real numbers but it's a good option for 
-- IPv6.
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
	--print("A[8]: " .. aA .. " B[8]: " .. aB .. " S[8]: " .. S[8] .. " C: " .. Caux )
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

---
-- 16-bits Binary adder with Carry. 
-- Actually it.s pseudo-bit because got strings and 
-- return strings (Onlye 1 and 0) . It's slower 
-- than using real numbers but it's a good option for 
-- IPv6.
-- @args	A	A String of 16 bits
-- @args	B	A String of 16 bits
-- @args	Cin	A String of 1 bit - Carry In
-- @return String	A string of 16 bits
-- @return String	A string of 1 bit ( Carry out)
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

-- Sumador binario de 32 bits (String) con acarreo
-- 32-bits Binary adder with Carry. 
-- Actually it.s pseudo-bit because got strings and 
-- return strings (Onlye 1 and 0) . It's slower 
-- than using real numbers but it's a good option for 
-- IPv6.
-- Useful for IPv4 (Thought Nmap can do it better)
-- @args	A	A String of 32 bits
-- @args	B	A String of 32 bits
-- @args	Cin	A String of 1 bit - Carry In
-- @return String	A string of 32 bits
-- @return String	A string of 1 bit ( Carry out)
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

-- Sumador binario de 64 bits (String) con acarreo
-- Useful for when using the Node Portion of IPv6
-- @args	A	A String of 64 bits
-- @args	B	A String of 64 bits
-- @args	Cin	A String of 1 bit - Carry In
-- @return String	A string of 64 bits
-- @return String	A string of 1 bit ( Carry out)
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

---
-- 128-bits Binary adder with Carry. 
-- Actually it.s pseudo-bit because got strings and 
-- return strings (Onlye 1 and 0) . It's slower 
-- than using real numbers but it's a good option for 
-- IPv6.
-- Useful for when using the Node Portion of IPv6
-- @args	A	A String of 128 bits
-- @args	B	A String of 128 bits
-- @args	Cin	A String of 1 bit - Carry In
-- @return String	A string of 128 bits
-- @return String	A string of 1 bit ( Carry out)
local Sumador128bits = function ( A, B, Cin)
	
	local  S, Cout, Caux = {}, "0","0" 
	local  aAH,aAL, aBH,aBL = "", "","", ""
	local Sstring = ""
	
	-- We divide on blocks of 16 
	aAH = A:sub(1,64)
	aAL = A:sub(65,128)
	aBH = B:sub(1,64)
	aBL = B:sub(65,128)
	
	--print("\t\tAH: " .. aAH .. " BH: " .. aBH)
	--print("\t\tAL: " .. aAL .. " BL: " .. aBL)
	 -- print(A)
	 -- print(B)
	-- print(aAH)
	-- print(aAL)
	-- print(aBH)
	-- print(aBL)
	
	S[2], Caux = Sumador64bits(aAL, aBL, Cin)
	Caux = tostring(Caux)
	
	--print("SL: " .. S[2] .. " C: " .. Caux)
	
	S[1], Cout= Sumador64bits( aAH,  aBH,  Caux)
	
	Sstring = S[1] .. S[2]
	
	
	return Sstring,  tostring(Cout)
end


--- This function will always return the next inmediatly  IPv6
-- address. This work only with String format.
-- @args	IPv6Address	A String IPv6 address  X:X:X:X:X:X:X:X
-- @args	Prefix	Optional Prefix. If it-s provided the function 
--			 will check to do sum with lesser bits (64, 32, 16 or 8)
-- @returns	String 128 bits of a IPv6 Address
local GetNext_AddressIPv6_String = function(IPv6Address, Prefix)

	local UNO
	local Next

	UNO = ipOps.ip_to_bin("::1")		
		
	if (not  Prefix )  then -- nil?
		--print("NIL")
		Next = Sumador128bits( IPv6Address, UNO , "0")
	elseif ( Prefix > 120) then
		--print(">= 120")
		Next = Sumador8bits( IPv6Address:sub(121,128), UNO:sub(121,128) , "0")
		Next = IPv6Address:sub(1,120) .. Next
	elseif (  Prefix > 112) then
		--print(">= 112")
		Next = Sumador16bits( IPv6Address:sub(113,128), UNO:sub(113,128) , "0")
		Next = IPv6Address:sub(1,112) .. Next
	elseif (  Prefix > 96) then
		--print ( ">96") 
		Next = Sumador32bits( IPv6Address:sub(97,128), UNO:sub(97,128) , "0")
		Next = IPv6Address:sub(1,96) .. Next
		
	elseif (  Prefix > 64) then
		--print ( ">64") 
		Next = Sumador64bits( IPv6Address:sub(65,128), UNO:sub(65,128) , "0")
		Next = IPv6Address:sub(1,64) .. Next
	else -- Wasn't need the Prefix but anyway...
		Next = Sumador128bits( IPv6Address, UNO , "0")
	end
	
	return Next
end

--- This function will always return the next inmediatly  IPv6
-- address. This work only with a structure of 4 numbers.
-- @args	IPv6Address	A String IPv6 address  X:X:X:X:X:X:X:X
-- @args	Prefix	Optional Prefix. If it-s provided the function 
--			 will check to do sum with lesser bits (64, 32, 16 or 8)
-- @returns	String 128 bits of a IPv6 Address
local GetNext_AddressIPv6_4Structure = function(IPv6Address, Prefix)
	local UNO
	local Next, Current
	
	--print("\t lineal")
	Current = 	{ ParteAltaH = 0, ParteAltaL = 0, ParteBajaH = 0, ParteBajaL = 0 }
	UNO = 		{ ParteAltaH = 0, ParteAltaL = 0, ParteBajaH = 0, ParteBajaL = 1 }
	
	--print(#Current)
	--print(Current.ParteAltaH ..  Current.ParteAltaL .. Current.ParteBajaH  .. Current.ParteBajaL)
	--print(IPv6Address)
	Current.ParteAltaH =  Bits32_BinToNumber( IPv6Address:sub(1,32)  )
	Current.ParteAltaL =  Bits32_BinToNumber( IPv6Address:sub(33,64)  )		
	Current.ParteBajaH =  Bits32_BinToNumber( IPv6Address:sub(65,96)  )
	Current.ParteBajaL =  Bits32_BinToNumber( IPv6Address:sub(97,128)  )
	
	--print(#Current)
	--print(#UNO)
	-- Now we add those numbers and make Casting (abusing a little of Lua)
	Next = Bits32_suma128(Current,UNO )
	Next = Bits32_NumberToBin( Next.ParteAltaH) .. 
		   Bits32_NumberToBin( Next.ParteAltaL) .. 
		   Bits32_NumberToBin( Next.ParteBajaH) .. 
		   Bits32_NumberToBin( Next.ParteBajaL)
	
	return Next
end

--[[ Global Functions

	Those are the global function that can be called by any script.
--]]


---
-- This function will always return the next inmediatly  IPv6
-- address.  
-- We work with 2 very differents aproachs: Strings or Numbers
-- the first make booleans operation with strings and the second
-- make math with 4 separed numbers.
-- Note: By default use the 128 bits for adding but if the 
-- the prefix its big can be a waste, that is why  there is a option 
-- for reduce the number of bits to sum (String case only). 
-- @args	IPv6Address	A String IPv6 address  X:X:X:X:X:X:X:X
-- @args	(Optional) Prefix. If it-s provided the function 
--			 will check to do sum with lesser bits (64, 32, 16 or 8)
--			 but only work if we are using "String"
-- @args 	IPv6_Mech_Operator A string which represent the mechanis 
--			 for calculating the next IPv6 Address. Values:
--				string 	- (Default) use pseudo binary operations 
--				number	- Divide the IPv6 in 4 numbers of 32 bits 
--						  (Mathematical operations)
-- @return String Formated full IPv6 X:X:X:X:X:X:X:X)
 GetNext_AddressIPv6 = function(IPv6Address, Prefix, IPv6_Mech_Operator)

	local Next = "::"
	-- 64 prefix left 64 bits to search
	-- 96 Prefix left 32 bits to search
	-- 112 prefix left 16 bits to search
	-- 120 prefix left  8 bits to search
		
	--First... Which mechanism?	
		
	--print(IPv6Address)
	IPv6Address = ipOps.ip_to_bin(IPv6Address)	 	
	if 	IPv6_Mech_Operator == nil then	
		Next = GetNext_AddressIPv6_String(IPv6Address, Prefix)
		
	elseif IPv6_Mech_Operator:lower(IPv6_Mech_Operator) == "string"  then --  We create two specials tables
		
		Next = GetNext_AddressIPv6_String(IPv6Address, Prefix)
			  
	elseif  IPv6_Mech_Operator:lower(IPv6_Mech_Operator) == "number" then	
		
		Next = GetNext_AddressIPv6_4Structure(IPv6Address, Prefix)
	end	-- For the moment are the only case, is something come wrong Next is a invalid IPv6 address
		
		
	return ipOps.bin_to_ip(Next)
end 

---
--  This function will always return the next inmediatly  IPv4 address.
--   We use only Dword operations for calculating so, there is no more options for this.  
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
-- Receive X:X:X::/YY and return two separated fields: 
-- IPv6 ADdress and Prefix.
--  The lesser prefix that return it's 48 because before that 
-- is IANA Field.
-- @args	IPv6PRefix	A String IPv6 address with Prefix: X:X:X::/YY
-- @return String	Formated full IPv6 ( X:X:X:: )
-- @return Number	Prefix number (0-128)
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
-- As this is global will check if was already called by one previous script 
-- if not, will create it. In both cases  a sub entry
  Registro_Global_Inicializar =  function ( Registro )

	local Global = nmap.registry.itsismx
		
	if Global  == nil  then --The first script to run initialice all the register
		
		Global = {}
		Global[Registro] = {}
		
		nmap.registry.itsismx = Global
		
	elseif  Global[Registro] == nil then --- WE MUST BE CAREFUL Don't overwritte other registry
		nmap.registry.itsismx[Registro]  = {}
		
	end
	
	-- local key, elemento 
	-- for key, elemento in pairs(nmap.registry.itsismx) do
		-- print(key, elemento)
	-- end
		
end


return _ENV;