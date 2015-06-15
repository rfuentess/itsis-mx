# General description #

All the scripts uses on some measure the library  **_Nmap/nselib/itsismx.lua_**. Here are collected all the common tools used for them.    Many of those tools were made by Raul Fuentes, but those who were collected from Internet  have the information.

You can go to the library with this [link](https://code.google.com/p/itsis-mx/source/browse/nselib/itsismx.lua)

# Some curiosities #



  * One of the variables are called "Mordidas" (Bytes == Mordidas), I find that  bad translation  on a network spanish book (And last time I bought something on the matter on spanish).

  * There are two way to calculate IPv6 address (as Lua is limited to smallest number we need to create custom constructs). Once was made with strings (and basic pseudo adds), and the other as Integers of 32 bits.  Of course, the last one is the most efficient (About all  when you do bigger explorations)... so, why are the both there?  because the first one was my  original  "_efficient thinking_" at 4:00 am ...  or say on other words, are a memento of those times when one should sleep instead of coding.

# Future works #

  * The function HextToBin() need too much work.
  * A revision on other functions could be wise.
  * Probably remove the String mechanism, however I'm  not sure if we can use it for other purposes.