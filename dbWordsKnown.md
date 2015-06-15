# General description #

The script [WordIs](WordIs.md) use this simple file text as DB. Nmap offer the possibility to read files like this for similar purposes (by example dictionary attack and OUI).


The general structure of any word is:

  1. ny number of Comments, on any order
> Number of segments |  Word |  word in binary

Where the  entries can be separated with blank space or tabs. This configuration was choosen for simplicity for creating the script. However, makes the things a little more hard for create the entries (Though nothing for Phyton or even AWK).

The Number of segment represent the size of the word, with this field the script [WordIs](WordIs.md) is able to find the appropriate words to use.

By the same reason of simplicity,   was made the third element: "word in binary", which are the binary values. (It's more easy to concatenate zeros and ones than hexadecimal characters with semi colons).

> # Future work #

  * Convert it on a truly DB, not just a concept test.