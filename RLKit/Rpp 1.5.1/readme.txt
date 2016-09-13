 R!SC's Process Patcher v1.5.1

 Description
 -----------

 RPP.EXE is a process patch creator, creates a win32.exe from a simple script,
 which will then load a process, and wait for it to unpack/deprotect itself,
 then patch the memory to fix any bugs that the author left in the program,
 y'no, like NAG screens, or silly 30 day trials, and its the only one of its
 kind!!! (which produces a stand-alone win32 exe) i cheat a bit by using a
 precompiled loader, and just altering the data in it, but who cares...

 Usage
 ------

 Double click rpp.exe in windows explorer, select a script file to use, and
 press OK :) 
 
 or drag & drop script file onto rpp.exe
 
 or use from the commandline "rpp.exe <script.rpp>"
 
 If the file you name as the output file exists, it will be OVERWRITTEN, you
 have been warned...

 the script can have any name/extension (from the commandline use)
 but the fileopen box, wants the script to be *.rpp ..


 The Script commands
 -------------------
 ';' means comment, everything is ignored until the next line
 'T=' denotes the amount of tries to patch the processes memory
 'F=' denotes the name of the file/process to load/patch
 'O=' denotes the filename of the loader to create
 'P=' denotes a process patch. followed by the ADDRESS to patch,
      the bytes that should be there, and the bytes to patch it with
      SEE EXAMPLE SCRIPTS...
 'R:' means resume thread . any patches before the 'R:' will happen whilst the
      process is suspended . see azpr243.rpp or halflife.rpp for an example
 ':' is the end marker of every command, must be there
 '$' denotes the end-of-script

 all numbers are taken as hexadecimal
 the amount of check bytes must match the amount of patch bytes in the process
 patch command (P=). ALL BYTES ARE SEPERATED BY A COMMA

example script:

;script.rpp
O=my loader.exe         ; loader to create
F=test.exe:             ; program to load/patch
P=40101D/74,60/74,00:   ; change a jz xx to a jz next instruction

P=4024A6/46,52,45,45,20/52,21,53,43,00: ;replace text 'FREE ' with 'R!SC',0

$ ;end of script


 Known Problems
 --------------
 
 i know of no problems with v1.5.1 . if their is a problem, you own the source
 code, fix it! . erm, or email me with details...
 

 Licence Agreement
 -----------------
 
 You must reverse engineer, disassemble, or decompile this program, and do
 what u want with the code, it wont be much help to u, but, if u don't, you are
 not licenced to use 'rpp.exe'
 

 History
 -------

april 19th...v0.0
 monday, got hold of thewd's process patcher, and didn't like it, had some
 ideas on writing my own...

april 20th...v0.01
 tuesday, scribbled some code down at work, kept thinking about how to do it,
 and do it properly

april 21st...v0.01
 wednesday, slept all day :)

april 22nd...v0.6
 thursday, spent 5 hours coding & testing the script conversion routine

april 23rd...v1.0
 friday, spent about 5hrs finishing off thursdays code, rewrote a loader to be
 able to include the data from the script conversion, integrated the two
 programs, and wrote the silly dox. heh, cracked pe-crypt aswell :) (cracking
 freeware, doh!)

april 24th...v1.0
 thought about adding another command to the script
 
april 25th...v1.0 (still :)
 sunday afternoon, spent couple of minutes adding a new command to the script,
 'O=', so u can specify the name of the loader you want to create

april 29th...v1.1
 sometime thursday, fixed script conversion to include more precise error
 messages, and include line numbers. fixed script conversion to understand
 CAPITAL and small ASCii Hex numbers, for ease of programming, i was idle
 before, and only included conversion of CAPITALS. Got rid of commandline, in
 favour of GetOpenFileNameA (nice box). Probably ready for the first release,
 1 week after the first line of code

may 6th...v1.2i
 re-added commandline option, counts amount of patch data to make sure you
 don't go over the limits, increased default timer loop, increased script
 buffer to a max of 40kb, cus they soon grow with a few comments, maybe did
 some other stuff aswell :)
 
oct 20th...v1.3
 recompiled a nicer loader.exe, which is 4.5kb with no patch data . has its
 section for the patch data info, has a nice icon, and the ability to
 create the process suspended, for (semi) advanced patching of protectors
 you can have filenames with spaces in them aswell, a lil bug i removed ..
 wow, loader even passes the commandline onto the process it creates!

nov 9th...v1.4
 hopefully fixed nasty winNT bug . i will learn to stop playing with pe
 headers, one day..

feb 25th...v1.5
 erm . optimised some stuff, probably added more bugs, 'hopefully' fixed
 that winNT/2k bug. getting it tested before i release . script file can
 only be 2000h bytes now . and a maximum of 180h bytes can be patched with
 a loader. did i release the source? haha, if i did, please dont read it!
 added call suspendthread, call virtualprotectex, call resumethread before
 every call writeprocessmemory, because EliCZ rekons its good .

mar 29th...v1.5.1
 added 10 lines of code to do some stuff, see patch.asm or whats.new
 
 (c)1999 r!sc  --  http://beam.to/risc