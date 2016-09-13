--------------------
 Process.Inject 0.1
--------------------

WARNINNG: Do not rename inject.exe!

How to use:
 inject.exe -p<PID> -a<ADDRESS> -b<BYTES> -l<LENGTH>
 inject.exe -p<PID> -a<ADDRESS> -f<FILE>
 inject.exe -p<PID> -n<ALLOCSIZE>
 inject.exe -p<PID> -r<THREADSTART>

 <PID> = ProcessID [hex]
 <ADDRESS> = Address where to insert bytes [hex]
 <BYTES> = Patch bytes [hex]
 <LENGTH> = Number of bytes to write (1..4)
 <FILE> = Path to file to inject in memory (.bin)
 <ALLOCSIZE> = Size of memory to allocate in target process [hex]
 <THREADSTART> = New thread`s start address [hex]

Example:
 inject.exe -p101 -a00401000 -bEBFE -l2
 inject.exe -p101 -a00401000 -fC:\inject_me.bin
 inject.exe -p101 -n1000
 inject.exe -p101 -r00830000

Program by: ap0x
Web site:   http://ap0x.jezgra.net
eMail:      ap0x.rce@gmail.com