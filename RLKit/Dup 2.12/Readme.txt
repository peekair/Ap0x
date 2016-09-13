diablo2oo2's Universal Patcher [dUP]
************************************
Version: 2.12

Features:
-multiple file patcher
-create Offset and Search&Replace patch/loader
-compare files (RawOffset and VirtualAddress) with different filesize
-registry patch, also for loaders
-attach files to patcher
-use file paths from registry
-enable CRC32 and filesize checks
-patching packed files
-compress patcher with your favorite packer
-saving Projects
-add custom skin to your patcher
-add custom icon to your patcher/loader
-add music (Tracker Modules: xm,mod,it,s3m,mtm,umx) to patcher
-and many more...


Version History
---------------
[2.12]
-add "Registry Paths" module (usage of custom environment variables)
-now shows description of registry patchdata in main window
-add option to switch on XP styled dialogs
-add results box instead messagebox in check occurrence dialog

[2.11]
-support for custom window shape [RGN files]
-new "save on exit" dialog if something changed
-support for custom cursor
-fixed bug in loader installer
-minor bugfix s&r loader
-minor code changes in follow in ollydbg function

[2.10]
-add new feature: installer for loaders
-add about box dialog (can be modified now in resource)
-add option to follow addresses in ollydbg
-fixed stupid bug when ripping icons from *.exe/*.dll files
-dup2 remembers window positions now
-better drag&drop support (drag files into single dialog items)
-use ufmod player instead of mfmplayer for xm files
-add some usefull tooltips
-add warning message when quit s&r dialog with data in editboxes
-add file attribute option for attached files
-add some context menu
-improved save dialog (generates filename)
-add option to show/hide release info message in patcher dialog
-fixed bug in VirtualAddress calculation routine
-minor code changes and bug fixes

[2.09]
-add support for custom colored patchers
-add support for transparent patcher dialog
-commandline support for patcher (silent mode,set workdir...)
-coded new method to apply skin (*.res file) to patcher
-pattern check changed: separators "A-F" and "0-9" not allowed
-add option to hide dUP main window when edit Patchdata
-fixed bug in Offset Dialog
-minor bug fixes and code changes

[2.08]
-this version comes with a help file :)
-add: use of windows environment variables in pathnames
-now patching "readonly" files possible
-patcher asks to overwrite existing file attachments
-option to switch off warning when exit dUP with open project
-add: play/stop buttons for music in the settings dialog
-bug fixed: String2Hex Dialog doesnt crash now
-bug fixed: the patcher/loader can now contain any icon format
-bug fixed in inline patcher: problem with already patched targets
-loader improved: can transfer now commandline arguments
-changed date format to: "monthname day, year" by default
-add: function to select custom icon from exe/dll files
-add support for (Win)Upack packer (http://dwing.go.nease.net)
-minor fixes in patcher when searching target file manually...
-better backup system in patcher

[2.07]
-ugly bugs fixed in Search&Replace Engine core
-fixed another bug in s&r loader, when using "Patch All" option
-fixed bug: compare big files with different size
-new button in Patch Info Dialog to get today date
-add autocorrection for different patternlength

[2.06]
-add option to use smaller dll for xm music instead of bassmod.dll
-add check in S&R Dialog: Pattern must have same lenght
-add 'MemCheck' feature for search&replace loaders
-items can move up & down in the offset and s&r table
-load last file in "Check Occurrence" Dialog by default
-bug fixed in Offset Dialog

[2.05]
-add support for creating patcher/loader under win9x =)
-improved patcher with logbox instead of messageboxes
 note: old skins dont work with this version
-fixed bug: dont patch already inline patched targets
-fixed bug: dont add unused data to inline patched targets
-fixed bug for inline patcher (better entrypoint calculation)
-improved S&R loader: can detect changed exe now
-support for nspack packer (www.nsdsn.com) for packing patcher/loader

[2.04]
-add support for more trackerformats (it,xm,s3m,mtm,mod,umx)
-drag&drop support in all dialogs
-fixed bug with long releaseinfo & about message
-minor code change in patcher.exe

[2.03]
-patcher without xm music has smaller filesize (compressed)
-remember now last 'CheckOccurrence' filepath
-show warning when first byte is 0 in VirtualAddress Mode

[2.02]
-fixed bug: directorys are remembered now correctly
-add: comments for S&R prjectdata

[2.01]
-serious (!) bug fixed in S&R procedures

[2.00]
-100% recoded
-multiple file patching
-compare files with different filesize
-unlimited patchdata
-Registry Patch
-File Attachment

[1.14]
-optimized search&replace routine (shorter & faster)
-fixed: Autoformat Bytes supports now also "??" string

[1.13]
-add: you also can use "??" instead of "**" in S&R Dialog
-add: move generated patch with mouse by clicking on any dialog place
-add: QuickString Function in S&R Dialog

[1.12]
-add: comments in S&R Projects
-add: "MemCheck" feature for loaders
-offset filecompare: file filter changed to "All Files *.*" as default
-ugly bug fixed when creating S&R Patcher...
-smaller patcher,loader code
-removed bug: inline patcher doesnt rename last section now

[1.11]
-selecting a packer is now easy.
 dUP detects packer and set optimal parameters
-fixed problem with upx: packing patcher for packed targets

[1.10]
-loader bug fixed when using xm files
-smaller patcher size when not using xm files
-Command line Packer bug fixed,when changing path
-about box msg fix,when changing text

[1.09]
-Removed "Options" Dialog,now easier to use
-add xm feature [playing Fast Tracker Modules]
-dUP remember now all important paths
-improved loader code
-fixed caption bug,when using custom *.res file

[1.08]
-fixed Bug under w2k when compare files
-add option to use custom "skins" (*.res files)

[1.07]
-add loader support for offset patching

[1.06]
-add Offset Patch Feature [also for packed exe's]
-Compare Function for Offset Patches
-Save/Open Offset Projects
-removed internel Packer;added option to choose your packer (upx,fsg,mew...)

[1.05]
-!!! Match Number will only patch the specified Number, and not the
 patterns before
-new "Check Occurence of Search Bytes" features; more info
-add Tab Control Navigation
-Hidden File Bug fixed

[1.00]
-fisrt crappy release :D

Homepage
--------
http://navig8.to/diablo2oo2
http://diablo2oo2.cjb.net
http://kickme.to/diablo2oo2
http://zor.org/d2k2

Support Board
-------------
http://navig8.to/mp2ksupport