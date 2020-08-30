PosDups: Finds possibly duplicate files. Written in Python. No dependencies.

Put directory or file paths in _paths.txt_ file on separate 
lines.
Read _paths.txt_ to understand how to make PosDups search a 
directory recursively.

Use **--help** option to see usage of file filters by size.

Examples:
  - python3 \_\_main__.py < "../paths.txt" > out.txt --filterLower 131072  ==  Exclude files smaller than 128Kb, then write results to "out.txt"
  - python3 \_\_main__.py < "../paths.txt" > out.txt -fl 131072  ==  Exclude files smaller than 128Kb, then write results to "out.txt"
  - python3 \_\_main__.py < "../paths.txt" > out.txt -fl 131072 -fh 20971520 == Exclude files smaller than 128Kb and bigger than 20Mb then write results to "out.txt"
  - python3 \_\_main__.py < "../paths.txt" -hs 1kb,128kb,5Mb,2Gb == Given a sequence, reads at most given bytes and applies checksum for grouping. Reasonable sequences 
  increase each size after the other. Default is 1kb,16kb,1mb

Contact info:
  - Gmail: armagan.sal.man+posdups
