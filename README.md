PosDups: Finds possibly duplicate files. Written in Python. No dependencies.

Put directory or file paths in _directory paths.txt_ file on separate 
lines.
Read _directory paths.txt_ to understand how to make PosDups search a 
directory recursively.

Use **--help** option to see usage of file filters by size.

**Warning**: Current version (0.5.0-beta) reads from _directory paths.txt_.
Production version will read from stdin.

Examples:
  - python3 PosDups.py > out.txt -filterLower 131072  ==  Exclude files smaller than 128Kb, then write results to "out.txt"
  - python3 PosDups.py > out.txt -fl 131072  ==  Exclude files smaller than 128Kb, then write results to "out.txt"
  - python3 PosDups.py > out.txt -fl 131072 -fh 20971520 == Exclude files smaller than 128Kb and bigger than 20Mb then write results to "out.txt"

Contact info:
  - Gmail: armagan.sal.man+posdups
