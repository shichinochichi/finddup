# finddup
Identify duplicate files.

Function: Find duplicate files using file sizes and cryptgraphic hashes.

Usage: run finddup.py --help

Assumptions:
  don't act on mountpoints because:
  - it's unclear where else the mounted partition may be mounted, e.g. bindfs
    can get around the problem by intentionally including the moutnpoint in the argument list
    
  don't act on softlinks because:
  - a softlink may point inside one of the directory trees under test
    so the same file will show up as a duplicate of itself
  - a softlink may point outside all directory trees under test
    so the program will impact a filesystem outside the scope of the application

Thanks to Todor Minakov on
https://stackoverflow.com/questions/748675/finding-duplicate-files-and-removing-them
for the original idea for writing this code.
