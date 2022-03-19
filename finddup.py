#!/usr/bin/env python3
"""
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
"""

# Thanks to Todor Minakov on
# https://stackoverflow.com/questions/748675/finding-duplicate-files-and-removing-them
# for the original idea for writing this code.


import argparse
import sys
import hashlib
import os
from collections import defaultdict
import random
import inspect


def init_argparse() -> argparse.ArgumentParser:
   parser = argparse.ArgumentParser(
      description = 'Function: Find duplicate files using file sizes and cryptgraphic hashes.' ,
   )
   parser.add_argument(
      '-v', '--version',
      action='version',
      version = f"{parser.prog} version 1.0.0-pre-release-001"
   )
   parser.add_argument(
      'dir_names',
      metavar='dir' ,
      default=list('.') ,
      nargs='*' ,
      help='root search location(s), default: cwd'
   )
   parser.add_argument(
      '-d' , '--digests' ,
      type=str ,
      default='sha1' ,
      help='comma separated list of digest algorithms, default: sha1'
   )
   parser.add_argument(
      '-i' , '--interim_dicts' ,
      action='store_true' ,
      help='interim dictionary content for debugging'
   )
   parser.add_argument(
      '-l' , '--list_digests' ,
      action='store_true' ,
      help='list digests that the platform supports and exit'
   )
   parser.add_argument(
      '-t' , '--trace' ,
      action='store_true' ,
      help='function trace for debugging'
   )
   return parser


def chunk_reader( fobj , chunk_size=1024 ):
   """Generator that reads a file in chunks of bytes"""
   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )
   while True:
      chunk = fobj.read(chunk_size)
      if not chunk:
         return
      yield chunk


def get_digest( filename , digest_name ):
   """Calculate one of the digests available on the system, on a file"""
   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )
   digest_obj = hashlib.new( digest_name )
#  try: <FIXME: what if access is not allowed for filename?
   file_object = open(filename, 'rb')

   for chunk in chunk_reader(file_object):
      digest_obj.update(chunk)
   digested = digest_obj.hexdigest()

   file_object.close()
   return digested


def print_digests( digestvar , desc , outfile ):
   "display a digest and the digest values"
   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )
   if ( desc and desc.strip() ):
      print( '----- start: ' + desc , file = outfile )
   for key , values in digestvar.items():
      print( f'key: {key}' , file = outfile )
      for v in values:
         print( f'\t{v}' , file = outfile )
   if ( desc and desc.strip() ):
      print( '----- end: ' + desc , file = outfile )


def extend_dict_with_digest( dict_in , digest_algorithm ):
   '''extend an existing dict of sets of files with the digest of the files'''
   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )
   dict_out = defaultdict( set )

   # test that dict_in has keys that are uniformly tuples
   uniform = ( all( type( elem ) == tuple for elem in dict_in.keys() ) )
   # exit the application if the keys are not all tuples
   if not uniform:
      print( "keys not all tuples" , file = sys.stderr )
      sys.exit( "exiting program" )

   # test that dict_in has a uniform key length
   one_key = random.choice( list( dict_in.keys() ) )                                  # choose an exemplar key at random
   key_length = len( one_key )                                                        # find the number of elements in the exemplar key
   uniform = ( all( len( key_elem ) == key_length for key_elem in dict_in.keys() ) )  # test the length of all the keys against the length of the exemplar key
   # exit the application if the key length is not uniform
   if not uniform:
      print( "uneven key lengths" , file = sys.stderr )
      sys.exit( "exiting program" )

   # create a dictionary with the extended key
   for key , values in dict_in.items():
      for filename in values:
         key_out = list( key )
         digest_value = get_digest( filename , digest_algorithm )
         key_out.append( digest_value )
         try:
            dict_out[ tuple( key_out ) ].add( filename )
         except (OSError,):  # the file access might have changed
            continue

   if args.interim_dicts:
      print_digests( dict_out , 'show dict_out' , sys.stderr )

   return dict_out


def get_dict_of_files_by_size( paths ):
   '''hash all files that have the same size together into a set'''
   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )
   dict_of_files_by_size = defaultdict( set )

   # <FIXME: eliminate false paths>

   for path in paths:
      if not os.path.isdir( path ):
         print( 'WARNING: Directory not found: %s' % path , file = sys.stderr )
         continue
      for dirpath, dirnames, filenames in os.walk(path):
         for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if os.path.islink( full_path ):  # don't act on softlinks
               print('WARNING: ignoring link: %s' % full_path , file = sys.stderr )
               continue
            if os.path.ismount( full_path ):  # don't act on mountpoints
               print('WARNING: ignoring mountpoint: %s' % full_path , file = sys.stderr )
               continue
            try:
               file_size = os.path.getsize(full_path)
               dict_of_files_by_size[ tuple( [ file_size ] ) ].add(full_path)
            except (OSError,):
               # not accessible (permissions, etc) - pass on
               # <FIXME: print warning to stderr for inaccessible file>
               continue

   if args.interim_dicts:
      print_digests( dict_of_files_by_size , "show dict_of_files_by_size" , sys.stderr )

   return dict_of_files_by_size


def prune_dict_by_size_of_set( dict_of_sets , min_length  ):
   """in a dictionary of sets, remove all elements with a set length less than the minimum length"""
   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )
   for key , values in tuple( dict_of_sets.items() ):
      if len( values ) >= min_length:
         continue
      try:
         del dict_of_sets[ key ]
      except KeyError:
         pass

   return dict_of_sets


def list_digests():
   '''verify the list of digests passed in on the command line, or the default digest'''
   print( "digest algorithms on this platform are:" , file = sys.stdout )
   for digest_element in sorted( hashlib.algorithms_available ):
      print( "   %s" % digest_element , file = sys.stdout )


def verify_digests( digest_list ):
   '''verify the list of digests passed in on the command line, or the default digest'''
   for digest_candidate in digest_list:
      print( "testing availability of digest algorithm: %s" % digest_candidate , file = sys.stderr )
      if digest_candidate not in hashlib.algorithms_available:
         print( "digest algorithm %s not available on this platform" % digest_candidate , file = sys.stderr )
         sys.exit( "exiting program" )


def get_duplicates_dictionary( paths , digest_algorithm_list ):
   '''create a duplicates set by first hashing files by size, then by cryptgraphic digests'''
   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )

   # create a dictionary of files hashed by file size
   # (much quicker first pass than calculating digests of the files)
   # and prune the dictionary of all hashes with only one filename
   dict_out = get_dict_of_files_by_size( paths )
   dict_out = prune_dict_by_size_of_set( dict_out , 2 )

   # For each digest algorithm in the list, add to the certainty of the uniqueness of the dictionary digest value
   # then again prune the dictionary of all hashes with only one filename
   for digest_algorithm in digest_algorithm_list:
      dict_out = extend_dict_with_digest( dict_out , digest_algorithm )
      dict_out = prune_dict_by_size_of_set( dict_out , 2 )

   return dict_out


def list_duplicate_files( dict_of_dups ):
   '''print the dictionary of sets'''

   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )

   for key , values in sorted( tuple( dict_of_dups.items() ) ):
      print( 'size: {0: >5}   digests: {1:}'.format( key[0], key[1:] ) )
      for value in sorted( values ):
         print( '   %s' % value )


def input_wrapper( prompt , answers , maxlen , verbose ):
   '''Decorator that gets user input.'''
   def input_wrapper_outer( fn ):
      '''identify the wrapped function'''
      @wraps( fn )
      def input_wrapper_inner( *args , **kwargs ):
         '''process the decorator, and call the wrapped function from here'''
         print( "This is the start of the 'wrapper' function" )
         while True:
            try:
               in_str = str( input( prompt ) )
            except TypeError:
               print( "User input must be a string" )
               continue
            numchars = len( in_str )
            if ( maxlen > 0 ) and ( numchars > maxlen ):
               # fails to meet the basic string length test criterion
               print( "User input must be less than %d characters in length" % maxlen )
               continue
            if not set( in_str ).issubset( set( answers ) ):
               # fails to meet the basic character set test criterion
               print( "User input must be in the '%s' character set" % answers )
               continue
            if not fn( in_str ):
               continue
            break
         print( "This is the end of the 'wrapper' function" )
         return in_str
      return wrapper


def ask_duplicate_files( dict_of_dups ):
   '''print the dictionary of sets'''
   choices = defaultdict( set )

   if args.trace:
      print( "function %s" % inspect.stack()[0][3] , file = sys.stderr )

   for key , values in sorted( tuple( dict_of_dups.items() ) ):
      print( 'size: {0: >5}   digests: {1:}'.format( key[0], key[1:] ) )
      choices = {}
      i = 0
      for value in sorted( values ):
         i = i + 1
         choices[ i ] = value
         print( '   %2d: %s' % ( i , value ) )

      print( 'HERE' )


if __name__ == "__main__":

   parser = init_argparse()
   args = parser.parse_args()

   # some flags require that its function get executed and the program exits
   if args.list_digests:
      list_digests()
      sys.exit( "exiting program" )

   # do initial actions on arguments
   if args.digests:
      args.digests = [ s.strip() for s in args.digests.split(',') ]
   assert len( args.digests ) > 0 , 'Must specify a digest algorithm.  argparse() should ensure its/their presence.'
   assert len( args.dir_names ) > 0 , 'Must specify one or more target directories.  argparse() should ensure its/their presence.'
   verify_digests( args.digests )
   for i in range( len( args.dir_names ) ):
      args.dir_names[i] = os.path.abspath( args.dir_names[i] )

   dups = get_duplicates_dictionary( args.dir_names , args.digests )

   print_digests( dups , "" , sys.stdout )
