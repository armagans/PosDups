import time
import argparse
import sys

import util
import PosDups as PD


def build_args(args):
	
	if type(args) == str:
		args = args.split()
	#
	parser = argparse.ArgumentParser()
	# parser.add_argument("square", type=int, help="display a square of a given number") # Positional arg.
	parser.add_argument("-s", "--filterSmaller", type=int,
						help="excludes files smaller than given count in bytes.")
	
	parser.add_argument("-b", "--filterBigger", type=int,
						help="excludes files bigger than given count in bytes.")
						
	parser.add_argument("-c", "--checksums",
						help="denotes the checksum byte sequence. Ex: 128Kb, 4Mb, 2Gb")
						
	parser.add_argument("-i", "--inputfile", help="path of the input file which contains paths.")
						
	parser.add_argument("-o", "--outputfile", help="path of the output file which will have the results.")
	
	return parser.parse_args(args)
#

def main(args):
	
	parsed_args = build_args(args)
	
	if parsed_args.checksums == None:
		parsed_args.checksums = "1kb,16kb,1mb"
	
	tm = dict()
	tm["start"] = time.ctime()
	
	res = []
	if parsed_args.inputfile == None:
		res = PD.read_and_work(sys.stdin.readlines(), parsed_args)
	#
	else:
		lines = util.read_all_lines(parsed_args.inputfile)
		res = PD.read_and_work(lines, parsed_args)
	#
	tm["end"] = time.ctime()
	
	return res, parsed_args, tm # [uniques, group sets], parsed_arg object, 
								# time dictionary that holds start and end times.
#

if __name__ == "__main__":
	# TODO(armagans): Sort groups by size.
	
	res, parsed_args, times = main(sys.argv[1:]) # Skip the program name.
	
	if parsed_args.outputfile != None: # TODO(armagans): Change given file path if it exists.
		
		parsed_args.outputfile = util.increment_file_name(parsed_args.outputfile)
		
		with open(parsed_args.outputfile, "w") as wf:
			wf.write("Arguments: " + str(parsed_args) + "\n")
	#
	else:
		print("Arguments: " + str(parsed_args))
	#
	util.write_results(res[0], res[1], parsed_args.outputfile, times)
#
