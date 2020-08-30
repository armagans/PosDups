import time
import argparse
import sys

import util
import PosDups as PD

if __name__ == "__main__":
	# TODO(armagans): Sort groups by size.
	# TODO(armagans): Add --inputfile, --outputfile, -inf, -outf arguments.
	
	parser = argparse.ArgumentParser()
	# parser.add_argument("square", type=int, help="display a square of a given number") # Positional arg.
	parser.add_argument("-fl", "--filterLower", type=int,
						help="excludes files smaller than given count in bytes.")
	
	parser.add_argument("-fh", "--filterHigher", type=int,
						help="excludes files bigger than given count in bytes.")
						
	parser.add_argument("-hs", "--hashes",
						help="denotes the checksum byte sequence. Ex: 128Kb, 4Mb, 2Gb")
						
	parser.add_argument("-inf", "--inputfile", help="path of the input file which contains paths.")
						
	parser.add_argument("-outf", "--outputfile", help="path of the output file which will have the results.")
						
	args = parser.parse_args()
	
	
	
	input_file_path = "../paths.txt"
	#input_file_path = "../external disk.txt"
	#input_file_path = ""
	
	print(time.ctime())
	
	res = []
	if args.inputfile == None:
		res = PD.read_and_work(sys.stdin.readlines(), args)
	#
	else:
		lines = util.read_all_lines(input_file_path)
		res = PD.read_and_work(lines, args)
	#
	util.print_results(res[0], res[1], args.outputfile)
	
	print(time.ctime())

#
