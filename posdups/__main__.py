import time
import argparse


import PosDups as PD

if __name__ == "__main__":
	# TODO(armagans): Read from stdin by default.
	# TODO(armagans): Sort groups by size.
	
	
	parser = argparse.ArgumentParser()
	# parser.add_argument("square", type=int, help="display a square of a given number") # Positional arg.
	parser.add_argument("-fl", "--filterLower", type=int,
						help="excludes files smaller than given count in bytes.")
	
	parser.add_argument("-fh", "--filterHigher", type=int,
						help="excludes files bigger than given count in bytes.")
						
	parser.add_argument("-hs", "--hashes",
						help="denotes the checksum byte sequence. Ex: 128Kb, 4Mb, 2Gb")
						
						
	args = parser.parse_args()
	
	
	input_file_path = "../directory paths.txt"
	#input_file_path = "../external disk.txt"
	#input_file_path = ""
	
	print(time.ctime())
	PD.read_and_work(input_file_path, args)
	
	print(time.ctime())

#
