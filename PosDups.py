"""
This program finds same files using size and hash values. It 
is not guaranteed that files in a group are exactly the same.

In main, input_file_path holds a txt file that contains paths to be searched.
In the txt file, if a path is to be searched recursively, prepend 
Recursive *
to that path. Else, prepend * character to path.

!Enable filter_func in read_and_work if there are thousands of small files.

TODO(armagans): Handle the case Recursive * Valid/file/path
"""

import os
import hashlib
import optparse # TODO(armagans): Use it for inputs with option (argument).
import time
import argparse

import util



def create_path_info(path_line):
	# Tries to walk path recursively if given line starts with lower 
	# cased "rec"
	# TODO(armagans): Add exclude capability.
	left, right = path_line.split("*")
	left = left.strip()
	right = right.strip()
	
	result = dict() # Holds path info. Path and is_recursive attributes.
	result["path"] = right
	
	left = left.lower()
	result["is_recursive"] = left.startswith("rec")
	
	return result
#


def file_list_grouper(file_paths, info_creator):
	""" Groups are sets that hold paths of similar files. Groups are 
		designated by their corresponding hashables.
	"""
	groups = dict()
	for path in file_paths:
		try:
			hashable = info_creator(path)
		except:
			print("Error with path '%s'.", path)
			continue
		
		if hashable not in groups: # A set exists for this hashable/group.
			groups[hashable] = set()
			
		groups[hashable].add(path)
	#
	return groups
#


def seperate_unique_files_from_groups(file_groups):
	unique_files = []
	one_element_group_size = 1
	keys = file_groups.keys()
	new_groups = dict()
	
	for key in keys:
		if len(file_groups[key]) == one_element_group_size:
			unique_files.append(file_groups[key].pop()) # pop one element from set.
		else:
			new_groups[key] = file_groups[key].copy() # copy the set of files
		#
	#
	return [unique_files, new_groups]
#


def get_file_paths_from_groups(groups):
	""" Each group is a set. Combine all sets to get all file paths.
	"""
	abs_file_set = set()
	for key, group_set in groups.items():
		abs_file_set.update(group_set)
	#
	
	abs_file_list = list(abs_file_set)
	return abs_file_list
#


def print_results(uniques_all, groups):
	total = 0
	print("Uniques:")
	unq_cnt = 0
	for elm in uniques_all:
		size = util.get_file_size_in_bytes(elm)
		#size = str(size//1024) + "Kb" if size//1024 > 1 else str(size) + "B"
		
		size = util.get_size_str(size)
		
		s = util.format_distinct_path(unq_cnt, size, "*", elm)
		print(s)
		#print(size,"kb * ", elm)
		unq_cnt += 1
		total += 1
	#
	print("**************")
	print("Probably identical files in groups:")
	cnt = 0
	for k,v in groups.items():
		#print(k, " | ")
		for el in v:
			size = util.get_file_size_in_bytes(el)
			#size = str(size//1024) + "Kb" if size//1024 > 1 else str(size) + "B"
			
			size = util.get_size_str(size)
			
			s = util.format_similar_path(cnt, size, "*", el)
			print(s)
			#print(size,"kb * ", el)
			total += 1
		#
		cnt += 1
		print()
	#	#print("-----------------*")
	print("Processed {} files.".format(total))
#


def group_files_multi_pass(abs_file_paths, info_creator_funs):
	""" Using first creator fun, create a group. Seperate uniques and
		use next creator fun for the remaining groups. Iterate until 
		there is no creator fun.
	"""
	# get_file_size_in_bytes should always be the first info creator 
	# because of its speed. 
	
	# TODO(armagans): Check why 1325 files are going to be processed. but
	# Processed 1246 files. for "directory paths.txt"
	
	abs_file_paths = list(abs_file_paths)
	print("{} files are going to be processed.".format(len(abs_file_paths)))
	
	groups = dict()
	uniques_all = list()
	uniques = list()
	for info_creator in info_creator_funs:
		file_groups = file_list_grouper(abs_file_paths, 
										info_creator)	
		
		uniques, groups = seperate_unique_files_from_groups(file_groups)
		uniques_all.extend(uniques)
		abs_file_paths = get_file_paths_from_groups(groups)
	#
	
	# TODO(armagans): Output should be separate. Also, don't print, 
	# write to file. Stdout by default.
	
	
	
	print_results(uniques_all, groups)
	
	
#


def read_and_work(input_file_path, low_filter_bytes, high_filter_bytes):
	# input_file_path = "directory paths.txt"
	if low_filter_bytes == None:
		low_filter_bytes = 0
	#
	
	lines = util.read_all_lines(input_file_path)
	
	path_info_list = []
	for el in lines:
		try:
			info = create_path_info(el)
			path_info_list.append(info)
		except:
			continue
	
	fpaths = util.get_abs_file_paths(path_info_list)

	
	def filter_func(abs_path):
		try:
			size = util.get_file_size_in_bytes(abs_path)
			decision = True
			
			if high_filter_bytes != None:
				decision = size <= high_filter_bytes # Accept on if size >= low_filter_bytes bytes
			#
			decision = decision and size >= low_filter_bytes # Accept on if size >= low_filter_bytes bytes
			return decision
		except:
			return False
	#
	
	filtered_paths = filter(filter_func, fpaths)
	#filtered_paths = filter(lambda x: True, fpaths)
	
	
	# TODO(armagans): Reduce hex bytes. External disk takes too long time.
	info_creator_funs = [util.get_file_size_in_bytes
						#util.hex_sha512_X_byte(4*1024), # 4Kb
						#util.hex_sha512_X_byte(128*1024), # 128Kb
						#util.hex_sha512_X_byte(2*1024*1024) # 2Mb
						
						
						#util.hex_sha512_X_byte(256)
						]
	
	group_files_multi_pass(filtered_paths, info_creator_funs)
#


# TODO(armagans): Multiply hash value of a file in a group with its 
# new hash value after it's put in a new group?

# TODO(armagans): Sort found groups by average group size.

if __name__ == "__main__":
	# TODO(armagans): Read from stdin by default.
	# TODO(armagans): Sort groups by size.
	
	
	parser = argparse.ArgumentParser()
	# parser.add_argument("square", type=int, help="display a square of a given number") # Positional arg.
	parser.add_argument("-fl", "--filterLower", type=int,
						help="excludes files smaller than given count in bytes.")
	
	parser.add_argument("-fh", "--filterHigher", type=int,
						help="excludes files bigger than given count in bytes.")
	args = parser.parse_args()
	
	#print(args.filterLower * 2)
	
	
		
	
	
	
	input_file_path = "directory paths.txt"
	#input_file_path = "external disk.txt"
	#input_file_path = "ext-disk-1mb-filter-size-1024b-out-fresh.txt"
	
	print(time.ctime())
	read_and_work(input_file_path, args.filterLower, args.filterHigher)
	
	print(time.ctime())

#

