# Copyright (C) 2020 Armağan Salman
#
# You should have received a copy of the GNU General Public License
# along with this program (COPYING).  If not, see <https://www.gnu.org/licenses/>.


"""
This program finds same files using size and hash values and groups them.
It is not guaranteed that files in a group are exactly the same.

In main, input_file_path holds a txt file that contains paths to be searched.
In the txt file, if a path is to be searched recursively, prepend 
Recursive *
to that path. Else, prepend * character to path.

Use -fl X or --filterLower X option to exclude files smaller than X bytes
if there are thousands of small files.

TODO(armagans): Handle the case Recursive * Valid/file/path
"""

import os
import hashlib

import util



def create_path_info(path_line):
	# Tries to walk path recursively if given line starts with lower 
	# cased "rec"
	# TODO(armagans): Add exclude capability.
	left, right = path_line.split("*", 1) # Split on first occurence only.
	left = left.strip()
	right = right.strip()
	
	result = dict() # Holds path info. Path and is_recursive attributes.
	result["path"] = right
	
	left = left.lower()
	result["is_recursive"] = left.startswith("rec")
	exclude = True if left[-1] == "x" else False
	result["exclude"] = exclude

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
	
	return [uniques_all, groups]
#


def read_and_work(path_lines, args):
	# input_file_path = "directory paths.txt"
	low_filter_bytes = args.filterLower
	high_filter_bytes = args.filterHigher
	hashes = args.hashes
	
	if low_filter_bytes == None:
		low_filter_bytes = 0
	#
	
	lines = path_lines
	
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
				decision = size <= high_filter_bytes
			#
			decision = decision and size >= low_filter_bytes
			return decision
		except:
			return False
	#
	
	filtered_paths = filter(filter_func, fpaths)
	
	if hashes == None:
		# default sha512 sequence: 1*1024, 16*1024, 1*1024*1024
		# TODO(armagans): Reduce hex bytes (maybe 1Mb). External disk takes too long time.
		hashes = "1kb,16kb,1mb"
	#
	byte_seq = util.get_bytes_from_size_seq(hashes)
	info_creator_funs = [util.get_file_size_in_bytes]
	
	for byt in byte_seq:
		info_creator_funs.append(util.hex_sha512_X_byte(byt))
	#
	
	# Returns [unique files, same file groups]
	return group_files_multi_pass(filtered_paths, info_creator_funs)
#


# TODO(armagans): Multiply hash value of a file in a group with its 
# new hash value after it's put in a new group?

# TODO(armagans): Sort found groups by average group size.


