"""
This program finds same files using size and hash values. It 
is not guaranteed that files in a group are exactly the same.

Accepts \n separated file and folder paths. By default, runs recursively
for folders. -Nrec for non recursive (only files in the folder).
TODO(armagan): -Nrec is unimplemented. Complete -Nrec related code.

Returns distinct files and similar files according to 
their size/sha256/etc. According to passes in 'apply_all_passes(fpaths)'

Usage: (must change 'path' variable in main for now.) 
(Give a minute or two for completion of 4k files from hard disk.)
python3 SimilarFileFinder_v_0.4.py > output.txt

Creator : armagans (armagansalman@gmail.com)
TODO(armagans) : Exception handling. Handle in sha256/ get byte/ functions.
TODO(armagans) : Accept one path arg || several paths from a file ||
	several paths from arg.
TODO(armagans) : non recursive walk option.
TODO(armagans) : Exception print to stderr
"""

import os
import hashlib
import optparse # TODO(armagans): Use it for inputs with option (argument).
import time


def is_file(potential_path):
	"""
	Return True if given path is a valid file.
	Else returns False.
	"""
	return os.path.isfile(potential_path)
#


def is_dir(potential_path):
	"""
	Return True if given path is a valid directory.
	Else returns False.
	"""
	return os.path.isdir(potential_path)
#


def get_paths_from_folder(dir_path):
	"""
	Returns all paths containing inside the given argument.
	!ERROR! if (folder_path) is not a valid folder.
	"""
	#TODO:(armagans) : Check for validness of argument. Return error if
	# it's the right thing.
	return os.listdir(dir_path)
#


def get_fpaths_from_folder(dir_path):
	fpaths = list()
	
	for p in get_paths_from_folder(dir_path):
		path = dir_path + p # For absolute path.
		if is_file(path):
			fpaths.append(path)
	#
	return fpaths
#


def get_fpaths_recursively_from_folder(dir_path):
	rec_files = list()
	for root, dirs, files in os.walk(dir_path):
		for name in files:
			rec_files.append(os.path.join(root, name))
		#
	#
	return rec_files
#


def get_file_size_in_bytes(path):
	statinfo = os.stat(path)
	
	return statinfo.st_size
#





def format_distinct_path(path, info, separator):
	return "Distinct" + str(info) + separator + path
#


def format_similar_path(path, info, separator):
	return "Group-" + str(info) + separator + path
#


def format_output_paths(distinct_paths, similar_groups):
	group_paths = []
	path_cnt = 0
	for k, v in similar_groups.items():
		#print("--- ", k ," ---")
		
		for x in v:
			s = format_similar_path(x, path_cnt, ":")
			group_paths.append(s)
		#
		path_cnt += 1
	#
	group_output = "\n".join(group_paths)
	
	print(group_output)
	
	print("--- ", "Distincts" ," ---")
	#print(dists)
	for path in dists:
		print(format_distinct_path(path, "", ":"))
	#
#


def read_all_lines(input_file_path):
	with open(input_file_path, "r") as f:
		lines = f.readlines()
		#print(len(lines))
		#for el in lines:
		#	print(el)
		return lines
	#
#

def create_path_info(path_line):
	left, right = path_line.split("*")
	left = left.strip()
	right = right.strip()
	
	result = dict() # Holds path info. Path and is_recursive attributes.
	result["path"] = right
	
	left = left.lower()
	result["is_recursive"] = left.startswith("rec")
	
	return result
#

def get_abs_file_paths(path_info_list):
	""" Each path_info dictionary holds path <string> 
		and is_recursive <boolean> attributes. If path is not recursive,
		collect files only in that directory. Else, collect every file 
		in the directory and its subdirectories recursively.
	"""
	
	#
	all_files = []
	
	for el in path_info_list:
		path, is_recursive = el["path"], el["is_recursive"]
		
		if is_file(path):
			all_files.append(path)
		elif is_dir(path):
			if is_recursive:
				all_files.extend(get_fpaths_recursively_from_folder(path))
			else:
				fpaths = get_fpaths_from_folder(path)
				all_files.extend(fpaths)
		else:
			# This should not happen. TODO(armagans): Throw Exception?
			pass
	#
	# Absolute paths are needed for set add semantics.
	all_files = [os.path.abspath(file) for file in all_files]
	
	return all_files
#


def file_list_grouper(file_paths, info_creator):
	""" Groups are sets that hold similar file paths. Groups are 
		designated by their corresponding hashables.
	"""
	groups = dict()
	for path in file_paths:
		hashable = info_creator(path)
		
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


def hex_digest_sha512(file_path, size=1024):
	""" An info_getter_func. Uses sha512 for file checksum.
		size is in bytes. Assumes file_path exists and can be read.
	"""
	with open(file_path, "rb") as fobj:
		# b is necessary. Must read as binary file. Not as text.
		read_bytes = fobj.read(size)
		
		m = hashlib.sha512()
		m.update(read_bytes)
		hx = m.hexdigest()
		return hx
	#
#


def hex_sha512_X_byte(byte_size):
	def hex_sha512(fpath):
		return hex_digest_sha512(fpath, byte_size)
	#
	return hex_sha512
#



def get_file_paths_from_groups(groups):
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
	
	# TODO(armagans): Accumulate unique files. Show them along with 
	# probably identical files.
	
	groups = dict()
	uniques = list()
	for info_creator in info_creator_funs:
		file_groups = file_list_grouper(abs_file_paths, 
										info_creator)	
		
		uniques, groups = seperate_unique_files_from_groups(file_groups)
	
		abs_file_paths = get_file_paths_from_groups(groups)
	#
	
	# TODO(armagans): Output should be seperate.
	for elm in uniques:
		print(elm)
	print("**************")
	for k,v in groups.items():
		print(k, " | ")
		for el in v:
			size = get_file_size_in_bytes(el)
			size = size//1024 if size//1024 > 1 else size/1024
			print(size ," - ", el)
		#
		print("-----------------")
	
	exit()
	
	# for every group, use next info_creator and create new groups.
#

def read_and_work(input_file_path):
	# input_file_path = "directory paths.txt"
	
	lines = read_all_lines(input_file_path)
	
	path_info_list = [create_path_info(el) for el in lines]
	
	fpaths = get_abs_file_paths(path_info_list)
	
	info_creator_funs = [get_file_size_in_bytes, hex_sha512_X_byte(1024),
						hex_sha512_X_byte(2048)]
	
	group_files_multi_pass(fpaths, info_creator_funs)
#


# TODO(Armagans): Multiply hash value of a file in a group with its 
# new hash value after it's put in a new group?

# TODO(armagans): Prepend file size for output.

# TODO(armagans): Sort found groups by size.

if __name__ == "__main__":

	input_file_path = "directory paths.txt"
	read_and_work(input_file_path)

	
	
	exit()

	print("Processing paths: ", paths)
	print(time.ctime())
	#
	print(time.ctime())
#

