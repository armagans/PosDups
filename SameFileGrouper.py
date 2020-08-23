"""
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




def get_kb(multiplier):
	kb = 1024
	return multiplier * kb
#


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


def get_paths(path_list, is_recursive):
	""" Given a path_list, adds files and folders to be processed.
		if is_recursive == True, directory paths will be processed recursively.
	"""
	assert type(path_list) == list
	#
	all_files = []
	
	for path in path_list:
		if is_file(path):
			all_files.append(path)
		elif is_dir(path):
			if is_recursive:
				all_files.extend(get_fpaths_recursively_from_folder(path))
			else:
				fpaths = get_fpaths_from_folder(path)
				all_files.extend(fpaths)
		
	return all_files
#


def get_file_size_in_bytes(path):
	statinfo = os.stat(path)
	
	return statinfo.st_size
#


def read_and_hex_digest_sha256(file_path, size):
	""" An info_getter_func. Uses sha256 for file checksum.
		size is in bytes. Assumes file_path exists and can be read.
	"""
	with open(file_path, "rb") as fobj:
		# b is necessary. Must read as binary file. Not as text.
		read_bytes = fobj.read(size)
		
		m = hashlib.sha256()
		m.update(read_bytes)
		hex256 = m.hexdigest()
		return hex256
	#
#


def read_and_hex_digest_sha256_X_kb(byte_size):
	def read_and_hex_sha256(fpath):
		return read_and_hex_digest_sha256(fpath, byte_size)
	#
	return read_and_hex_sha256
#


def separate_singular_group(in_group):
	"""
	For a K(group info), V(path_set) of in_group:
		if V has only one path, add it to distinct_files.
		else add V to new_group[K].
	"""
	distinct_files = []
	new_group = {}
	for info, file_set in in_group.items():
		if len(file_set) == 1:
			distinct_files.append(file_set.pop())
		#
		else:
			new_group[info] = file_set
		#
	return [distinct_files, new_group]
#


def apply_info_func(file_list, info_func):
	"""
	Get info from file using info_func.
	Use that info as key to a dictionary. file path as dict value.
	"""
	groups = dict()
	
	for fpath in file_list:
		info = "ERROR"
		try:
			info = info_func(fpath)
		except:
			print("Error with file:", fpath)
		else:
			s = set()
			
			if info in groups:
				s = groups[info]
			#
			s.add(fpath) # Add fpath to a path group.
			groups[info] = s # Grouped by info.
	#
	return groups
#


def transform_to_new_group(in_group, info_func):
	"""
	Applies info func. to a dictionary.
	Input : {group_type:file_list} , 
		a function to transform to a new group.
	
	Output : [distinc_file_list, 
				new_group]
	"""
	end_group = dict()
	end_files = set()
	
	for group, in_files in in_group.items():
		separated_group = apply_info_func(in_files, info_func)
		distinct_files, new_group = separate_singular_group(separated_group)
		
		# TODO(armagans): Make sure extend is the right choice/working choice.
		end_files.update(distinct_files)
		for new_info, new_set in new_group.items():
			if new_info in end_group:
				s = end_group[new_info]
				s.update(new_set)
			#
			else:
				end_group[new_info] = new_set
	#
	return [end_files, end_group]
#


def apply_all_passes(fpaths):
	#TODO(armagans) : Take a parameter for separator functions.
	sha256_first_1kb = read_and_hex_digest_sha256_X_kb(get_kb(1))
	sha256_first_4kb = read_and_hex_digest_sha256_X_kb(get_kb(4))
	sha256_first_16kb = read_and_hex_digest_sha256_X_kb(get_kb(16))
	
	# TODO(armagans) : name functions like this:
	sha256_first_32kb = read_and_hex_digest_sha256_X_kb(get_kb(32))
	
	all_separator_funcs = [get_file_size_in_bytes]
						#,sha256_first_1kb]
						#,sha256_first_4kb]
						#sha256_first_16kb]
						#read_hex_digest_sha256_32kb]
	#
	
	# First, apply size info function to all input files. 
	# Then, apply other info functions.
	size_info_func = all_separator_funcs.pop(0)
	groups = apply_info_func(fpaths, size_info_func)
	distinct_files, new_group = separate_singular_group(groups)
	# From here on, apply other info functions.
	end_distinct_files = set()
	end_group = dict()
	
	# TODO(armagans): Solve and complete this mess.
	end_distinct_files.update(distinct_files)
	group = new_group
	
	while(len(all_separator_funcs) > 0):
		info_func = all_separator_funcs.pop(0)
		nfiles, ngroup = transform_to_new_group(group, info_func)
		
		end_distinct_files.update(nfiles)
		group = ngroup
	#
	
	end_group = group
	return [end_distinct_files, end_group]
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


def multiple_pass_on_groups():
	pass
#

def transform_to_new_groups(groups, info_creator):
	new_groups = dict()
	
	
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
	#let's say info_creator_funs have 3 functions.
	# get_file_size_in_bytes should always be the first info creator because of its speed. 
	
	#file_groups = file_list_grouper(abs_file_paths, info_creator_funs[0])
	
	#uniques, groups = seperate_unique_files_from_groups(file_groups)
	
	#abs_file_list = get_file_paths_from_groups(groups)
	
	#file_groups = file_list_grouper(abs_file_list, info_creator_funs[1])
	
	#uniques, groups = seperate_unique_files_from_groups(file_groups)
	
	#abs_file_list = get_file_paths_from_groups(groups)
	
	#file_groups = file_list_grouper(abs_file_list, info_creator_funs[2])
	
	#uniques, groups = seperate_unique_files_from_groups(file_groups)
	
	groups = dict()
	uniques = list()
	for info_creator in info_creator_funs:
		file_groups = file_list_grouper(abs_file_paths, 
										info_creator)
	
		uniques, groups = seperate_unique_files_from_groups(file_groups)
	
		abs_file_paths = get_file_paths_from_groups(groups)
	
	
	for elm in uniques:
		print(elm)
	print("**************")
	for k,v in groups.items():
		print(k, " | ")
		for el in v:
			print(el)
		#
		print("-----------------")
	
	exit()
	
	# for every group, use next info_creator and create new groups.
#


# TODO(armagans): Multiple info_creators and mltiple passes on groups.

# TODO(armagans): After seperating uniques and groups, make a list 
# of all file in all groups then use them in the next round(info_creator->groups...).


# TODO(Armagans): Multiply hash value of a file in a group with its 
# new hash value after it's put in a new group?


if __name__ == "__main__":

	input_file_path = "directory paths.txt"
	
	lines = read_all_lines(input_file_path)
	
	path_info_list = [create_path_info(el) for el in lines]
	
	fpaths = get_abs_file_paths(path_info_list)
	
	info_creator_funs = [get_file_size_in_bytes, hex_sha512_X_byte(1024),
						hex_sha512_X_byte(2048)]
	
	group_files_multi_pass(fpaths, info_creator_funs)
	
	
	#print(uniques)
	#print("***********")
	#print(groups)
	
	#for k,v in groups.items():
	#	print(k, " | ", v)
	
	
	exit()

	# path = "/media/auser/SAMSUNG/NOT SAMSUNG/Anime-Cartoon-Manga/"
	path = "/home/auser/Desktop/tmpdir/"
	# path = "/media/auser/SAMSUNG/NOT SAMSUNG/"
	
	# Using sets makes it not vulnerable to same paths.
	
	#paths = ["/home/auser/Desktop/tmpdir/"]
	
	#paths = ["/media/auser/SAMSUNG/NOT SAMSUNG/ALL BOOKS-PAPERS/"
			#,"/media/auser/756C16F773C79BA8/ALL BOOKS-PAPERS/"]
			
	"""
	paths = ["/home/auser/Desktop/tmpdir/Wallpapers_0/",
				"/home/auser/Desktop/tmpdir/Wallpapers_0/",
				"/home/auser/Desktop/tmpdir/Wallpapers_0 (copy 1)/",
				"/home/auser/Desktop/tmpdir/"]
	
	"""
	paths = ["/media/auser/SAMSUNG/NOT SAMSUNG/Any backup before 2020-02-16/"]
	
	print("Processing paths: ", paths)
	print(time.ctime())
	
	#fpaths = get_fpaths_recursively_from_folder(path)
	fpaths = get_paths(paths, is_recursive=True)
	dists, groups = apply_all_passes(fpaths)
	
	format_output_paths(dists, groups)
	
	print(time.ctime())
#

