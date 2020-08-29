import os
import hashlib

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


def read_all_lines(input_file_path):
	with open(input_file_path, "r") as f:
		lines = f.readlines()
		#print(len(lines))
		#for el in lines:
		#	print(el)
		return lines
	#
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


def hex_digest_sha512(file_path, size):
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


def format_distinct_path(distinct_num, size, separator, path):
	# size is currently in bytes.
	return str.format("Distinct-{} | Size-{} {} {}", 
						distinct_num, size, separator, path)
	#return "Distinct" + str(info) + separator + path
#


def format_similar_path(group_num, size, separator, path):
	# size is currently in bytes.
	return str.format("Group-{} | Size-{} {} {}", 
						group_num, size, separator, path)
	#return "Group-" + group_num + str(info) + separator + path
#


def get_size_str(size_in_bytes):
	try:
		sizes = ["B", "Kb", "Mb", "Gb", "Tb"]
		x = size_in_bytes
		i = 0
		while x > 1024:
			x = x//1024
			i += 1
		#
		return str(x) + sizes[i] if i <= 4 else "bigger than terabyte"
	#
	except:
		return "Error calculating size str for " + str(size_in_bytes)
	#
#
