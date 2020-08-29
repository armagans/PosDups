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
