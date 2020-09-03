# Copyright (C) 2020 Armağan Salman
#
# You should have received a copy of the GNU General Public License
# along with this program (COPYING).  If not, see <https://www.gnu.org/licenses/>.

import sys
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
	with open(input_file_path, "r", encoding="utf-8") as f:
		lines = f.readlines()
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
#


def format_similar_path(group_num, size, separator, path):
	# size is currently in bytes.
	return str.format("Group-{} | Size-{} {} {}", 
						group_num, size, separator, path)
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


def get_byte_from_size_str(size):
	d = {"kb": 1024, "mb": 1048576, "gb": 1073741824}

	multiplier = int(size[:-2])
	ident = d[size[-2:]]

	return multiplier * ident
#


def get_bytes_from_size_seq(sizes):
	return [get_byte_from_size_str(el) for el in sizes.lower().split(',')]
#

def write_results(uniques_all, groups, out_file_path, times):
	# TODO(armagans): Write a better print function.
	# TODO(armagans): Handle out_file if given. Write to it.
	out = [ times["start"] ]
	#out.append("Given output file: "+str(out_file_path))
	total = 0
	out.append("Uniques:")
	unq_cnt = 0
	for elm in uniques_all:
		size = get_file_size_in_bytes(elm)
		#size = str(size//1024) + "Kb" if size//1024 > 1 else str(size) + "B"
		
		size = get_size_str(size)
		
		s = format_distinct_path(unq_cnt, size, "*", elm)
		out.append(s)
		#print(size,"kb * ", elm)
		unq_cnt += 1
		total += 1
	#
	out.append("**************")
	out.append("Probably identical files in groups:")
	cnt = 0
	for k,v in groups.items():
		#print(k, " | ")
		for el in v:
			size = get_file_size_in_bytes(el)
			#size = str(size//1024) + "Kb" if size//1024 > 1 else str(size) + "B"
			
			size = get_size_str(size)
			
			s = format_similar_path(cnt, size, "*", el)
			out.append(s)
			#print(size,"kb * ", el)
			total += 1
		#
		cnt += 1
		out.append("") # Will be \n to separate groups
	#	#print("-----------------*")
	out.append(times["end"])
	out.append("Processed {} files.".format(total))
	
	if out_file_path == None:
		sys.stdout.write("\n".join(out))
		pass
	else:
		# write to given file.
		with open(out_file_path, "a", encoding="utf-8") as w:
			w.write("\n".join(out))
#

def increment_file_name(given_path):
	i = 1
	fpath = given_path
	while is_file(fpath):
		#fpath = str.format("", str(i), base)
		dot = fpath.rfind(".")
		name, ext = fpath[:dot], fpath[dot:]
		
		dash = name.rfind("-")
		if dash >= 0:
			num = name[dash+1:dot]
			i = int(num)+1
			name = str.format("{}-{}", name[:dash], str(i))
		#
		else:
			name = str.format("{}-{}", name, str(i))
			i = i+1
		#
		fpath = name + ext
	#
	if fpath != given_path:
		print("Changed given path to: " + fpath)
	#
	return fpath
#
