# coding: utf-8

'''
Filename: btwris.py
URL: https://www.fuzzingbook.org/html/Fuzzer.html
Section: Breaking Things With Random Inputs (BTWRIs)
'''

import fuzzingbook
from fuzzingbook.Fuzzer import RandomFuzzer
import random
import os
import tempfile
import subprocess

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

BASENAME = "temp_fuzz.txt"
C_PROG = "mem_check.c"

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

class ProgramRunner():
	# Outcomes
	PASS = "PASS"
	FAIL = "FAIL"
	UNRESOLVED = "UNRESOLVED"

	def __init__(self, program):
		# Initialize. <program> is a program spec as passed to "subprocess.run()"
		self.program = program

	def run_process(self, inp="", flags=""):
		# Run the program with <inp> as input.  Return result of "subprocess.run()"
		print(self.program, flags)
		return subprocess.run([self.program, flags],
													input=inp,
													stdout=subprocess.PIPE,
													stderr=subprocess.PIPE,
													universal_newlines=True)

	def run(self, inp="", flags=""):
		# Run the program with <inp> as input. Return test outcome based on result of "subprocess.run()"
		result = self.run_process(inp, flags)
		print(result)

		if result.returncode == 0:
			outcome = self.PASS
		elif result.returncode < 0:
			outcome = self.FAIL
		else:
			outcome = self.UNRESOLVED
		print(outcome)

		return (result, outcome)

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

''' A string of up to <max_length> characters in the range [<char_start>, <char_start> + <char_range>] '''
def fuzzer(max_length=100, char_start=32, char_range=94):
	string_length = random.randrange(0, max_length + 1)
	out = ""
	for i in range(0, string_length):
		out += chr(random.randrange(char_start, char_start + char_range))
	return out

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

def gen_temp_file_path(basename=BASENAME):
	tempdir = tempfile.mkdtemp() # temporary file directory
	FILE = os.path.join(tempdir, basename) # full temporary file path
	return FILE

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

def create_temp_fuzz_data_file(basename=BASENAME, verbose=False):
	FILE = gen_temp_file_path() # full temporary file path
	data = fuzzer() # get some random input fuzz data
	with open(FILE, "w") as f:
		f.write(data) # write the random fuzz data to the temporary file
	contents = open(FILE).read()
	assert(contents == data), "Fuzz data is incorrect." # check if fuzz data was actually written correctly

	if(verbose): print("\nWrote", contents, "to", FILE + '\n')

	return (contents, FILE)

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

'''
The BC calculator application has previously been fixed from its bugs revealed by fuzzing.
It is very unlikely that the program will return a non-zero <returncode>.
'''
def fuzz_bc_calculator(basename=BASENAME, data="2+2\n", verbose=True):
	FILE = gen_temp_file_path() # full temporary file path
	program = "bc"
	with open(FILE, "w") as f:
	  f.write(data) # static input data
	result = subprocess.run([program, FILE],
	                        stdin=subprocess.DEVNULL,
	                        stdout=subprocess.PIPE,
	                        stderr=subprocess.PIPE,
	                        universal_newlines=False)
	if(verbose):
		print("\nInput Data:", data)
		print("stdout:", result.stdout)
		print("stderr:", result.stderr)
		print("returncode:", result.returncode)

	return result

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

def crash_if_too_long(s):
	buf = "0123456789abcdefghijklmnopqrstuvwxz"
	if len(s) > len(buf):
		raise ValueError

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

'''
Will enter an infinite loop if string <s> has no spaces in it.
'''
def hang_if_no_space(s):
	i = 0
	while True:
		if i < len(s):
			if s[i] == ' ':
				break
		i += 1

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

'''
It is common for memory to be allocated with: "char *buffer = (char *)malloc(size);" in the C language.
What happens if <size> is too large and exceeds the usable memory space?
What happens if <size> is negative?
What happens if <size> is less than the number of characters needed to store in the resulting buffer?
All of these cases can cause damage/crash a program that doesn't account for these types of error checks.

If we really wanted to allocate that much memory on a system, having it quickly fail as above actually would be the better option.
In reality, running out of memory may dramatically slow systems down,
up to the point that they become totally unresponsive and restarting is the only option.

One might argue that these are all problems of bad programming, or of bad programming languages.
But then, there are thousands of people starting to program every day, and all of them make the same mistakes again and again, even today.
'''
def collapse_if_too_large(s):
	if int(s) > 1000:
		raise ValueError

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

'''
To catch problematic memory accesses during testing, one can run C programs in special memory-checking environments;
at runtime, these check for each and every memory operation whether it accesses valid and initialized memory.

A popular example is LLVM Address Sanitizer which detects a whole set of potentially dangerous memory safety violations.
In the following example we will compile a rather simple C program with this tool and provoke an out-of-bounds read by reading
past an allocated portion of memory.

If you want to find errors in a C program, turning on such checks for fuzzing is fairly easy.
It will slow down execution by a certain factor depending on the tool (for AddressSanitizer it is typically 2×) and also consume more memory,
but CPU cycles are dead cheap compared to the human effort it takes to find these bugs.

Out-of-bounds accesses to memory are a great security risk, as they may let attackers access or even modify information that is not meant for them.
As a famous example, the HeartBleed bug was a security bug in the OpenSSL library,
implementing cryptographic protocols that provide communications security over a computer network.
'''
def write_OV_buf_prog():
	with open(C_PROG, "w") as f:
		f.write(
"""#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv)
{
	int mems = atoi(argv[1]);

  /* Create an array mems bytes, initialized with 42 */
  char *buf = malloc(mems);
  memset(buf, 42, mems);

  /* Read the n-th element, with n being the first command-line argument */
  int idx = atoi(argv[2]);
  printf("Attempting to access index %d of %d allocated memory locations...", idx, mems);
  if(mems >= idx)
  	printf("SUCCESS");
  else
  	printf("FAILURE");
  char val = buf[idx];

  /* Clean up memory so we don't leak */
  free(buf);
  return val;
}"""
		)

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

def gen_fuzz_int(length, max_dig_val, verbose=False):
	num = fuzzer(length, ord('0'), max_dig_val)
	if(verbose): print(num)
	return num

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

'''
Information leaks may not only occur through illegal memory accesses;
they can also occur within "valid" memory – if this "valid" memory contains sensitive information that should not leak out.

However, if the length is greater than the length of the reply string, additional contents of memory spill out.
Note that all of this still occurs within regular array bounds, so an address sanitizer would not be triggered.
'''
def heartbeat(reply, length, verbose=True):
	secrets = ("<space for reply>" + fuzzer(100) + "<secret-certificate>" + fuzzer(100) + "<secret-key>" + fuzzer(100) + "<other-secrets>")

	uninitialized_memory_marker = "deadbeef"
	while len(secrets) < 2048:
		secrets += uninitialized_memory_marker

		memory = reply + secrets[len(reply):] # store the heartbeat reply

	s = ""
	for i in range(length):
		s += memory[i]

	# These error checking conditions are important to eliminate possible valid memory location leaks
	if(len(s) != len(reply)): raise ValueError
	if(s.find(reply) == -1): raise ValueError
	if(s.find(uninitialized_memory_marker) != -1): raise AssertionError
	if(s.find("secret") != -1): raise AssertionError

	if(verbose): print(s)

	return s # send back the heartbeat reply

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

'''
One key idea for detecting errors early is the concept of assertion – a predicate that checks the input (precondition)
and the result (postcondition) of important functions. The more assertions you have in your program, the higher your
chances to detect errors during execution that would go undetected by generic checkers – notably during fuzzing.
If you worry about the impact of assertions on performance, keep in mind that assertions can be turned off in production
code (although it can be helpful to leave the most critical checks active).
'''
def valid_airport_code(code):
	assert len(code) == 3, "Airport code must have three characters: " + repr(code)
	for c in code:
		assert c.isalpha(), "Non-letter in airport code: " + repr(code)
		assert c.isupper(), "Lowercase letter in airport code: " + repr(code)
	return True

def valid_airport_codes(codes):
	for code in codes:
		assert valid_airport_code(code), "Not all codes are valid."
	return True

def add_new_airport(code, city, codes):
	assert valid_airport_code(code)
	assert valid_airport_codes(codes)
	codes[code] = city
	assert valid_airport_codes(codes)


# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————
