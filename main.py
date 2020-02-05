# coding: utf-8

'''
Filename: main.py
Description: Collection of examples from The Fuzzing Book (fuzzingbook.org).
'''

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

import fuzzingbook
from fuzzingbook.Fuzzer import RandomFuzzer
import btwris
from tqdm import tqdm

# —————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

'''
One of the most important uses of assertions for finding errors is checking the integrity of data structures.
'''
airport_codes = {
	"YVR": "Vancouver",
	"JFK": "New York-JFK",
	"CDG": "Paris-Charles de Gaulle",
	"CAI": "Cairo",
	"LED": "St. Petersburg",
	"PEK": "Beijing",
	"HND": "Tokyo-Haneda",
	"AKL": "Auckland"
}

def main():
	# Test the bc calculator application
	print("\nFuzzing the BC Calculator application:")
	bc_trials = 1000
	for i in tqdm(range(bc_trials)):
		fuzz_data = btwris.fuzzer()
		bc_res = btwris.fuzz_bc_calculator(data=fuzz_data, verbose=False)
		if(bc_res.returncode != 0):
			print(bc_res)

	# The "fuzzingbook" library works
	print("\nTesting the fuzzingbook RandomFuzzer:")
	for i in range(10):
		f = RandomFuzzer(max_length=10, char_start=32, char_range=94)
		print(f.fuzz())


	# The heartbeat doesnt allow access to memory less than or greater than the quantity of characters for the reply ; heartbleed bug averted
	print("\nSimulating resiliance against a heartbleed bug:")
	s = btwris.heartbeat("reply", 5)


	# Assert the state of the current airport codes and the addition of a new airport code
	print("\nAsserting error checks for structures that have specified formatting against fuzzed input:")
	print(airport_codes)
	btwris.add_new_airport("BNA", "Nashville", airport_codes)
	print(airport_codes)


	# Experiment with 
	print("\nWriting a C program (" + btwris.C_PROG + ") to test buffer overflow and memory address sanitization:")
	btwris.write_OV_buf_prog()
	print("Done.")
	print("Use \'make link_c\' to compile and link the sample C program with memory address sanitization.")
	print("Use \'make run_c\' to execute the program with default parameters: memory addresses to allocate (mems=100) & memory address index to access (idx=99).\n")


	# Define Unix command and flags to run
	ls = btwris.ProgramRunner(program="ls")
	ls.run(flags="-a")

main()

