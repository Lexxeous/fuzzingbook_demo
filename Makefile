mems ?= 100
idx ?= 99

run_py:
	python3 main.py


link_c:
	gcc -fsanitize=address -g -o mem_check mem_check.c

run_c:
	./mem_check $(mems) $(idx)


clean:
	rm -rf mem_check mem_check.*
