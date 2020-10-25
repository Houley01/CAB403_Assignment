server = overseer
controller = controller
test = ./test_prog
helpers = helpers

server_args = 12345
controller_args = localhost 12345 $(test) one two three four
out_and_log = -o outputfile -log logfile
out_and_log2 = -o outputfile2 -log logfile2

build: clean build_server build_controller
	@gcc -o $(test) $(test).c

rebuild: clean build

test_controller: build_controller
	./$(controller) localhost 12345 $(out_and_log) $(test) one two three four

test_controller2: build_controller
	./$(controller) localhost 12345 $(out_and_log2) $(test) one two three four five

run_controller: build_controller
	./$(controller) $(controller_args) $(user_args)

build_controller:
	@echo Building controller
	gcc -o $(controller) $(controller).c -g

run_server: build_server

	./$(server) $(server_args) $(user_args)

build_server:
	@echo Building server 
	gcc -c $(helpers).c
	gcc -c $(server).c
	gcc -g -o $(server) $(server).o $(helpers).o -pthread

# run: overseer.c controller.c
# 	@make clean

# 	clear

# 	@echo Attempting to compile $(server) and $(controller).
	
# 	@gcc -o $(test) $(test).c
# 	@gcc -c $(helpers).c
# 	@gcc -c $(server).c
# 	@gcc -o $(server) $(server).o $(helpers).o -pthread
# 	@gcc -o $(controller) $(controller).c

# 	@echo Opening $(server) in new terminal.
# 	@gnome-terminal -q -e "sh -c './$(server) $(server_args) $(user_args); exec bash'"
# 	@sleep 2
# 	@echo Opening $(controller) in new terminal.
# 	@gnome-terminal -q -e "sh -c './$(controller) $(controller_args) $(user_args

clean:
	@echo Removing compiled files. 
	@$(RM) $(server)
	@$(RM) $(controller)
	@$(RM) $(test)
	@$(RM) *.o