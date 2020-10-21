server = overseer
client = client
test = ./test_prog
helpers = helpers

server_args = 12345
client_args = localhost 12345 $(test) one two three four
out_and_log = -o outputfile -log logfile
out_and_log2 = -o outputfile2 -log logfile2

build: clean build_server build_client
	@gcc -o $(test) $(test).c

rebuild: clean build

test_client: build_client
	./$(client) localhost 12345 $(out_and_log) $(test) one two three four

test_client2: build_client
	./$(client) localhost 12345 $(out_and_log2) $(test) one two three four five

run_client: build_client
	./$(client) $(client_args) $(user_args)

build_client:
	@echo Building client
	gcc -o $(client) $(client).c -g

run_server: build_server

	./$(server) $(server_args) $(user_args)

build_server:
	@echo Building server 
	gcc -c $(helpers).c
	gcc -c $(server).c
	gcc -g -o $(server) $(server).o $(helpers).o -pthread

# run: overseer.c client.c
# 	@make clean

# 	clear

# 	@echo Attempting to compile $(server) and $(client).
	
# 	@gcc -o $(test) $(test).c
# 	@gcc -c $(helpers).c
# 	@gcc -c $(server).c
# 	@gcc -o $(server) $(server).o $(helpers).o -pthread
# 	@gcc -o $(client) $(client).c

# 	@echo Opening $(server) in new terminal.
# 	@gnome-terminal -q -e "sh -c './$(server) $(server_args) $(user_args); exec bash'"
# 	@sleep 2
# 	@echo Opening $(client) in new terminal.
# 	@gnome-terminal -q -e "sh -c './$(client) $(client_args) $(user_args

clean:
	@echo Removing compiled files. 
	@$(RM) $(server)
	@$(RM) $(client)
	@$(RM) $(test)
	@$(RM) *.o