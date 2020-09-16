server = overseer
client = client
test = test_prog
helpers = helpers

server_args = 12345
client_args = localhost 12345 test_prog one two three four

run: overseer.c client.c
	@make clean

	clear

	@echo Attempting to compile $(server) and $(client).
	
	@gcc -o $(test) $(test).c
	@gcc -c $(helpers).c
	@gcc -c $(server).c
	@gcc -o $(server) $(server).o $(helpers).o -pthread
	@gcc -o $(client) $(client).c


	@echo Any additional gcc runtime flags \(enter to continue with default parameters\)?
	@read user_args 

	@# test

	@echo Opening $(server) in new terminal.
	@gnome-terminal -q -e "sh -c './$(server).o $(server_args) $(user_args); exec bash'"
	@sleep 2
	@echo Opening $(client) in new terminal.
	@gnome-terminal -q -e "sh -c './$(client).o $(client_args) $(user_args); exec bash'"

clean:
	@echo Removing compiled files. 
	@$(RM) *.o
