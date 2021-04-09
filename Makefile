# VARIABLES
GREEN 	= \033[38;5;40m
RESET 	= \033[0m
NAME 		= ft_nmap

# COMPILATION
CC 		= gcc
FLAGS 	= -Wall -Wextra -Werror
RM 		= rm -rf


# DIRECTORIES
DSRCS		= ./srcs/
DOBJS	= ./comp/

# SOURCES
SRCS =	parse.c nmap.c exit.c

# OBJS
OBJS 	= $(SRCS:%.c=$(DOBJS)%.o)  

#H EADER FILE
HEADER = ./incs/nmap.h


# MAKE
all: $(NAME)


# COMPILATION
$(NAME): $(OBJS)
	$(CC) $(FLAGS) $(OBJS) -o $(NAME)
	echo "$(GREEN)$(NAME) DONE ✔$(RESET)"


$(OBJS): | $(DOBJS)

$(DOBJS)%.o: $(DSRCS)%.c $(HEADER)
	$(CC) $(FLAGS) -c $< -o $@

# OBJECT FILE DIRECTORY CREATION
$(DOBJS):
	mkdir -p $(DOBJS)


# CLEAR
clean:
	$(RM) ./comp

fclean: clean
	$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re
.SILENT: all $(NAME)