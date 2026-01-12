NAME = war
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g3

SRC_PATH = src/
SRC_PATH_O = src_obfuscated/
OBJ_PATH = obj/
OBJ_PATH_O = obj_obfuscated/
INC_PATH_O = include_obfuscated/

SRC = files_handle.c \
	main.c \
	signature.c \
	injector.c \
	elf_parser.c \
	syscall_tracer.c \
	metamorph.c \
	rc4.c \
	anti_process.c

SRCS = $(addprefix $(SRC_PATH), $(SRC))
OBJS = $(patsubst $(SRC_PATH)%.c,$(OBJ_PATH)%.o,$(SRCS))

SRCS_O = $(addprefix $(SRC_PATH_O), $(SRC))
OBJS_O = $(patsubst $(SRC_PATH_O)%.c,$(OBJ_PATH_O)%.o,$(SRCS_O))

GREEN = \033[0;32m
BLUE = \033[0;34m
YELLOW = \033[0;33m
RED = \033[0;31m
RESET = \033[0m


all: $(NAME)

$(NAME): $(OBJS)
	@printf "$(YELLOW)Building $(NAME)...$(RESET) \n"
	@$(CC) $(CFLAGS) $(OBJS) $(INC) -o $(NAME) && \
		printf "$(GREEN)✔ Build succesful!$(RESET) \n" || \
		printf "$(RED)✘ Build failed!$(RESET) \n"

$(OBJ_PATH)%.o: $(SRC_PATH)%.c | $(OBJ_PATH)
	@printf "$(BLUE)Compiling $<...$(RESET) \n"
	@$(CC) $(CFLAGS) $(INC) -c $< -o $@

$(OBJ_PATH):
	@printf "$(BLUE)Creating object directory...$(RESET) \n"
	@mkdir -p $(OBJ_PATH)

$(OBJ_PATH_O):
	@printf "$(BLUE)Creating obfuscated object directory...$(RESET) \n"
	@mkdir -p $(OBJ_PATH_O)

obfuscated: $(OBJS_O)
	@printf "$(YELLOW)Building $(NAME) (obfuscated)...$(RESET) \n"
	@$(CC) $(CFLAGS) $(OBJS_O) -I$(INC_PATH_O) -o $(NAME) && \
		printf "$(GREEN)✔ Obfuscated build successful!$(RESET) \n" || \
		printf "$(RED)✘ Obfuscated build failed!$(RESET) \n"

$(OBJ_PATH_O)%.o: $(SRC_PATH_O)%.c | $(OBJ_PATH_O)
	@printf "$(BLUE)Compiling (obfuscated) $<...$(RESET) \n"
	@$(CC) $(CFLAGS) -I$(INC_PATH_O) -c $< -o $@

clean:
	@printf "$(BLUE)Cleaning object files...$(RESET) \n"
	@rm -f $(OBJS)
	@rm -f $(OBJS_O)
	@printf "$(GREEN)✔ Objects cleaned succesfully!$(RESET) \n"

fclean: clean
	@printf "$(BLUE)Removing binaries, dependencies and object files...$(RESET) \n"
	@rm -f $(NAME)
	@rm -f $(NAME)_obfuscated
	@printf "$(GREEN)✔ Directory cleaned succesfully!$(RESET) \n"

re: fclean all

call: all clean
	@printf "$(YELLOW)Cleaning dependency builds...$(RESET) \n"
	@printf "$(GREEN)✔ Dependency builds cleaned succesfully!$(RESET) \n"

.PHONY: all clean fclean re call obfuscated
