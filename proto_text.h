#ifndef PROTO_TEXT_H
#define PROTO_TEXT_H

// FIXME: keep these out of this .h header.
#define COMMAND_TOKEN 0
#define SUBCOMMAND_TOKEN 1
#define KEY_TOKEN 1

#define MAX_TOKENS 24
typedef struct token_s {
    char *value;
    size_t length;
} token_t;
size_t tokenize_command(char *command, token_t *tokens, const size_t max_tokens);

/* text protocol handlers */
void complete_nread_ascii(conn *c);
int try_read_command_asciiauth(conn *c);
int try_read_command_ascii(conn *c);
void process_command_ascii(conn *c, char *command);

#endif
