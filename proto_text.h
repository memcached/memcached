#ifndef PROTO_TEXT_H
#define PROTO_TEXT_H

/* text protocol handlers */
void process_command(conn *c, char *command);
int try_read_command_asciiauth(conn *c);
int try_read_command_ascii(conn *c);

#endif
