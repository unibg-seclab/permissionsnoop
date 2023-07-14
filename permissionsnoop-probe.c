// posix compatible getline()
#define  _POSIX_C_SOURCE 200809L
#include <stdio.h>

int main() {
	char *line = NULL;
	size_t len = 1;
	getline(&line, &len, stdin);
}
