#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define ADD(a,b) (a + b)

int check_password(char* p, int p_size, char* i, int i_size) {
	int m = 0;

	// Pad guess with dollar signs
	char guess[46] = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\0";
	int pre_dollars = 15 - i_size;
	for (int k = 0; k < i_size; k++) {
		guess[pre_dollars + k] = i[k];
		m |= (i[k] == '$');
	}

	//fprintf(stderr, "password: %s\nguess   : %s\n", p, guess);
	for (int k = 0; k < 46; k++) {
		m |= (p[k] ^ guess[k]);
	}

	return m == 0;
}

//assumptions: password only has small characters [a, z], maximum length is 15 characters
int main (int argc, char* argv[])	{

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <password guess> <output_file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}


	FILE* password_file;
	
	size_t len = 0;
	char* line;
	password_file = fopen ("/home/isl/t2_3/password.txt", "r");

	if (password_file == NULL) {
		perror("cannot open password file\n");
		exit(EXIT_FAILURE);
	}

	
	// Passowrd gets padded with 30 dollar signs
	//	-> so, 15 + 30 = 45, plus \0
	char password[46] = "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\0";

	// Don't use fscanf because of https://moodle-app2.let.ethz.ch/mod/forum/discuss.php?d=116648
	// fscanf(password_file, "%s", password);
	for (int i = 0; i <= 16; i++) {
		password[i] = fgetc(password_file);
	}

	int is_match = 0; 
	is_match = check_password(password, strlen(password), argv[1], strlen(argv[1]));
	
	FILE* output_file;
	output_file = fopen (argv[2], "wb");
	fputc(is_match, output_file);
	fclose(output_file);

	fclose(password_file);
	return 0;
}
