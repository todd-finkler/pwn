int main(int argc, char **argv, char **envp)
{
	int num_vars = 0;
	while (*envp)
	{
		envp++;
		num_vars++;
	}
	printf("There are %d environment variables.\n", num_vars);
}

