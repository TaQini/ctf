int main(){
  char m1[17];
  strcpy(m1, ":\"AL_RT^L*.?+6/46");
  char m2[] = "harambe"; //"ebmarah";
  int v6 = 7;
  char s[100];
  printf("Welcome to the RC3 secure password guesser.\n");
  printf("To continue, you must enter the correct password.\n");
  printf("Enter your guess: ");
  scanf("%32s", s);
  int input = strlen(s);
  int i;
  if ( input < strlen(m1) )
    err();
  for ( i = 0; i < strlen(s); ++i )
  {
    if ( i >= strlen(m1) )
      err();
    //if ( s[i] != (m2[i%v6] ^ m1[i]) )
	  printf("%c",m2[i%v6] ^ m1[i]);
  }
  right();
}

void err(){
	puts("err");
	exit(0);
}

void right(){
	puts("\nright");
	exit(0);
}
