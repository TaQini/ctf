char array[] = "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x2B\x2F\x00";

char *array_1 = array;
char *array_2 = array+10;

signed int swap()
{
  signed int result; // eax
  char v1; // cl

  result = 6;
  do
  {
    v1 = array_2[result];
    array_2[result] = array_1[result];
    array_1[result++] = v1;
  }
  while ( result < 15 );
  return result;
}

int main(){
    printf("%s\n",array);
    //printf("%s\n",array_1);
    //printf("%s\n",array_2);
    swap();
    printf("%s\n",array);
    //printf("%s\n",array_1);
    //printf("%s\n",array_2);

}
