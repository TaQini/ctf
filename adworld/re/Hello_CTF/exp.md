# code

```c
  strcpy(&key, "437261636b4d654a757374466f7246756e");
  while ( 1 )
  {
    memset(&hex_input, 0, 0x20u);
    v11 = 0;
    v12 = 0;
    output(aPleaseInputYou, v6);
    scanf(aS, user_inpit);
    if ( strlen(user_inpit) > 17 )
      break;
    cnt = 0;
    do
    {
      ptr = user_inpit[cnt];
      if ( !ptr )
        break;
      sprintf(&v8, asc_408044, ptr);
      strcat(&hex_input, &v8);
      ++cnt;
    }
    while ( cnt < 17 );
    if ( !strcmp(&hex_input, &key) )
      output(aSuccess, v7);
    else
      output(aWrong, v7);
  }
  output(aWrong, v7);
```

# exp
```
Python>"437261636b4d654a757374466f7246756e".decode('hex')
CrackMeJustForFun
```
