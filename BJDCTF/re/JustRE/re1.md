```
BOOL __stdcall DialogFunc(HWND hWnd, UINT a2, WPARAM a3, LPARAM a4)
{
  CHAR String; // [esp+0h] [ebp-64h]

  if ( a2 != 272 )
  {
    if ( a2 != 273 )
      return 0;
    if ( (_WORD)a3 != 1 && (_WORD)a3 != 2 )
    {
      sprintf(&String, aD, ++dword_4099F0);
      if ( dword_4099F0 == 19999 )
      {
        sprintf(&String, aBjdDD2069a4579, 0x4E1F, 0);
        SetWindowTextA(hWnd, &String);
        return 0;
      }
      SetWindowTextA(hWnd, &String);
      return 0;
    }
    EndDialog(hWnd, (unsigned __int16)a3);
  }
  return 1;
}
```
