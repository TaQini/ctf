# leave ins

- `leave` <=> 
 - `mov esp, ebp; pop ebp`

# Stack pivot

 - 栈溢出，栈空间不足时，通过栈转移，扩大可利用的栈空间

 - stack pivot `gadget` -> `leave; ret`
 - overwrite `ebp` -> control `esp`
