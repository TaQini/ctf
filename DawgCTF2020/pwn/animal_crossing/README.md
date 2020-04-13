
## Tom Nook the Capitalist Racoon

### Description

> Anyone else hear about that cool infinite bell glitch?
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4400
>
> Author: trashcanna


### Attachment

[animal_crossing](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/animal_crossing/animal_crossing)

### Analysis

menu:

```
Timmy: Welcome!
How can I help you today?
1. I want to sell
2. What's for sale?
3. See you later.
```

#### I want to sell

list of `I want to sell`:

```
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
3. slingshot - the closest thing you can get to a gun Price: 900 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells

```

and the item in list was disappeared after sell:

```
3

Timmy: A slingshot!
Sure! How about if I offer you
900 Bells?
Thank you! Please come again!

1. I want to sell
2. What's for sale?
3. See you later.
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells

```

#### What's for sale?

list of `What's for sale?`:

```
Timmy: Welcome!
How can I help you today?
1. I want to sell
2. What's for sale?
3. See you later.
Choice: 2

8500 bells
Timmy: Here's what we have to sell today.
1. flimsy net - 400 bells
2. tarantula - 8000 bells
3. slingshot - 900 bells
4. sapling - 640 bells
5. cherry - 400 bells
6. flag - 420000 bells

```

>  show money after choose 2

We don't have enough money to purchase `flag`, but we can buy `tarantula`.

 `tarantula` was added to list of `I want to sell` after we purchase it :

```
2

Timmy: Excellent purchase!
Yes, thank you for the bells
1. I want to sell
2. What's for sale?
3. See you later.
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
3. slingshot - the closest thing you can get to a gun Price: 900 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells
5. tarantula - I hate spiders! Price: 8000 bells

```

then try to sell `tarantula`:

```
Timmy: Excellent purchase!
Yes, thank you for the bells
1. I want to sell
2. What's for sale?
3. See you later.
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
3. slingshot - the closest thing you can get to a gun Price: 900 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells
5. tarantula - I hate spiders! Price: 8000 bells
5

Timmy: A tarantula!
Sure! How about if I offer you
8000 Bells?
Thank you! Please come again!

1. I want to sell
2. What's for sale?
3. See you later.
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
3. slingshot - the closest thing you can get to a gun Price: 900 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells
5. tarantula - I hate spiders! Price: 8000 bells

```

!!! `tarantula` was still in list of `I want to sell` after sold

so we can sell it for many times to earn enough money, then buy the flag

### Solution

```python
# buy tarantula - 8000
sla('Choice: ','2')
sla('6. flag - 420000 bells\n','2')

# sell tarantula 53 times - 8000*53=424000
for i in range(53):
    sla('Choice: ','1')
    sla('5. tarantula - I hate spiders! Price: 8000 bells\n','5')
    print i

# sell 1,2 (make room in pockets)
sla('Choice: ','1')
sla('5. tarantula - I hate spiders! Price: 8000 bells\n','2')
sla('Choice: ','1')
sla('5. tarantula - I hate spiders! Price: 8000 bells\n','1')

# buy flag
sla('Choice: ','2')
sla('6. flag - 420000 bells\n','6')

# print flag
context.log_level = 'debug'
sla('Choice: ','1')
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/animal_crossing) 


