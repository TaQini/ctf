letters1 = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',
]
letters2 = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',
]
# cipher1 = [
#     "aaaaa", "aaaab", "aaaba", "aaabb", "aabaa", "aabab", "aabba",
#     "aabbb", "abaaa", "abaab", "ababa", "ababb", "abbaa", "abbab",
#     "abbba", "abbbb", "baaaa", "baaab", "baaba", "baabb",
#     "babaa", "babab", "babba", "babbb", "bbaaa", "bbaab",
# ]
# cipher2 = [
#     "AAAAA", "AAAAB", "AAABA", "AAABB", "AABAA", "AABAB", "AABBA",
#     "AABBB", "ABAAA", "ABAAA", "ABAAB", "ABABA", "ABABB", "ABBAA",
#     "ABBAB", "ABBBA", "ABBBB", "BAAAA", "BAAAB", "BAABA",
#     "BAABB", "BAABB", "BABAA", "BABAB", "BABBA", "BABBB",
# ]

cipher1 = [
    "00000", "00001", "00010", "00011", "00100", "00101", "00110",
    "00111", "01000", "01001", "01010", "01011", "01100", "01101",
    "01110", "01111", "10000", "10001", "10010", "10011",
    "10100", "10101", "10110", "10111", "11000", "11001",
]
cipher2 = [
    "00000", "00001", "00010", "00011", "00100", "00101", "00110",
    "00111", "01000", "01000", "01001", "01010", "01011", "01100",
    "01101", "01110", "01111", "10000", "10001", "10010",
    "10011", "10011", "10100", "10101", "10110", "10111",
]

def bacon1(string):
    lists = []
    # 分割，五个一组
    for i in range(0, len(string), 5):
        lists.append(string[i:i+5])
    # print(lists)
    # 循环匹配，得到下标，对应下标即可
    for i in range(0, len(lists)):
        for j in range(0, 26):
            if lists[i] == cipher1[j]:
                # print(j)
                print(letters1[j], end="")
    print("")


def bacon2(string):
    lists = []
    # 分割，五个一组
    for i in range(0, len(string), 5):
        lists.append(string[i:i+5])
    # print(lists)
    # 循环匹配，得到下标，对应下标即可
    for i in range(0, len(lists)):
        for j in range(0, 26):
            if lists[i] == cipher2[j]:
                # print(j)
                print(letters2[j], end="")
    print("")


# enc = '11001 11011 10110 10110 11111 10000 11011 10011 11111 01010 11000 11000 10000 11001 00011 00111 01001 11000 10000 01110 11000 01001 00001'
enc = '00110 00100 01001 01001 00000 01111 00100 01100 00000 10101 00111 00111 01111 00110 11100 11000 10110 00111 01111 10001 00111 10110 11110'

bacon2(enc)