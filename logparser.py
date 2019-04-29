

f = open("log1.txt","r")

lines = f.readlines()

f.close()

time = 0
clk = 0

for line in lines:
    words = line.replace(':',' ').replace('=',' ').split()
    if int(words[0]) != time:
        time = int(words[0])
        print(int(words[2]) - clk)
        clk = int(words[2])


