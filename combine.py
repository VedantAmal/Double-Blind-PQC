with open('paper.tex', 'w') as outfile:
    for fname in ['part1.tex', 'part2.tex', 'part3.tex', 'part4.tex']:
        with open(fname) as infile:
            outfile.write(infile.read())
            outfile.write('\n\n')
print("Successfully combined all 4 parts into paper.tex")
