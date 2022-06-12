# eunectes murinus

For this challenge, we're given a .pyc file. Doing some googling, we see that we can decompile it back into a .py file using pycdc. Doing this, we're presented with invalid python code: 
[invalid, decompiled python](../something.disasm)

Notice how each equation doesn't have the first variable defined, which makes it very annoying. I can't read assembly, so the only choice we have left is to bash it manually given the flag format.

## bash
How do you bash this when there are 58 variables? Well let's start with the givens. The flag format is `flag{}`, which means we know the first 5 variables and the last one. Going through all the equations and dividing out our knowns, we can factor the result and put the possible results on the other variable. Note that the flag's characters can only be a-z, _, and 0-9.

4 hours later, we can read most of the plaintext. `f, l, a, g, {, i, m, a, g, i, n, e, _, s, o, x15, x16, x17, n, g, x20, t, h, x23, s, _, x26, h, x28, x29, l, x31, n, x33, e, _, m, a, x38, x39, x40, x41, l, y, _`

It appears to read `flag{imagine_solving_this_manually_`. Well shit, guess what I did. Anyways, we still have a bit of flag left to solve for. This section appears to be the hex part of the flag, 12 chars long. When we're done bashing, we get this result: `8, b, 6, 2, f/6, e, 3, 1, b, 1, c, b`.

Unlucky. It appears that we are given a bit of ambiguity due to our lack of assembly reading ability. Submitting both flags gives us the right answer: `flag{imagine_solving_this_challenge_manually_8b626e31b1cb}`

That was very [fun](../fun.txt) ;)
