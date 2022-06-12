# MD++
Wow css injection, I wonder what we can do with this. Looking at the page, we can assume that the flag is stored in the admin username. This username is stored in the placeholder attribute of an input element. Cool, let's leak the flag 1 char at a time.

Before we do that, let's leak the flag charset using fonts. `tjkegsauwfrlbp{}_`

Assembling this into a flag, we see that this obviously can be rearranged into `flag{waterfall_bfutsftfejpk}`
