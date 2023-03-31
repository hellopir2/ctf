# Invisible WORDs
Opening the file in https://hexed.it, and looking at bitmap specification, we can immediately make a few observations:
- There is a random 02 byte in header.
- Weird 00FFxxxx image data for like 90% of the image. The other 10% of the image has random bytes there, and messing with the headers makes this random data obvious.
- Third byte always starts with a 0 bit. Probably an artifact of only having 5 bits per color.
- Weird image data in general, 5 bits per color, no alpha channel, specified 32 bits per pixel. This must be what hint #2 is referring to with the image quality - it can't be very good if there's only 5 bits per color.
- There seems to be hidden data in the other 10% of the image, in the first 2 bytes (notably, two bytes is a word).

I went and isolated the image bytes that had the weird data, starting from where the 00FF bytes stopped, all the way to the header, since bitmap pixels are in like little endian or something for some reason.

After doing so, I went ahead and selected the bytes of relevance, because I couldn't figure out how to isolate them with python (it doesn't like reading random bytes). After doing so, I realized that this file header looks suspiciously similar to a zip file header. Looking at zip file specifications, this seems to be true. So now we have to figure out how to isolate those bytes, and hopefully find a valid zip file.

My teammate Ryan went and coded this part in Rust:
```rust
use std::fs;
fn main() -> anyhow::Result<()> {
    let bytes = fs::read("./potato.txt")?;
    let mut buf = vec![];
    for (i, c) in bytes.into_iter().enumerate() {
        if i % 4 == 2 || i % 4 == 3 {
            buf.push(c);
        }
    }
    fs::write("./potato.txt.zip", buf)?;
    Ok(())
}
```
(Yeah the txt file I stored the bytes in was called potato.txt)<br>
Anyways opening the zip file and ctrl+f for "picoCTF" yielded the flag: `picoCTF{w0rd_d4wg_y0u_f0und_5h3113ys_m4573rp13c3_e4f8c8f0}`

# UnforgottenBits
This challenge is probably THE most guessy forensics challenge I have completed. I will split the following writeup into two sections, detailing the two parts of the solution.

## Step 1. Steghide
The first step is steghide. On what? Well, 7.bmp. The other bmp files just give some random books, decrypting using the info in the irc logs.

What's the password? Note two things:<br>
1. The irc log is 4 concatenated league of legends characters.<br>
2. There is a notes file that says "yasuoaatrox..." which are two league of legends characters.<br>

Now we extrapolate. We generate wordslists of 4 concatenated league of legends characters, starting with "yasuoaatrox". We run these wordlists through stegseek, and get the password and the decrypted result. The password happens to be "yasuoaatroxashecassiopeia".

## Step 2. Locate the AES Key.
From the previous step, we obtain the file "ledger.1.txt.enc", which is an aes encrypted file. Or is it?

Here is where the real guessing begins.<br>

Well, the mail files have weird names. Maybe information is hidden there?<br>

Let's go on a tangent.<br>

Hey so we have this disk img here, and I'm going to explore the file system real quick. Oh look, random-seed file. I wonder if this could be used to generate some hmmm... aes keys... hmmmm... that seems complicated. Maybe I should keep looking and think about other stuff later.<br>

Let's explore OTHER ways to generate aes keys. That's what a salt is for right? Why would they give us a salt if it's useless? Yeah that's right. It must be used. Also, this yone person clearly uses uuids to seed their keys (source: irc logs), so combined with random-seed, clearly you can generate their keys, right?

Ok so after a few hours wasted on this idea, bashing random strings and reusing the old salt for the other file, nothing was found. No progress made.<br>

Stephen: Brings up file carving tool<br>

Me: Hey let's bash more aes key things

As expected, nothing came from this. However, as unexpected, since chall versions got updated, we could check to see if we were on the right track. We diffed the new and old versions and only the last few bytes of the ledger.1.txt.enc got changed, telling us we didn't need the salt OR the iv, which meant we only needed to find the key. We tried everything, reusing the old salt, figuring out how urandom generates things, trying random "keys" from around the files. Eventually, we returned to file carving, because the emails seemed suspicious. By using a file carving tool, we were able to find something! Was it what we wanted though? It turns out, this was actually a hint to the previous step. So, as expected, we were back to square one. But, I noticed that the file carver showed extra bytes after the file it carved, so hypothetically we could find extra data behind files, or maybe consecutive files on the disk image (which is probably meaningless but whatever). So, we checked behind irc logs, notes (well only guldulheen), and found nothing. So, as a last resort, I decided to throw the disk image into https://hexed.it.

After a few hours, I found something. There was phinary behind note 1. Maybe we should've checked that... Anyways now we have a bunch of random phinary, that is concatenated and arbitrarily truncated, for some reason. So this took a few hours to figure out (the format of the phinary, WHY WOULD YOU TRUNCATE A TERMINATING DECIMAL?!?!), and after that it was pretty ez and we got the flag: `picoCTF{f473_53413d_77fbcfb9}`
