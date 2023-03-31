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
