with open("src/crypto/handlers.rs", "r") as f:
    text = f.read()

text = text.replace("\nfn ", "\npub fn ")
text = text.replace("\nunsafe fn ", "\npub unsafe fn ")
text = text.replace("\nstatic ", "\npub static ")

with open("src/crypto/handlers.rs", "w") as f:
    f.write(text)
